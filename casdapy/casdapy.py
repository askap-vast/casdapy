import binascii
from functools import partial
import hashlib
import logging
from pathlib import Path, PurePath
import time
from typing import List, NewType, Optional, Collection, Tuple, ByteString
from urllib.parse import urlsplit, urljoin
from xml.etree import ElementTree

from astropy.coordinates import SkyCoord, Angle, Longitude, Latitude
from astropy.table import Table
from astropy.time import Time
import astropy.units as u
from astropy.utils.console import human_file_size
import pandas as pd
import requests
from tqdm import tqdm

ElementTreeType = NewType("ElementTreeType", ElementTree.ElementTree)


class BearerAuth(requests.auth.AuthBase):
    """Authentication class for use with requests. Adds an Authorization header to the
    request with the value "Bearer {token}".
    """
    def __init__(self, token):
        self.token = token

    def __call__(self, r: requests.PreparedRequest):
        r.headers["Authorization"] = f"Bearer {self.token}"
        return r


class CasdaDownloadException(Exception):
    """A problem has occurred with a CASDA download.
    """
    pass


_DAP_API_BASE = "https://data.csiro.au/dap/ws/v2/"
DAP_API_SEARCH_URL = urljoin(_DAP_API_BASE, "domains/casdaObservation/search")
DAP_API_DOWNLOAD_URL = urljoin(_DAP_API_BASE, "domains/casdaObservation/download")
_DAP_REST_USERNAME = "DAP_UI_User@DAPPrd"
_DAP_REST_PASSWORD = ""
DAP_TOKEN_URL = "https://data.csiro.au/dap/oauth/token"
_CASDA_DATA_ACCESS_BASE = "https://casda.csiro.au/casda_data_access/"
CASDA_DATA_ASYNC_URL = urljoin(_CASDA_DATA_ACCESS_BASE, "data/async/")
CASDA_DATA_DOWNLOAD_LINKS_URL = urljoin(_CASDA_DATA_ACCESS_BASE, "download/")
_UWS_NAMESPACES = {"uws": "http://www.ivoa.net/xml/UWS/v1.0"}
CATALOGUE_SUBTYPES = ["Continuum Island", "Continuum Component"]
IMAGE_CUBE_SUBTYPES = [
    "cont_components_t0",
    "cont_components_t1",
    "cont_cleanmodel_t0",
    "cont_cleanmodel_t1",
    "cont_cleanmodel_3d",
    "cont_fitresidual_t0",
    "cont_fitresidual_t1",
    "cont_noise_t0",
    "cont_noise_t1",
    "cont_residual_t0",
    "cont_residual_t1",
    "cont_residual_3d",
    "cont_restored_t0",
    "cont_restored_t1",
    "cont_restored_3d",
    "cont_weight_t0",
    "cont_weight_t1",
    "cont_weight_3d",
]
IMAGE_CUBE_POLARISATIONS = ["I", "Q", "U", "V"]
DATAPRODUCT_SUBTYPES = IMAGE_CUBE_SUBTYPES + CATALOGUE_SUBTYPES
logger = logging.getLogger(__name__)


def _get_auth_token(username: str, password: str) -> str:
    """Request an authentication token from the CSIRO DAP API using an ATNF OPAL account.

    Args:
        username (str): ATNF OPAL account username. Usually an email address.
        password (str): ATNF OPAL account password.

    Returns:
        str: the authentication token required for data access requests.
    """
    response = requests.post(
        DAP_TOKEN_URL,
        data={
            "username": f"opal/{username}",
            "password": password,
            "grant_type": "password",
        },
        headers={"Accept": "application/json"},
        auth=(_DAP_REST_USERNAME, _DAP_REST_PASSWORD),
    )
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as error:
        logger.error("Error encountered while attempting to get auth token: %s", error)
        raise
    return response.json()["access_token"]


def _get_async_job_details(async_job_id: str) -> ElementTree.Element:
    """Return the async job details.

    Args:
        async_job_id (str): CASDA async job ID.

    Returns:
        ElementTree.Element: XML data providing job details.
    """
    response = requests.get(urljoin(CASDA_DATA_ASYNC_URL, async_job_id))
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as error:
        logger.error("Error encountered while getting async job status: %s", error)
        raise

    # TODO return something easier to parse, e.g. JSON
    return ElementTree.fromstring(response.text)


def _get_async_job_status(async_job_id: str) -> str:
    """Return the CASDA async job status.

    Args:
        async_job_id (str): CASDA async job ID.

    Raises:
        CasdaDownloadException: when CASDA job details or status cannot be retrieved.

    Returns:
        str: the job status, i.e. PENDING, QUEUED, EXECUTING, ERROR, COMPLETED.
    """
    job_phase_element = _get_async_job_details(async_job_id).find(
        "uws:phase", namespaces=_UWS_NAMESPACES
    )
    if job_phase_element is not None:
        job_phase = job_phase_element.text
        if job_phase:
            return job_phase
    raise CasdaDownloadException("Could not get status of async job %s", async_job_id)


def _download_casda_link(link: str, destination: Path, filename: str = None) -> Path:
    """Download the data file for the given link from CASDA.

    Args:
        link (str): link to data file.
        destination (Path): download destination.
        filename (str, optional): rename the downloaded file to this filename. If
            `None`, use the filename from CASDA. Defaults to None.

    Returns:
        Path: the downloaded file.
    """
    response = requests.get(link, stream=True)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as error:
        logger.error(
            "Error encountered while attempting to download %s: %s", link, error
        )
        raise

    filename = PurePath(urlsplit(link).path).name if filename is None else filename
    output_file: Path = destination / filename
    filesize = int(response.headers.get("Content-Length", 0))  # bytes
    logger.debug("Downloading %s (%s)", filename, human_file_size(filesize))
    with output_file.open(mode="wb") as fout, tqdm(
        desc=filename, total=filesize, unit="B", unit_scale=True
    ) as pbar:
        for chunk in response.iter_content(chunk_size=64 * 1024):
            fout.write(chunk)
            pbar.update(len(chunk))
    logger.debug("Downloading %s completed.", filename)
    response.close()
    return output_file


def verify_casda_checksum(data_file: Path, checksum_file: Path = None) -> bool:
    """Verify the integrity of a data file downloaded from CASDA with its provided
    checksum file.

    Args:
        data_file (Path): The data file to verify.
        checksum_file (Path, optional): The checksum file for `data_file`. If None, uses
            `data_file`.checksum. Defaults to None.

    Returns:
        bool: the calculated checksum for `data_file` matches the checksum file.
    """
    data_crc, data_digest, data_file_size = calculate_casda_checksum(data_file)
    if checksum_file is None:
        checksum_file = Path(data_file.parent, data_file.name + ".checksum")
    _checksum_crc, _checksum_digest, _checksum_file_size = (
        checksum_file.read_text().split()
    )

    # convert checksum crc and size from hex to int, decode binary digest
    checksum_crc = int(_checksum_crc, 16)
    checksum_digest = binascii.unhexlify(_checksum_digest)
    checksum_file_size = int(_checksum_file_size, 16)

    return (
        data_crc == checksum_crc
        and data_digest == checksum_digest
        and data_file_size == checksum_file_size
    )


def calculate_casda_checksum(data_file: Path) -> Tuple[int, ByteString, int]:
    """Calculate the CASDA checksum for a data file.

    Args:
        data_file (Path): Data file for which to calculate the CASDA checksum.

    Returns:
        Tuple[int, ByteString, int]: The CASDA checksum: (CRC, SHA-1 digest, file size in bytes)
    """
    crc = 0
    sha1 = hashlib.sha1()
    file_size = 0  # 0x00000000
    chunk_size = 65536

    with data_file.open(mode="rb") as fin:
        for chunk in iter(partial(fin.read, chunk_size), b""):
            crc = binascii.crc32(chunk, crc)
            sha1.update(chunk)
            file_size += len(chunk)

    if crc < 0:
        crc = crc + (1 << 32)

    # sys.stdout.write(format(crc, '08;x') + " " + sha1.hexdigest() + " " + format(fsize, 'x'))
    return crc, sha1.digest(), file_size


def query(
    username: str,
    password: str,
    sbid: Optional[int] = None,
    coord: Optional[SkyCoord] = None,
    radius: Optional[Angle] = None,
    polarisations: List[str] = IMAGE_CUBE_POLARISATIONS,
    data_products: List[str] = DATAPRODUCT_SUBTYPES,
) -> Table:
    """Query CASDA for matching image cubes and catalogues.

    Args:
        username (str): ATNF OPAL account username.
        password (str): ATNF OPAL account password.
        sbid (Optional[int], optional): Search for data products with this SBID only.
            Defaults to None.
        coord (Optional[SkyCoord], optional): Search for data products around this
            coordinate only. If specified, must also provide `radius`. Defaults to None.
        radius (Optional[Angle], optional): Radius for the cone search around `coord`.
            Must be specified if `coord` is given. Defaults to None.
        polarisations (List[str], optional): Filter image cube results that contain
            these polarisations only. Filtering catalogues by polarisation currently not
            supported. Defaults to IMAGE_CUBE_POLARISATIONS, i.e. all Stokes parameters.
        data_products (List[str], optional): Filter results that match these data
            product types only. Defaults to DATAPRODUCT_SUBTYPES, i.e. all types.

    Raises:
        ValueError: when supplied polarisations or data_products are not recognised.
        ValueError: when a coord is given but a radius is not, and vice-versa.

    Returns:
        astropy.table.Table: image cube and catalogue details that match the query
            parameters. Pass the "dataObjectId" column values to `download_data` to download.
    """
    # validate args
    if not set(polarisations) <= set(IMAGE_CUBE_POLARISATIONS):
        raise ValueError(
            f"polarisations must be one or more of the following: {IMAGE_CUBE_POLARISATIONS}"
        )
    if not set(data_products) <= set(DATAPRODUCT_SUBTYPES):
        raise ValueError(
            f"data_products must be one or more of the following: {DATAPRODUCT_SUBTYPES}"
        )
    if (coord is not None) ^ (radius is not None):
        raise ValueError("Both a coord and radius must be given, or neither.")

    session = requests.Session()
    session.auth = (username, password)

    search_payload = {
        "facets": [{"label": "Collection Types", "values": ["observational"]}],
        "dataProducts": [
            {"dataProduct": "IMAGE_CUBE", "page": 1, "pageSize": 500},
            {"dataProduct": "CATALOGUE", "page": 1, "pageSize": 500},
        ],
    }
    if sbid:
        search_payload.update({"schedulingBlockId": sbid})
    if coord is not None and radius is not None:
        search_payload.update(
            {
                "coneSearches": [
                    {
                        "rightAscension": coord.ra.to_string(unit="hourangle", sep=":"),
                        "declination": coord.dec.to_string(unit="deg", sep=":"),
                        "radius": radius.arcmin,
                    }
                ]
            }
        )

    response = session.post(DAP_API_SEARCH_URL, json=search_payload)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as error:
        logger.error("HTTP error encountered when sending query to CASDA: %s", error)
        raise

    # get results matching coord and apply filters
    results_images = response.json()["imageCubeResultDto"]
    results_catalogues = response.json()["catalogueResultDto"]
    df_images = pd.DataFrame(data=results_images["files"])
    df_catalogues = pd.DataFrame(data=results_catalogues["files"])

    if len(df_images) > 0:
        logger.debug(
            "%d images found in cone search (before filtering by type, pol, etc)",
            len(df_images),
        )
        df_images = df_images.query(
            (
                "type.str.lower() in @data_products and "
                "polarisation.str.strip('/') in @polarisations"
            )
        )
        logger.debug("%d images remain after filtering", len(df_images))
    else:
        logger.warning("No images found for given coordinate.")

    if len(df_catalogues) > 0:
        logger.debug(
            "%d catalogues found in cone search (before filtering by type, pol, etc)",
            len(df_catalogues),
        )
        df_catalogues = df_catalogues.query("catalogueType in @data_products")
        logger.debug("%d catalogues remain after filtering", len(df_catalogues))
    else:
        logger.warning("No catalogues found for given coordinate.")

    # --- format output with appropriate units and objects
    # key: column name
    # value:
    #   astropy.units.Unit to apply to the table column, or
    #   Tuple[astropy object, kwargs for constructor] to pass column into, or
    #   type to pass to column.astype, or
    #   None to do nothing except keep the column in the table
    col_types = {
        "dataObjectId": None,
        "filename": None,
        "fileSize": u.byte,
        "catalogueRows": int,
        "centreFrequency": u.MHz,
        "lastModifiedDate": (Time, {}),
        "numChannels": int,
        "obsStart": (Time, {}),
        "obsEnd": (Time, {}),
        "polarisation": None,
        "qualityLevel": None,
        "rightAscension": (Longitude, {"unit": "hourangle"}),
        "declination": (Latitude, {"unit": "deg"}),
        "sbid": int,
        "type": None,
        "embargoed": None,
        "catalogueType": None,
    }
    df = pd.concat((df_images, df_catalogues), sort=False, ignore_index=True)[
        col_types.keys()
    ]
    table = Table.from_pandas(df)
    for col in table.itercols():
        col_type = col_types[col.name]
        if isinstance(col_type, u.Unit):
            col.unit = col_type
        elif isinstance(col_type, tuple):
            ColClass, kwargs = col_type
            table.replace_column(col.name, ColClass(col, **kwargs))
        elif col_type is not None:
            table.replace_column(col.name, col.astype(col_type))

    return table


def download_data(
    data_object_ids: Collection[str],
    destination: Path,
    username: str,
    password: str,
    poll_period: int = 30,
) -> List[Path]:
    """Download data products from CASDA.

    Args:
        data_object_ids (Collection[str]): the CASDA data object IDs to download.
        destination (Path): download destination directory.
        username (str): ATNF OPAL account username.
        password (str): ATNF OPAL account password.
        poll_period (int, optional): number of seconds to wait between CASDA async job
            status requests. Defaults to 30.

    Raises:
        CasdaDownloadException: when the CASDA async job status returns an ERROR status.
        CasdaDownloadException: when the number of requested files does not match the
            number of downloaded files (less the checksum files).

    Returns:
        List[Path]: the downloaded files.
    """
    auth_token = _get_auth_token(username, password)

    response = requests.post(
        DAP_API_DOWNLOAD_URL,
        params={
            "id": data_object_ids,
            "downloadMode": "WEB",
            "downloadFormat": "VOTABLE_INDIVIDUAL",
        },
        auth=BearerAuth(auth_token),
    )
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as error:
        logger.error("Error encountered while creating CASDA async job: %s", error)
        raise

    async_job_id = PurePath(urlsplit(response.json()["jobLink"]).path).parts[-3]

    # poll CASDA for async job status, stop when either completed or failed
    job_status = _get_async_job_status(async_job_id)
    while job_status in ("EXECUTING", "QUEUED", "PENDING"):
        time.sleep(poll_period)
        job_status = _get_async_job_status(async_job_id)

    # when complete, download the requested files (incl checksums)
    downloaded_files: List[Path] = []
    if job_status != "ERROR":
        response = requests.get(urljoin(CASDA_DATA_DOWNLOAD_LINKS_URL, async_job_id))
        response.raise_for_status()
        for link in response.text.split():
            output_file = _download_casda_link(link, destination)
            if output_file is not None:
                downloaded_files.append(output_file)
        if len(data_object_ids) != len(downloaded_files) // 2:
            logger.error(
                (
                    "Number of downloaded files (%d) does not match the number of "
                    "requested files (%d). Download was likely interrupted!"
                ),
                len(downloaded_files) // 2,
                len(data_object_ids),
            )
            raise CasdaDownloadException(
                (
                    "Number of files downloaded from CASDA did not match the number "
                    "of search results."
                )
            )

        # verify the checksums (should be downloaded automatically)
        n_passed = 0
        downloaded_data_files = [f for f in downloaded_files if f.suffix != ".checksum"]
        for file in downloaded_data_files:
            checksum_passed = verify_casda_checksum(file)
            if not checksum_passed:
                logger.error("Checksum failed for %s", file)
            else:
                n_passed += 1
        logger.debug(
            "%d of %d files passed checksum verification.",
            n_passed,
            len(downloaded_data_files),
        )
        return downloaded_files
    else:
        raise CasdaDownloadException("CASDA async job failed with status: ERROR.")
