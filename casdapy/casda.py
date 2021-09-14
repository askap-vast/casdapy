import binascii
from functools import partial
import hashlib
from http.client import HTTPException
from math import ceil
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, ByteString, Iterable, Sequence
from urllib.parse import unquote
import warnings

from astropy.coordinates import SkyCoord, Angle
from astropy.io.votable.exceptions import VOTableChangeWarning, VOTableSpecWarning
from astropy.table import Table
from astropy.utils.console import human_file_size
import astropy.utils.data
import astroquery.casda
from astroquery.utils.tap.core import TapPlus
import pypika
import requests.exceptions
from retrying import retry
from tqdm.auto import tqdm

from casdapy._logging import logger

CASDA_TAP_URL = "https://casda.csiro.au/casda_vo_tools/tap"
CATALOGUE_SUBTYPES = ("catalogue.continuum.island", "catalogue.continuum.component")
IMAGE_CUBE_SUBTYPES = (
    "cont.background.t0",
    "cont.background.t1",
    "cont.components.t0",
    "cont.components.t1",
    "cont.cleanmodel.t0",
    "cont.cleanmodel.t1",
    "cont.fitresidual.t0",
    "cont.fitresidual.t1",
    "cont.noise.t0",
    "cont.noise.t1",
    "cont.residual.t0",
    "cont.residual.t1",
    "cont.restored.t0",
    "cont.restored.t1",
    "cont.weight.t0",
    "cont.weight.t1",
)
IMAGE_CUBE_POLARISATIONS = ("I", "Q", "U", "V")
DATAPRODUCT_SUBTYPES = IMAGE_CUBE_SUBTYPES + CATALOGUE_SUBTYPES
MAX_RETRIES = 30  # max number of retries for functions decorated with @retry

AdqlCircle = pypika.CustomFunction("CIRCLE", ["coord_system", "ra", "dec", "radius"])
AdqlIntersects = pypika.CustomFunction("INTERSECTS", ["region1", "region2"])


class CasdaClass(astroquery.casda.CasdaClass):
    # override to add retrying and error detection to the download
    def download_files(self, urls, savedir=None):
        filenames = []
        for url in urls:
            local_filename = url.split("/")[-1]
            if os.name == "nt":
                # Windows doesn't allow special characters in filenames like
                # ":" so replace them with an underscore
                local_filename = local_filename.replace(":", "_")
            local_filepath = os.path.join(savedir or ".", local_filename)

            with self._session.get(
                url, timeout=self.TIMEOUT, stream=True, allow_redirects=True
            ) as response:
                response.raise_for_status()
                if "content-length" in response.headers:
                    length: Optional[int] = int(response.headers["content-length"])
                    if length == 0:
                        logger.warning("URL %s has length=0.", url)
                else:
                    logger.warning("URL %s did not return a Content-Length.", url)
                    length = None
                accepts_ranges = "Accept-Ranges" in response.headers

            headers = None
            existing_file_length = 0
            if os.path.exists(local_filepath) and accepts_ranges:
                # file exists locally and the server accepts byte range requests
                open_mode = "ab"
                existing_file_length = os.stat(local_filepath).st_size
                if length is not None:
                    if existing_file_length >= length:
                        # file exists and appears to be complete based on expected size
                        # move on to the next file URL
                        logger.info(
                            "Found cached file %s with expected size %s",
                            local_filepath,
                            human_file_size(existing_file_length),
                        )
                        filenames.append(local_filepath)
                        continue  # next URL
                    elif existing_file_length == 0:
                        # file exists but appears empty
                        logger.info("Found cached file %s with size 0", local_filepath)
                        open_mode = "wb"
                    else:
                        # file exists but is incomplete, request the remaining byte range
                        logger.info(
                            "Continuing download of file %s with %s to go (%.2f%%)",
                            local_filepath,
                            human_file_size(length - existing_file_length),
                            (length - existing_file_length) / length * 100,
                        )
                        end = f"{length-1}" if length is not None else ""
                        headers = {"Range": f"bytes={existing_file_length}-{end}"}
            else:
                # file doesn't exist locally
                open_mode = "wb"

            with self._session.get(
                url,
                timeout=self.TIMEOUT,
                stream=True,
                allow_redirects=True,
                headers=headers,
            ) as response:
                response.raise_for_status()
                logger.info("Downloading %s ...", url)
                with tqdm.wrapattr(
                    open(local_filepath, open_mode),
                    "write",
                    total=length,
                    initial=existing_file_length,
                    miniters=1,
                    unit="B",
                    unit_scale=True,
                ) as f:
                    blocksize = astropy.utils.data.conf.download_block_size
                    for block in response.iter_content(blocksize):
                        f.write(block)
                    f.close()
                # check final filesize
                filesize = os.stat(local_filepath).st_size
                if length is not None and filesize < length:
                    logger.error(
                        "File %s appears incomplete with size %s < expected size %s",
                        local_filepath,
                        human_file_size(filesize),
                        human_file_size(length),
                    )
                    # TODO raise exception and retry
            filenames.append(local_filepath)

        return filenames

    # override to add service_name kwarg to allow catalogue downloads in addition to images
    # and keep track of the original filenames from the TAP query results
    def stage_data(
        self, table, verbose=False, service_name="cutout_service"
    ) -> Dict[str, str]:
        """Override astroquery.casda.CasdaClass.stage_data to add `service_name` kwarg
        which allows catalogue downloads. The original implementation in astroquery only
        supports image downloads. This override also keeps track of the original CASDA
        filenames which are sometimes mangled due to URL encoding.

        Args:
            table ([type]): The CASDA TAP query results.
            verbose (bool, optional): Defaults to False.
            service_name (str, optional): Defaults to "cutout_service".

        Raises:
            ValueError: When not authenticated.
            ValueError: When the CASDA staging job returns a status other than COMPLETED.

        Returns:
            Dict[str, str]: A dict mapping the CASDA file ID to the download URL.
        """
        if not self._authenticated:
            raise ValueError(
                "Credentials must be supplied to download CASDA image data"
            )

        if table is None or len(table) == 0:
            return {}

        # Use datalink to get authenticated access for each file
        tokens = []
        for row in table:
            access_url = row["access_url"]
            response = self._request(
                "GET", access_url, auth=self._auth, timeout=self.TIMEOUT, cache=False
            )
            response.raise_for_status()
            soda_url, id_token = self._parse_datalink_for_service_and_id(
                response, service_name
            )
            tokens.append(id_token)

        # Create job to stage all files
        job_url = self._create_soda_job(tokens, soda_url=soda_url)
        if verbose:
            logger.info("Created data staging job " + job_url)

        # Wait for job to be complete
        final_status = self._run_job(job_url, verbose, poll_interval=self.POLL_INTERVAL)
        if final_status != "COMPLETED":
            if verbose:
                logger.info("Job ended with status " + final_status)
            raise ValueError(
                "Data staging job did not complete successfully. Status was "
                + final_status
            )

        # Build list of result file urls
        job_details = self._get_job_details_xml(job_url)
        fileurls = {}
        for result in job_details.find("uws:results", self._uws_ns).findall(
            "uws:result", self._uws_ns
        ):
            file_id = result.get("id")
            file_location = unquote(result.get("{http://www.w3.org/1999/xlink}href"))
            fileurls[file_id] = file_location

        return fileurls


def _retry_if_connection_error(exception):
    return isinstance(exception, requests.exceptions.ConnectionError)


def _retry_if_http_error(exception):
    return isinstance(exception, HTTPException)


def chunks(seq: Sequence, n: int) -> Iterable:
    """Yield chunks of at least length `n` from `seq` until exhausted.

    Parameters
    ----------
    seq : Sequence
        A sequence, e.g. a List.
    n : int
        The maximum number of elements per chunk. All chunks except the last should
        contain `n` elements.

    Yields
    -------
    Iterator[Iterable]
    """
    for i in range(0, len(seq), n):
        yield seq[i : i + n]  # noqa: E203


def verify_casda_checksum(data_file: Path, checksum_file: Path = None) -> bool:
    """Verify the integrity of a data file downloaded from CASDA with its provided
    checksum file.

    Parameters
    ----------
    data_file : Path
        The data file to verify.
    checksum_file : Path, optional
        The checksum file for `data_file`. If None, uses `data_file`.checksum. By
        default None.

    Returns
    -------
    bool
        The calculated checksum for `data_file` matches the checksum file.
    """
    data_crc, data_digest, data_file_size = calculate_casda_checksum(data_file)
    if checksum_file is None:
        checksum_file = Path(data_file.parent, data_file.name + ".checksum")
    (
        _checksum_crc,
        _checksum_digest,
        _checksum_file_size,
    ) = checksum_file.read_text().split()

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

    Parameters
    ----------
    data_file : Path
        Data file for which to calculate the CASDA checksum.

    Returns
    -------
    Tuple[int, ByteString, int]
        The CASDA checksum: (CRC, SHA-1 digest, file size in bytes)
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
    project: Optional[str] = None,
    sbid: Optional[Tuple[int, ...]] = None,
    coord: Optional[SkyCoord] = None,
    radius: Optional[Angle] = None,
    polarisations: Tuple[str, ...] = IMAGE_CUBE_POLARISATIONS,
    data_products: Tuple[str, ...] = DATAPRODUCT_SUBTYPES,
    filenames: List[str] = None,
) -> Table:
    """Query CASDA for matching image cubes and catalogues.

    Parameters
    ----------
    project : Optional[str], optional
        Search for data products with this OPAL project code only, e.g. "AS110" for
        RACS, by default None.
    sbid : Optional[Tuple[int, ...]], optional
        Search for data products with these SBIDs only, by default None.
    coord : Optional[SkyCoord], optional
        Search for data products that intersect with a circle at position `coord` with
        radius `radius`. If specified, must also provide `radius`. By default None.
    radius : Optional[Angle], optional
        Radius for the cone search around `coord`. Must be specified if `coord` is
        given. By default None.
    polarisations : Tuple[str, ...], optional
        Search for image cubes that contain these polarisations only. Filtering
        catalogues by polarisation currently not supported. By default all Stokes
        parameters (I, Q, U, V).
    data_products : Tuple[str, ...], optional
        Search for these data product types only. By default all types. See
        `DATAPRODUCT_SUBTYPES`.
    filenames : List[str], optional
        Download results with the given filenames only.

    Returns
    -------
    Table
        Image cube and catalogue details that match the query parameters. Pass the
        "dataObjectId" column values to `download_data` to download.

    Raises
    ------
    ValueError
        One or more of the given `polarisations` is not recognised.
    ValueError
        One or more of the given `data_products` is not recognised.
    ValueError
        If `coord` is supplied, `radius` must also be supplied and vice-versa.
    """
    # validate args
    if not set(polarisations) <= set(IMAGE_CUBE_POLARISATIONS):
        raise ValueError(
            "polarisations must be one or more of the following:"
            f" {IMAGE_CUBE_POLARISATIONS}"
        )
    if not set(data_products) <= set(DATAPRODUCT_SUBTYPES):
        raise ValueError(
            "data_products must be one or more of the following:"
            f" {DATAPRODUCT_SUBTYPES}"
        )
    if (coord is not None) ^ (radius is not None):
        raise ValueError("Both a coord and radius must be given, or neither.")

    obscore_table = pypika.Table("ivoa.obscore")
    adql_query: pypika.queries.QueryBuilder = pypika.Query.from_(obscore_table).select(
        "*"
    )

    if project:
        project_table = pypika.Table("casda.project")
        adql_query = (
            adql_query.left_join(project_table)
            .on(obscore_table.obs_collection == project_table.short_name)
            .where(project_table.opal_code == project)
        )

    if sbid:
        adql_query = adql_query.where(obscore_table.obs_id.isin([str(x) for x in sbid]))

    if coord is not None and radius is not None:
        adql_query = adql_query.where(
            1
            == AdqlIntersects(
                AdqlCircle("ICRS", coord.ra.deg, coord.dec.deg, radius.deg),
                obscore_table.s_region,
            )
        )

    if filenames:
        adql_query = adql_query.where(obscore_table.filename.isin(filenames))

    adql_query = adql_query.where(obscore_table.dataproduct_subtype.isin(data_products))
    # only the image cubes have pol_states, filtering by polarisation is not directly
    # possible for catalogues without assuming ASKAP pipeline naming conventions
    adql_query = adql_query.where(
        obscore_table.pol_states.isin([f"/{pol}/" for pol in polarisations])
        | (obscore_table.pol_states.isnull() & obscore_table.dataproduct_type.isnull())
    )

    adql_query_str = adql_query.get_sql(quote_char=None)
    logger.info("Querying CASDA TAP server ...")
    logger.debug("ADQL query: %s", adql_query_str)
    casdatap = TapPlus(url=CASDA_TAP_URL, verbose=False)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", VOTableChangeWarning)
            warnings.simplefilter("ignore", VOTableSpecWarning)
            job = casdatap.launch_job_async(adql_query_str)
        r = job.get_results()
    except requests.exceptions.HTTPError as e:
        logger.error("CASDA returned an HTTP error: %s", e)
        r = Table()
    return r


@retry(
    retry_on_exception=_retry_if_http_error,
    wait_exponential_multiplier=1000,
    wait_exponential_max=30000,
    stop_max_attempt_number=MAX_RETRIES,
)
def get_casda_tap_result(
    job: astroquery.utils.tap.model.job.Job, catalogue_filename: str
):
    logger.debug(
        "Attempting to download %s job ID %s",
        catalogue_filename,
        job.jobid,
    )
    results = job.get_results()
    return results


def download_data(
    casda_tap_query_result: Table,
    destination: Path,
    username: str,
    password: str,
    job_size: int = 20,
) -> Tuple[List[Path], List[Path]]:
    """Download and verify data products from CASDA.

    Parameters
    ----------
    casda_tap_query_result : Table
        The Table of query results returned by CASDA to be downloaded. i.e. the output
        of `casdapy.casdapy.query`. Must contain the `access_url` column.
    destination : Path
        Download destination directory.
    username : str
        ATNF OPAL account username.
    password : str
        ATNF OPAL account password.
    job_size : int, optional
        The number of files in each CASDA job. Note the actual number of downloaded
        files will be 2*N as CASDA always provides a small .checksum file for each
        requested file. By default 20.

    Returns
    -------
    Tuple[List[Path], List[Path]]
        The list of downloaded file paths that passed checksum verification, and the
        list of paths that failed checksum verification.
    """
    casda = CasdaClass(username, password)

    n_jobs = ceil(len(casda_tap_query_result) / job_size)
    logger.info(
        "Splitting %d files into %d CASDA jobs. CASDA will send a confirmation"
        " email for each job to the address associated with your OPAL account.",
        len(casda_tap_query_result),
        n_jobs,
    )
    if n_jobs >= 10:
        logger.info("Brace your inbox!")

    for i, subset in enumerate(chunks(casda_tap_query_result, job_size)):
        logger.info(
            "Staging %d files for download for CASDA job #%d of %d ...",
            len(subset),
            i + 1,
            n_jobs,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", VOTableSpecWarning)
            url_dict = casda.stage_data(
                subset, verbose=True, service_name="async_service"
            )
        logger.info("Staging complete for CASDA job #%d of %d.", i + 1, n_jobs)

        logger.info("Downloading files for CASDA job #%d of %d ...", i + 1, n_jobs)
        try:
            downloaded_job_files = download_staged_data_urls(
                url_dict, username, password, destination, casda=casda
            )
        except requests.exceptions.ConnectionError:
            logger.error(
                "Reached limit of %d retries for downloading files for CASDA job #%d of"
                " %d. Aborting.",
                MAX_RETRIES,
                i + 1,
                n_jobs,
            )
        logger.info("Download complete for CASDA job #%d of %d.", i + 1, n_jobs)

        # rename to filenames provided in TAP query result as sometimes the names are
        # mangled due to URL encoding
        for casda_id, downloaded_file in downloaded_job_files.items():
            is_checksum = casda_id.endswith(".checksum")
            if is_checksum:
                casda_id_main_file = casda_id.replace(".checksum", "")
            else:
                casda_id_main_file = casda_id
            casda_filename = str(
                subset["filename"][subset["obs_publisher_did"] == casda_id_main_file][0]
            )
            if is_checksum:
                casda_filename += ".checksum"

            logger.info("Renaming %s to %s", downloaded_file, casda_filename)
            # update the stored path using the original casda_id
            downloaded_job_files[casda_id] = downloaded_file.rename(
                downloaded_file.with_name(casda_filename)
            )

        # verify the checksums (should be downloaded automatically)
        logger.info(
            "Verifying downloaded files for CASDA job #%d of %d ...", i + 1, n_jobs
        )
        downloaded_valid_files, downloaded_invalid_files = verify_downloaded_data(
            downloaded_job_files.values()
        )
    return downloaded_valid_files, downloaded_invalid_files


@retry(
    retry_on_exception=_retry_if_connection_error,
    wait_exponential_multiplier=1000,
    wait_exponential_max=30000,
    stop_max_attempt_number=MAX_RETRIES,
)
def download_staged_data_urls(
    url_dict: Dict[str, str],
    username: str,
    password: str,
    destination: Path,
    casda: Optional[astroquery.casda.CasdaClass] = None,
) -> Dict[str, Path]:
    """Download the staged CASDA file URLs.

    Parameters
    ----------
    url_dict : Dict[str, str]
        Dict mapping CASDA file IDs to URLs for data files staged by CASDA. i.e. the
        output of `CasdaClass.stage_data`.
    username : str
        ATNF OPAL username. Must be the same credentials used to create the CASDA job.
    password : str
        ATNF OPAL password. Must be the same credentials used to create the CASDA job.
    destination : Path
        Download destination path.
    casda : astroquery.casda.CasdaClass, optional
        An instance of `CasdaClass`. If present, will use this instance to interact with
        CASDA, otherwise a new instance will be created using the given credentials.

    Returns
    -------
    Dict[str, Path]
        Dict mapping CASDA file IDs to `Path` objects for the downloaded files.
    """
    if casda is None:
        casda = CasdaClass(username, password)

    downloaded_job_files = {}
    for casda_id, url in url_dict.items():
        file_path = casda.download_files([url], savedir=str(destination))
        if file_path and len(file_path) > 0:
            downloaded_job_files[casda_id] = Path(file_path[0])
    return downloaded_job_files


def verify_downloaded_data(path_list: List[Path]) -> Tuple[List[Path], List[Path]]:
    """Verify data files downloaded from CASDA using the supplied checksum files. The
    checksum files are assumed to be located alongside the data files.

    Parameters
    ----------
    path_list : List[Path]
        List of `Path` objects. Files with suffix ".checksum" will be ignored.

    Returns
    -------
    Tuple[List[Path], List[Path]]
        A list of `Path` objects that passed verification, and a list of `Path` objects
        that failed.
    """
    downloaded_job_data_files = [f for f in path_list if f.suffix != ".checksum"]
    downloaded_valid_files: List[Path] = []
    downloaded_invalid_files: List[Path] = []
    for file in downloaded_job_data_files:
        checksum_passed = verify_casda_checksum(file)
        if checksum_passed:
            downloaded_valid_files.append(file)
        else:
            logger.error("Checksum failed for %s", file)
            downloaded_invalid_files.append(file)
    if len(downloaded_valid_files) != len(downloaded_job_data_files):
        logger.error(
            "%d file(s) FAILED checksum verification.",
            len(downloaded_job_data_files) - len(downloaded_valid_files),
        )
    logger.info(
        "%d of %d files passed checksum verification.",
        len(downloaded_valid_files),
        len(downloaded_job_data_files),
    )
    return downloaded_valid_files, downloaded_invalid_files
