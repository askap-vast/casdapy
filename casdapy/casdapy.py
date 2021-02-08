import binascii
from functools import partial
import hashlib
from math import ceil
from pathlib import Path
from typing import List, Optional, Tuple, ByteString, Iterable, Sequence
import warnings

from astropy.coordinates import SkyCoord, Angle
from astropy.io.votable.exceptions import VOTableChangeWarning, VOTableSpecWarning
from astropy.table import Table
import astroquery.casda
from astroquery.utils.tap.core import TapPlus
import pypika
from casdapy import logger

CASDA_TAP_URL = "https://casda.csiro.au/casda_vo_tools/tap"
CATALOGUE_SUBTYPES = ["catalogue.continuum.island", "catalogue.continuum.component"]
IMAGE_CUBE_SUBTYPES = [
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
]
IMAGE_CUBE_POLARISATIONS = ["I", "Q", "U", "V"]
DATAPRODUCT_SUBTYPES = IMAGE_CUBE_SUBTYPES + CATALOGUE_SUBTYPES
# logger = logging.getLogger(__name__)
AdqlCircle = pypika.CustomFunction("CIRCLE", ["coord_system", "ra", "dec", "radius"])
AdqlIntersects = pypika.CustomFunction("INTERSECTS", ["region1", "region2"])


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
    sbid: Optional[int] = None,
    coord: Optional[SkyCoord] = None,
    radius: Optional[Angle] = None,
    polarisations: List[str] = IMAGE_CUBE_POLARISATIONS,
    data_products: List[str] = DATAPRODUCT_SUBTYPES,
) -> Table:
    """Query CASDA for matching image cubes and catalogues.

    Parameters
    ----------
    project : Optional[str], optional
        Search for data products with this OPAL project code only, e.g. "AS110" for
        RACS, by default None.
    sbid : Optional[int], optional
        Search for data products with this SBID only, by default None.
    coord : Optional[SkyCoord], optional
        Search for data products that intersect with a circle at position `coord` with
        radius `radius`. If specified, must also provide `radius`. By default None.
    radius : Optional[Angle], optional
        Radius for the cone search around `coord`. Must be specified if `coord` is
        given. By default None.
    polarisations : List[str], optional
        Search for image cubes that contain these polarisations only. Filtering
        catalogues by polarisation currently not supported. By default all Stokes
        parameters (I, Q, U, V).
    data_products : List[str], optional
        Search for these data product types only. By default all types. See
        `DATAPRODUCT_SUBTYPES`.

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
        adql_query = adql_query.where(obscore_table.obs_id == str(sbid))

    if coord is not None and radius is not None:
        adql_query = adql_query.where(
            1
            == AdqlIntersects(
                AdqlCircle("ICRS", coord.ra.deg, coord.dec.deg, radius.deg),
                obscore_table.s_region,
            )
        )

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
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", VOTableChangeWarning)
        warnings.simplefilter("ignore", VOTableSpecWarning)
        job = casdatap.launch_job_async(adql_query_str)
    r = job.get_results()
    return r


def download_catalogue_data(
    catalogue_filename: str, destination: Path, is_component: bool = True
) -> Path:
    """Download VOTable catalogues from CASDA with TAP.

    Parameters
    ----------
    catalogue_filename : str
        Filename from CASDA.
    destination : Path
        Location to save catalogue. Must be a directory.
    is_component : bool, optional
        True if this is a component catalogue, False for an island catalogue. By default
        True.

    Returns
    -------
    Path
        The local path to the downloaded file.
    """
    casdatap = TapPlus(url=CASDA_TAP_URL, verbose=False)
    catalogue_table = pypika.Table("casda.catalogue")
    data_table = (
        pypika.Table("casda.continuum_component")
        if is_component
        else pypika.Table("casda.continuum_island")
    )
    adql_query = (
        pypika.Query.from_(data_table)
        .select(data_table.star)
        .join(catalogue_table)
        .on(data_table.catalogue_id == catalogue_table.id)
        .where(catalogue_table.filename == catalogue_filename)
    )
    adql_query_str = adql_query.get_sql(quote_char=None)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", VOTableChangeWarning)
        warnings.simplefilter("ignore", VOTableSpecWarning)
        job = casdatap.launch_job_async(adql_query_str)
    results = job.get_results()
    output_file = destination / catalogue_filename
    if output_file.exists():
        logger.warning("Overwriting existing file %s", output_file)
    results.write(str(output_file), format="votable", overwrite=True)
    return output_file


def download_image_data(
    casda_tap_query_result: Table,
    destination: Path,
    username: str,
    password: str,
    job_size: int = 20,
) -> Tuple[List[Path], List[Path]]:
    """Download and verify image cube data products from CASDA.

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
    casda = astroquery.casda.Casda(username, password)

    # ensure only image cubes are being downloaded - catalogues won't work with this method
    casda_tap_query_result_images = casda_tap_query_result[
        casda_tap_query_result["dataproduct_type"] == "cube"
    ]
    if len(casda_tap_query_result_images) != len(casda_tap_query_result):
        n_not_images = len(casda_tap_query_result) - len(casda_tap_query_result_images)
        logger.warning(
            "%d CASDA query result files are not images and will not be downloaded.",
            n_not_images,
        )
    n_jobs = ceil(len(casda_tap_query_result_images) / job_size)
    logger.info(
        "Splitting %d files into %d CASDA jobs. CASDA will send a confirmation"
        " email for each job to the address associated with your OPAL account.",
        len(casda_tap_query_result_images),
        n_jobs,
    )
    if n_jobs >= 10:
        logger.info("Brace your inbox!")

    for i, subset in enumerate(chunks(casda_tap_query_result_images, job_size)):
        logger.info(
            "Staging %d files for download for CASDA job #%d of %d ...",
            len(subset),
            i + 1,
            n_jobs,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", VOTableSpecWarning)
            url_list = casda.stage_data(subset, verbose=True)
        logger.info("Staging complete for CASDA job #%d of %d.", i + 1, n_jobs)

        logger.info("Downloading files for CASDA job #%d of %d ...", i + 1, n_jobs)
        downloaded_job_files = download_staged_data_urls(
            url_list, username, password, destination
        )
        logger.info("Download complete for CASDA job #%d of %d.", i + 1, n_jobs)

        # verify the checksums (should be downloaded automatically)
        logger.info(
            "Verifying downloaded files for CASDA job #%d of %d ...", i + 1, n_jobs
        )
        downloaded_valid_files, downloaded_invalid_files = verify_downloaded_data(
            downloaded_job_files
        )
    return downloaded_valid_files, downloaded_invalid_files


def download_staged_data_urls(
    url_list: List[str], username: str, password: str, destination: Path
) -> List[Path]:
    """Download the staged CASDA file URLs.

    Parameters
    ----------
    url_list : List[str]
        List of URLs for data files staged by CASDA. i.e. the output of
        `astroquery.casda.stage_data`.
    username : str
        ATNF OPAL username. Must be the same credentials used to create the CASDA job.
    password : str
        ATNF OPAL password. Must be the same credentials used to create the CASDA job.
    destination : Path
        Download destination path.

    Returns
    -------
    List[Path]
        List of `Path` objects for the downloaded files.
    """
    casda = astroquery.casda.Casda(username, password)
    downloaded_job_files = [
        Path(f) for f in casda.download_files(url_list, savedir=str(destination))
    ]
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
