import getpass
import logging

# import logging.config
from pathlib import Path
from typing import Optional, Tuple, TextIO, Union
from urllib.parse import unquote

from astropy.coordinates import SkyCoord, Angle
from astropy.utils.console import human_file_size
import astropy.units as u
from astroquery.casda import Casda
import click
import requests

from casdapy import casda
from casdapy._logging import debug_http_on, logger


class ClickPathPath(click.Path):
    """A click path argument that returns a pathlib Path instead of a string."""

    def convert(self, value, param, ctx):
        return Path(super().convert(value, param, ctx))


def process_cone_search_args(ctx, param, value):
    if len(value) == 0:
        return {"coord": None, "radius": None}
    ra, dec, radius = value
    coord = SkyCoord(ra=ra, dec=dec, unit="deg")
    radius = Angle(radius, unit="arcmin")
    return {"coord": coord, "radius": radius}


def _get_auth(credentials_file: Optional[Union[Path, TextIO]]) -> Tuple[str, str]:
    """Read a username and password from a text file or ask the user interactively.

    Parameters
    ----------
    credentials_file : Optional[Union[Path, TextIO]]
        Either a `Path` to a local file containing the ATNF OPAL username and password on
        separate lines; or an open file pointer to such a file; or `None`. If `None`, ask
        the user interactively.

    Returns
    -------
    Tuple[str, str]
        ATNF OPAL username, password.
    """
    if credentials_file:
        if isinstance(credentials_file, Path):
            fp = credentials_file.open()
        else:
            fp = credentials_file
        opal_username, opal_password, *_ = fp.read().split("\n")
    else:
        opal_username = input("ATNF OPAL username: ")
        opal_password = getpass.getpass("ATNF OPAL password: ")
    return opal_username, opal_password


@click.group()
@click.option(
    "-v",
    "--verbose",
    count=True,
    help=(
        "Show more detailed logging information which is useful for debugging. Can be"
        " used multiple times to increase the level of verbosity. i.e. -v will turn on"
        " debug logging for casdapy logging; -vv will also turn on debug logging for"
        " all HTTP requests."
    ),
)
def cli(verbose: int = 0):
    if verbose > 0:
        logger.setLevel(logging.DEBUG)
    if verbose > 1:
        debug_http_on()


@cli.command(
    help=(
        "Query CASDA for files matching various search criteria and download the"
        " results."
    ),
    short_help="Query CASDA and download results.",
)
@click.option(
    "--project", type=str, help="Limit results to the given ASKAP OPAL project code."
)
@click.option(
    "--sbid",
    type=int,
    multiple=True,
    help=(
        "Limit results to the given ASKAP SBIDs. Can be given multiple times, e.g."
        " --sbid 30861 --sbid 30862."
    ),
)
@click.option(
    "--sbid-file",
    type=click.File("r"),
    help=(
        "Only download data products with SBIDs specified in the given file. Each SBID"
        " must be on a separate line. If used with --sbid, all given SBIDs are merged."
    ),
)
@click.option(
    "--cone-search",
    nargs=3,
    metavar="RA DEC RADIUS",
    help=(
        "Perform a cone search around (RA, DEC) with RADIUS and return results that"
        " intersect with this region. RA and DEC must be given in a format parseable by"
        " `astropy.coordinate.SkyCoord`, e.g. 23h30m00.00s -55d00m00.00s, or decimal"
        " degrees 352.5 -55.0. Note that sexigesimal coordinates must be delimited with"
        " hms/dms, not colons, as the latter has ambiguous units. RADIUS must be given"
        " in a format parseable by `astropy.coordinate.Angle`, e.g. 15arcsec,"
        " 1.5arcmin, etc. If no unit is given, the value will be interpreted in arcmin."
    ),
    callback=process_cone_search_args,
)
@click.option(
    "--image-type",
    type=click.Choice(casda.IMAGE_CUBE_SUBTYPES, case_sensitive=False),
    multiple=True,
    help=(
        "The image type(s) to download. Multiple can be given, e.g. --image-type"
        " cont_restored_t0 --image-type cont_restored_t1. At least one must be provided"
        " to download images. No deafault."
    ),
)
@click.option(
    "--image-pol",
    type=click.Choice(casda.IMAGE_CUBE_POLARISATIONS, case_sensitive=False),
    multiple=True,
    help=(
        "Image polarisation product(s) to download. Multiple can be given, e.g."
        " --image-pol I --image-pol V. Defaults to I."
    ),
    default=("I",),
)
@click.option(
    "--catalogue-type",
    type=click.Choice(casda.CATALOGUE_SUBTYPES, case_sensitive=False),
    multiple=True,
    help=(
        "The catalogue type(s) to download. Multiple can be given, e.g."
        ' --catalogue-type "Continuum Component" --catalogue-type "Continuum Island".'
        " At least one must be provided to download catalogues. No default."
    ),
)
@click.option(
    "--filenames-file",
    type=click.File("r"),
    help=(
        "Only download files with filenames specified in the given file. Each filename"
        " must be on separate lines. If using filenames from previous CASDA URLs, note"
        " that the filename in the URL has some special characters replaced, e.g. "
        " 2333+18A becomes 2333_18A. The filename stored in the CASDA database is the "
        " original, e.g. 2333+18A."
    ),
)
@click.option(
    "--credentials-file",
    type=click.File("r"),
    help=(
        "Read ATNF OPAL account credentials from a file containing the username"
        " and password on separate lines. If not supplied, user will be prompted to"
        " enter a username and password interactively."
    ),
)
@click.option(
    "--destination-dir",
    type=ClickPathPath(exists=True, file_okay=False, writable=True),
    help=(
        "Directory to save downloaded images. Existing files that match query results"
        " will be overwritten. Defaults to current directory."
    ),
    default=".",
)
@click.option(
    "--job-size",
    type=int,
    default=20,
    metavar="N",
    help=(
        "Ask CASDA to split the download into several jobs, each containing a maximum"
        " of N files. Note the actual number of returned files will be 2*N as CASDA"
        " always provides a small .checksum file for each requested file. Defaults"
        " to 20."
    ),
)
@click.option(
    "--catalogue-retries",
    type=int,
    default=5,
    metavar="N",
    help=(
        "If an error occurs when downloading a requested catalogue, retry the download"
        " a maximum of N times with exponential backoff."
    ),
)
@click.option(
    "--checksum-fail-mode",
    type=click.Choice(["log", "delete"]),
    help=(
        'What to do with image files that fail checksum verification. "log" will write'
        " the filenames of the bad files to a file named failed_verification.txt in the"
        " location specified by `--destination-dir`. Existing contents will be"
        ' overwritten. "delete" will delete the files. Default is to do nothing, but'
        " files that fail verification will still be logged in the main log with level"
        " ERROR."
    ),
)
@click.option(
    "--dry-run",
    is_flag=True,
    help=(
        "Don't download any files, only perform query steps and report which files"
        " *would* be downloaded. Defaults to False."
    ),
)
def download(
    project,
    sbid: Tuple[int, ...],
    sbid_file: Optional[TextIO],
    cone_search,
    image_type: Tuple[str, ...],
    image_pol: Tuple[str, ...],
    catalogue_type: Tuple[str, ...],
    filenames_file: Optional[TextIO],
    credentials_file: Optional[TextIO],
    destination_dir: Path,
    job_size,
    catalogue_retries,
    checksum_fail_mode,
    dry_run,
):
    filenames = (
        [line.strip() for line in filenames_file.readlines()]
        if filenames_file is not None
        else None
    )
    sbids_from_file = None
    if sbid_file is not None:
        try:
            sbids_from_file = tuple([int(line.strip()) for line in sbid_file.readlines()])
        except ValueError:
            logger.error(
                "Failed to parse SBID file %s. Please ensure each line contains only an"
                " SBID that may be cast to an int.",
                sbid_file.name,
            )
            exit()
        sbid = sbid + sbids_from_file

    casda_results = casda.query(
        project,
        sbid if len(sbid) > 0 else None,
        cone_search["coord"],
        cone_search["radius"],
        polarisations=image_pol,
        data_products=image_type + catalogue_type,
        filenames=filenames,
    )
    if len(casda_results) == 0:
        logger.warning("No results returned by CASDA.")
        exit()

    logger.info("Query returned %d files.", len(casda_results))
    logger.info(
        "Estimated image download size: %s",
        human_file_size(casda_results["access_estsize"].sum() * u.kilobyte),
    )
    logger.debug(
        "Filenames returned by query: %s", ", ".join(casda_results["filename"].tolist())
    )

    if not dry_run and len(casda_results) > 0:
        # download files by creating an async SODA job on CASDA (astroquery.casda does all this)
        # get the user's OPAL account login for image download
        if credentials_file:
            opal_username, opal_password, *_ = credentials_file.read().split("\n")
        else:
            opal_username = input("ATNF OPAL username: ")
            opal_password = getpass.getpass("ATNF OPAL password: ")
        files_good, files_bad = casda.download_data(
            casda_results,
            Path(destination_dir),
            opal_username,
            opal_password,
            job_size,
        )
        logger.info(
            "All file downloads completed. Checksum verification: %d passed, %d"
            " failed.",
            len(files_good),
            len(files_bad),
        )
        if len(files_bad) > 0:
            if checksum_fail_mode == "log":
                fail_log_file = destination_dir / "failed_verification.txt"
                logger.info(
                    "Writing filenames that failed checksum verification to %s ...",
                    fail_log_file,
                )
                with fail_log_file.open(mode="w") as f:
                    for failed_file_path in files_bad:
                        # use .name as the fail log file is in the same directory as the images
                        print(failed_file_path.name, file=f)
            elif checksum_fail_mode == "delete":
                logger.info("Deleting files that failed checksum verification ...")
                for failed_file_path in files_bad:
                    failed_file_path.unlink()
                    logger.debug("Deleted %s.", failed_file_path)
    logger.info("Finished!")


@cli.command(
    help=(
        "Verify files downloaded from CASDA by calculating their checksums and"
        " comparing them with the .checksum files provided by CASDA. Assumes the"
        " .checksum files are in the same location as the data files."
    ),
    short_help="Verify CASDA download checksums.",
)
@click.argument("files", type=ClickPathPath(exists=True, dir_okay=False), nargs=-1)
@click.option(
    "--delete", is_flag=True, help="Delete files that fail checksum verification."
)
@click.option(
    "--show-full-path",
    is_flag=True,
    help=(
        "Print the full relative path for files in log messages. Default is to print"
        " the filename only."
    ),
)
def verify(files: Tuple[Path], delete: bool, show_full_path: bool):
    for f in files:
        f_log_str = str(f) if show_full_path else f.name
        if f.suffix == ".checksum":
            logger.debug("Skipping checksum file %s", f_log_str)
            continue
        f_checksum = f.with_name(f.name + ".checksum")
        if not f_checksum.exists():
            logger.warning("No checksum file found for %s", f_log_str)
        else:
            passed = casda.verify_casda_checksum(f, f_checksum)
            if passed:
                logger.debug("PASSED: %s", f_log_str)
            else:
                logger.error("FAILED: %s", f_log_str)
                if delete:
                    logger.debug("Deleting %s and checksum file.", f_log_str)
                    f.unlink()
                    f_checksum.unlink()


@cli.command(
    help=(
        "Retry downloading files from an existing CASDA job. Existing and completed"
        " files will be ignored, existing but incomplete files will be resumed if"
        " possible. A file is considered completed if is has the expected filesize, so"
        " users should delete corrupted data files if they wish to retry downloading"
        " them."
    ),
    short_help="Download files from an existing CASDA job.",
)
@click.argument("job-id")
@click.option(
    "--destination-dir",
    type=ClickPathPath(exists=True, file_okay=False, writable=True),
    help="Directory to save downloaded images. Defaults to current directory.",
    default=".",
)
@click.option(
    "--credentials-file",
    type=click.File("r"),
    help=(
        "Read ATNF OPAL account credentials from a file containing the username"
        " and password on separate lines. If not supplied, user will be prompted to"
        " enter a username and password interactively."
    ),
)
def retry(
    job_id: str,
    destination_dir: Path,
    credentials_file: Optional[TextIO],
):
    job_url = Casda._get_soda_url() + "/" + job_id
    job_details = Casda._get_job_details_xml(job_url)
    status = Casda._read_job_status(job_details, verbose=True)
    if status != "COMPLETED":
        logger.error(
            "CASDA job %s has status %s and is not ready for download.", job_id, status
        )
    else:
        opal_username, opal_password = _get_auth(credentials_file)
        url_list = [
            unquote(result.get("{http://www.w3.org/1999/xlink}href"))
            for result in job_details.find("uws:results", Casda._uws_ns).findall(
                "uws:result", Casda._uws_ns
            )
        ]
        logger.info("Downloading files for CASDA job %s ...", job_id)
        try:
            _ = casda.download_staged_data_urls(
                url_list, opal_username, opal_password, destination_dir
            )
        except requests.exceptions.HTTPError as e:
            logger.error("A HTTPError was raised.")
            logger.error("request.url: %s", e.request.url)
            logger.error("request.header: %s", e.request.headers)
            logger.error("request.body: %s", e.request.body)
            logger.error("response.status_code: %s", e.response.status_code)
            logger.error("response.headers: %s", e.response.headers)
            raise
        logger.info("Download complete.")


if __name__ == "__main__":
    cli()
