import getpass
import logging
import logging.config
from pathlib import Path

from astropy.coordinates import SkyCoord, Angle
from astropy.utils.console import human_file_size
import astropy.units as u
import click

from casdapy import casdapy, logger


class ClickPathPath(click.Path):
    """A click path argument that returns a pathlib Path, not a string"""

    def convert(self, value, param, ctx):
        return Path(super().convert(value, param, ctx))


def process_cone_search_args(ctx, param, value):
    if len(value) == 0:
        return {"coord": None, "radius": None}
    ra, dec, radius = value
    coord = SkyCoord(ra=ra, dec=dec, unit="deg")
    radius = Angle(radius, unit="arcmin")
    return {"coord": coord, "radius": radius}


@click.command()
@click.option(
    "--project", type=str, help="Limit results to the given ASKAP OPAL project code."
)
@click.option("--sbid", type=int, help="Limit results to the given ASKAP SBID.")
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
    type=click.Choice(casdapy.IMAGE_CUBE_SUBTYPES, case_sensitive=False),
    multiple=True,
    help=(
        "The image type(s) to download. Multiple can be given, e.g. --image-type"
        " cont_restored_t0 --image-type cont_restored_t1. At least one must be provided"
        " to download images. No deafault."
    ),
)
@click.option(
    "--image-pol",
    type=click.Choice(casdapy.IMAGE_CUBE_POLARISATIONS, case_sensitive=False),
    multiple=True,
    help=(
        "Image polarisation product(s) to download. Multiple can be given, e.g."
        " --image-pol I --image-pol V. Defaults to I."
    ),
    default=("I",),
)
@click.option(
    "--catalogue-type",
    type=click.Choice(casdapy.CATALOGUE_SUBTYPES, case_sensitive=False),
    multiple=True,
    help=(
        "The catalogue type(s) to download. Multiple can be given, e.g."
        ' --catalogue-type "Continuum Component" --catalogue-type "Continuum Island".'
        " At least one must be provided to download catalogues. No default."
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
@click.option(
    "--verbose",
    is_flag=True,
    help="Show more logging information. Useful for debugging. Defaults to False.",
)
def main(
    project,
    sbid,
    cone_search,
    image_type,
    image_pol,
    catalogue_type,
    credentials_file,
    destination_dir: Path,
    job_size,
    checksum_fail_mode,
    dry_run,
    verbose,
):
    if verbose:
        logger.setLevel(logging.DEBUG)

    casda_results = casdapy.query(
        project,
        sbid,
        cone_search["coord"],
        cone_search["radius"],
        polarisations=image_pol,
        data_products=image_type + catalogue_type,
    )
    if len(casda_results) == 0:
        logger.warning("No results returned by CASDA.")
        exit()

    image_mask = casda_results["dataproduct_type"] == "cube"
    casda_results_images = casda_results[image_mask]
    casda_results_catalogues = casda_results[~image_mask]
    logger.info(
        "Query returned %d files. %d images and %d catalogues.",
        len(casda_results),
        len(casda_results_images),
        len(casda_results_catalogues),
    )
    logger.info(
        "Estimated image download size: %s",
        human_file_size(casda_results_images["access_estsize"].sum() * u.kilobyte),
    )
    logger.debug(
        "Filenames returned by query: %s", ", ".join(casda_results["filename"].tolist())
    )
    if not dry_run and len(casda_results_catalogues) > 0:
        # download catalogues by querying the global CASDA catalogue for each filename with TAP
        logger.info(
            "Downloading %d catalogues with TAP ...", len(casda_results_catalogues)
        )
        for catalogue_filename in casda_results_catalogues["filename"]:
            logger.debug("Downloading catalogue %s with TAP ...", catalogue_filename)
            _ = casdapy.download_catalogue_data(catalogue_filename, destination_dir)
            logger.debug("Download completed for %s.", catalogue_filename)
        logger.info(
            "Catalogue downloads completed. Output directory: %s", destination_dir
        )

    if not dry_run and len(casda_results_images) > 0:
        # download images by creating an async SODA job on CASDA (astroquery.casda does all this)
        # get the user's OPAL account login for image download
        if credentials_file:
            opal_username, opal_password, *_ = credentials_file.read().split("\n")
        else:
            opal_username = input("ATNF OPAL username: ")
            opal_password = getpass.getpass("ATNF OPAL password: ")
        images_good, images_bad = casdapy.download_image_data(
            casda_results_images,
            Path(destination_dir),
            opal_username,
            opal_password,
            job_size,
        )
        logger.info(
            "All image downloads completed. Checksum verification: %d passed, %d"
            " failed.",
            len(images_good),
            len(images_bad),
        )
        if len(images_bad) > 0:
            if checksum_fail_mode == "log":
                fail_log_file = destination_dir / "failed_verification.txt"
                logger.info(
                    "Writing filenames that failed checksum verification to %s ...",
                    fail_log_file,
                )
                with fail_log_file.open(mode="w") as f:
                    for failed_file_path in images_bad:
                        # use .name as the fail log file is in the same directory as the images
                        print(failed_file_path.name, file=f)
            elif checksum_fail_mode == "delete":
                logger.info("Deleting files that failed checksum verification ...")
                for failed_file_path in images_bad:
                    failed_file_path.unlink()
                    logger.debug("Deleted %s.", failed_file_path)
    logger.info("Finished!")


if __name__ == "__main__":
    main()
