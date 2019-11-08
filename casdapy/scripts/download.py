import argparse
import getpass
import json
import logging
import logging.config
from pathlib import Path
import pkg_resources

from astropy.coordinates import SkyCoord, Angle
import click

import casdapy


class CoordinateAction(argparse.Action):
    """argparse action for handling cone search parameters. Expects three values: ra, dec,
    and radius. Creates a SkyCoord using ra and dec, and an Angle using radius. Sets the
    arg dest to a dict with keys "coord" and "radius".
    """

    def __call__(self, parser, namespace, values, option_string=None):
        ra, dec, radius = values
        coord = SkyCoord(ra=ra, dec=dec, unit="deg")
        radius = Angle(radius, unit="arcmin")
        setattr(namespace, self.dest, {"coord": coord, "radius": radius})


def process_cone_search_args(ctx, param, value):
    if len(value) == 0:
        return {"coord": None, "radius": None}
    ra, dec, radius = value
    coord = SkyCoord(ra=ra, dec=dec, unit="deg")
    radius = Angle(radius, unit="arcmin")
    return {"coord": coord, "radius": radius}


@click.command()
@click.option("--sbid", type=int, help="Limit results to the given ASKAP SBID")
@click.option(
    "--cone-search",
    nargs=3,
    metavar="RA DEC RADIUS",
    help=(
        "Perform a cone search around (RA, DEC) with RADIUS. RA and DEC must be "
        "given in a format parseable by `astropy.coordinate.SkyCoord`, e.g. "
        "23h30m00.00s -55d00m00.00s, or decimal degrees 352.5 -55.0. Note that "
        "sexigesimal coordinates must be delimited with hms/dms, not colons, as the "
        "latter has ambiguous units. RADIUS must be given in a format parseable by "
        "`astropy.coordinate.Angle`, e.g. 15arcsec, 1.5arcmin, etc. If no unit is "
        "given, the value will be interpreted in arcmin."
    ),
    callback=process_cone_search_args,
)
@click.option(
    "--image-type",
    type=click.Choice(casdapy.IMAGE_CUBE_SUBTYPES, case_sensitive=False),
    multiple=True,
    help=(
        "The image type(s) to download. Multiple can be given, e.g. --image-type "
        "cont_restored_t0 --image-type cont_restored_t1. At least one must be provided "
        "to download images. Defaults to cont_restored_t0."
    ),
    default=("cont_restored_t0",),
)
@click.option(
    "--image-pol",
    type=click.Choice(casdapy.IMAGE_CUBE_POLARISATIONS, case_sensitive=False),
    multiple=True,
    help=(
        "Image polarisation product(s) to download. Multiple can be given, e.g. "
        "--image-pol I --image-pol V. Defaults to I."
    ),
    default=("I",)
)
@click.option(
    "--catalogue-type",
    type=click.Choice(casdapy.CATALOGUE_SUBTYPES, case_sensitive=False),
    multiple=True,
    help=(
        "The catalogue type(s) to download. Multiple can be given, e.g. --catalogue-type "
        "\"Continuum Component\" --catalogue-type \"Continuum Island\". At least one "
        "must be provided to download catalogues. Defaults to None."
    ),
)
@click.option(
    "--credentials-file",
    type=click.File("r"),
    help=(
        "Read ATNF OPAL account credentials from a file containing the username "
        "and password on separate lines. If not supplied, user will be prompted to "
        "enter a username and password interactively."
    ),
)
@click.option(
    "--destination-dir",
    type=click.Path(exists=True, file_okay=False, writable=True),
    help="Directory to save downloaded images. Defaults to current directory.",
    default=".",
)
@click.option(
    "--poll-period",
    type=int,
    help="Number of seconds to poll CASDA for the job status for async jobs. Defaults to 30.",
    default=30,
)
@click.option(
    "--dry-run",
    is_flag=True,
    help=(
        "Don't download any files, only perform query steps and report which files "
        "*would* be downloaded. Defaults to False."
    ),
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Show more logging information. Useful for debugging. Defaults to False.",
)
def main(
    sbid,
    cone_search,
    image_type,
    image_pol,
    catalogue_type,
    credentials_file,
    destination_dir,
    poll_period,
    dry_run,
    verbose,
):
    logging.config.dictConfig(
        json.loads(pkg_resources.resource_string(__name__, "logger_config.json"))
    )
    logger = logging.getLogger()

    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("arguments:")
        logger.debug("sbid: %s (%s)", sbid, type(sbid))
        logger.debug("cone_search: %s (%s)", cone_search, type(cone_search))
        logger.debug("image_type: %s (%s)", image_type, type(image_type))
        logger.debug("image_pol: %s (%s)", image_pol, type(image_pol))
        logger.debug("catalogue_type: %s (%s)", catalogue_type, type(catalogue_type))
        logger.debug("credentials_file: %s (%s)", credentials_file, type(credentials_file))
        logger.debug("destination_dir: %s (%s)", destination_dir, type(destination_dir))
        logger.debug("poll_period: %s (%s)", poll_period, type(poll_period))
        logger.debug("dry_run: %s (%s)", dry_run, type(dry_run))
        logger.debug("verbose: %s (%s)", verbose, type(verbose))

    # get the user's OPAL account login
    if credentials_file:
        opal_username, opal_password, *_ = credentials_file.read().split("\n")
    else:
        opal_username = input("ATNF OPAL username: ")
        opal_password = getpass.getpass("ATNF OPAL password: ")

    if verbose:
        logger.setLevel(logging.DEBUG)

    casda_results = casdapy.query(
        opal_username,
        opal_password,
        sbid,
        cone_search["coord"],
        cone_search["radius"],
        polarisations=image_pol,
        data_products=image_type + catalogue_type,
    )

    if not dry_run:
        _ = casdapy.download_data(
            casda_results["dataObjectId"],
            Path(destination_dir),
            opal_username,
            opal_password,
            poll_period,
        )


if __name__ == "__main__":
    main()
