import argparse
import getpass
import json
import logging
import logging.config
from pathlib import Path
import pkg_resources

from astropy.coordinates import SkyCoord, Angle

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


def main():
    logging.config.dictConfig(
        json.loads(pkg_resources.resource_string(__name__, "logger_config.json"))
    )
    logger = logging.getLogger()

    parser = argparse.ArgumentParser(
        description="Download images and catalouges from CASDA that match given criteria.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--sbid", type=int, help="Limit results to the given ASKAP SBID"
    )
    parser.add_argument(
        "--cone-search",
        help=(
            "Perform a cone search around (RA, DEC) with RADIUS. RA and DEC must be "
            "given in a format parseable by `astropy.coordinate.SkyCoord`, e.g. "
            "23h30m00.00s -55d00m00.00s, or decimal degrees 352.5 -55.0. Note that "
            "sexigesimal coordinates must be delimited with hms/dms, not colons, as the "
            "latter has ambiguous units. RADIUS must be given in a format parseable by "
            "`astropy.coordinate.Angle`, e.g. 15arcsec, 1.5arcmin, etc. If no unit is "
            "given, the value will be interpreted in arcmin."
        ),
        nargs=3,
        metavar=("RA", "DEC", "RADIUS"),
        default={"coord": None, "radius": None},
        action=CoordinateAction,
    )
    parser.add_argument(
        "--image-type",
        metavar="IMAGE_TYPE",
        nargs="*",
        help=(
            "The image type(s) to download. Multiple can be given. No default: at least "
            "one must be provided to download images. "
            "Possible choices are: %(choices)s."
        ),
        choices=casdapy.IMAGE_CUBE_SUBTYPES,
        default=("cont_restored_t0",),
    ),
    parser.add_argument(
        "--image-pol",
        metavar="POLARISATION",
        nargs="*",
        help=(
            "Image polarisation product(s) to download. Multiple can be given. "
            "Possible choices are: %(choices)s."
        ),
        choices=casdapy.IMAGE_CUBE_POLARISATIONS,
        default=["I"],
    )
    parser.add_argument(
        "--catalogue-type",
        metavar="CATALOGUE_TYPE",
        nargs="*",
        help=(
            "The catalogue type(s) to download. Multiple can be given. No default: at "
            "least one must be provided to download catalogues. "
            "Possible choices are: %(choices)s."
        ),
        choices=casdapy.CATALOGUE_SUBTYPES,
        default=("Continuum Component",),
    )
    parser.add_argument(
        "--credentials-file",
        type=Path,
        help=(
            "Read ATNF OPAL account credentials from a file containing the username "
            "and password on separate lines. If not supplied, user will be prompted to "
            "enter these interactively."
        ),
    )
    parser.add_argument(
        "--destination-dir",
        type=Path,
        help="Directory to save downloaded images. Defaults to current directory.",
        default=".",
    )
    parser.add_argument(
        "--poll-period",
        type=int,
        help="Number of seconds to poll CASDA for the job status for async jobs.",
        default=30,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Don't download any files, only perform query steps and report which files "
            "*would* be downloaded."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show more logging information. Useful for debugging.",
    )
    args = parser.parse_args()

    # get the user's OPAL account login
    if args.credentials_file:
        opal_username, opal_password, *_ = args.credentials_file.read_text().split("\n")
    else:
        opal_username = input("ATNF OPAL username: ")
        opal_password = getpass.getpass("ATNF OPAL password: ")

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    casda_results = casdapy.query(
        opal_username,
        opal_password,
        args.sbid,
        args.cone_search["coord"],
        args.cone_search["radius"],
        polarisations=args.image_pol,
        data_products=args.image_type + args.catalogue_type,
    )

    if not args.dry_run:
        _ = casdapy.download_data(
            casda_results["dataObjectId"],
            args.destination_dir,
            opal_username,
            opal_password,
            args.poll_period,
        )


if __name__ == "__main__":
    main()
