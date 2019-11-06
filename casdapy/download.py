import argparse
import getpass
import json
import logging
import logging.config
from pathlib import Path
import pkg_resources

from casdapy.query import CasdaSbidQuery, CasdaPositionQuery


def sbid():
    logging.config.dictConfig(
        json.loads(pkg_resources.resource_string(__name__, "logger_config.json"))
    )
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser()
    parser.add_argument("sbid", help="The ASKAP SBID.")
    parser.add_argument(
        "--image-type",
        metavar="IMAGE_TYPE",
        nargs="*",
        help=(
            "The image type(s) to download. Multiple can be given. No default: at least "
            "one must be provided to download images. "
            "Possible choices are: %(choices)s."
        ),
        choices=CasdaSbidQuery._IMAGE_CUBE_SUBTYPES,
    ),
    parser.add_argument(
        "--image-pol",
        metavar="POLARIZATION",
        nargs="*",
        help=(
            "Image polarization product(s) to download. Multiple can be given. "
            "Possible choices are: %(choices)s."
        ),
        choices=["I", "Q", "U", "V"],
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
        choices=CasdaSbidQuery._CATALOGUE_SUBTYPES,
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
        logger.setLevel(logging.INFO)

    if args.image_type:
        casda_query = CasdaSbidQuery(
            args.sbid,
            opal_username,
            opal_password,
            polarisations=args.image_pol,
            dataproducts=args.image_type,
        )
        casda_query.run(
            args.destination_dir.expanduser().resolve(),
            poll_period=args.poll_period,
            dry_run=args.dry_run,
        )
    else:
        logger.info("No image types requested.")

    if args.catalogue_type:
        casda_query = CasdaSbidQuery(
            args.sbid, opal_username, opal_password, dataproducts=args.catalogue_type
        )
        casda_query.run(
            args.destination_dir.expanduser().resolve(),
            poll_period=args.poll_period,
            dry_run=args.dry_run,
        )
    else:
        logger.info("No catalogue types requested.")


def position():
    logging.config.dictConfig(
        json.loads(pkg_resources.resource_string(__name__, "logger_config.json"))
    )
    logger = logging.getLogger()

    parser = argparse.ArgumentParser()
    parser.add_argument("ra", help="RA for the cone search.")
    parser.add_argument("dec", help="Dec for the cone search.")
    parser.add_argument("radius", type=float, help="Radius for the cone search in arcmin.")
    parser.add_argument(
        "--image-type",
        metavar="IMAGE_TYPE",
        nargs="*",
        help=(
            "The image type(s) to download. Multiple can be given. No default: at least "
            "one must be provided to download images. "
            "Possible choices are: %(choices)s."
        ),
        choices=CasdaPositionQuery._IMAGE_CUBE_SUBTYPES,
    ),
    parser.add_argument(
        "--image-pol",
        metavar="POLARISATION",
        nargs="*",
        help=(
            "Image polarisation product(s) to download. Multiple can be given. "
            "Possible choices are: %(choices)s."
        ),
        choices=CasdaPositionQuery.IMAGE_CUBE_POLARISATIONS,
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
        choices=CasdaPositionQuery._CATALOGUE_SUBTYPES,
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

    casda_query = CasdaPositionQuery(
        args.ra,
        args.dec,
        args.radius,
        opal_username,
        opal_password,
        polarisations=args.image_pol,
        dataproducts=args.image_type + args.catalogue_type,
    )
    data_object_ids = casda_query.query()

    casda_query.download(
        data_object_ids,
        args.destination_dir.expanduser().resolve(),
        poll_period=args.poll_period,
    )


def main():
    position()


if __name__ == "__main__":
    main()
