import argparse
import getpass
import logging
from pathlib import Path

from casdapy.images import CasdaSbidImageQuery

logging.basicConfig(format="%(asctime)-15s %(module)s: %(levelname)s %(message)s")
logger = logging.getLogger("casdapy")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sbid", help="The ASKAP SBID.")
    parser.add_argument(
        "--credentials_file",
        type=Path,
        help=(
            "Read ATNF OPAL account credentials from a file containing the username "
            "and password on separate lines. If not supplied, user will be prompted to "
            "enter these via stdin."
        ),
    )
    parser.add_argument(
        "--destination_dir",
        type=Path,
        help="Directory to save downloaded images. Defaults to current directory.",
        default=".",
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

    casda_query = CasdaSbidImageQuery(args.sbid, opal_username, opal_password)
    casda_query.run(args.destination_dir.expanduser().resolve())

    # TODO: verify checksums


if __name__ == "__main__":
    main()
