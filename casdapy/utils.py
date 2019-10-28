from pathlib import Path
import hashlib
import binascii
from functools import partial
from typing import Tuple, ByteString


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
    checksum_crc, checksum_digest, checksum_file_size = (
        checksum_file.read_text().split()
    )

    # convert checksum crc and size from hex to int, decode binary digest
    checksum_crc = int(checksum_crc, 16)
    checksum_digest = binascii.unhexlify(checksum_digest)
    checksum_file_size = int(checksum_file_size, 16)

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
