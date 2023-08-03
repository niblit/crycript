import binascii
from math import ceil
from os import remove
from os.path import basename, dirname, getsize, join as os_join

from cryptography.fernet import Fernet

from crycript import constants, exceptions
from crycript.utils import compress, get_filename


def encrypt(path: str, key: bytes) -> str:
    try:
        key_cipher = Fernet(key)
    except (ValueError, binascii.Error):
        raise exceptions.InvalidKey("An invalid key was provided")

    filename = basename(path)
    parent_dir = dirname(path)

    new_filename = get_filename(
        parent_dir,
        filename[:constants.ENCRYPTED_FILENAME_ORIGINAL_CHARS]
        if len(filename) > constants.ENCRYPTED_FILENAME_ORIGINAL_CHARS
        else
        filename,
        constants.ENCRYPTED_FILE_EXTENSION
    )

    compressed_filename = filename + constants.COMPRESSED_FILE_EXTENSION
    compressed_path = path + constants.COMPRESSED_FILE_EXTENSION

    compress(path, compressed_path)

    rounds = ceil(getsize(compressed_path) / constants.ENCRYPTION_BUFFER_SIZE)

    file_keys = tuple(Fernet.generate_key() for _ in range(rounds + 1))

    file_ciphers = tuple(Fernet(key) for key in file_keys)

    encrypted_file_keys = key_cipher.encrypt(b' '.join(file_keys))
    del file_keys
    del key_cipher

    with open(compressed_path, 'rb') as original_file:
        with open(os_join(parent_dir, new_filename), 'wb') as encrypted_file:
            encrypted_file.write(constants.BYTES_VERSION)
            encrypted_file.write(b'\n')

            encrypted_file.write(encrypted_file_keys)
            encrypted_file.write(b'\n')

            encrypted_file.write(file_ciphers[0].encrypt(compressed_filename.encode()))
            encrypted_file.write(b'\n')

            for cipher in file_ciphers[1:]:
                encrypted_file.write(
                    cipher.encrypt(
                        original_file.read(constants.ENCRYPTION_BUFFER_SIZE)
                    )
                )

                encrypted_file.write(b'\n')

    remove(compressed_path)

    return f"{filename} -> {new_filename}"
