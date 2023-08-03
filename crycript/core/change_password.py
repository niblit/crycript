import binascii
from os import remove, rename
from os.path import basename, dirname, join as os_join
from time import sleep

from cryptography.fernet import Fernet, InvalidToken

from crycript import constants, exceptions
from crycript.utils import get_filename


def change_password(path: str, old_key: bytes, new_key: bytes) -> str:
    try:
        old_cipher = Fernet(old_key)
        new_cipher = Fernet(new_key)
    except (ValueError, binascii.Error):
        raise exceptions.InvalidKey("An invalid key was provided")

    with open(path, "rb") as old_file:
        version = old_file.readline()

        try:
            encrypted_keys = new_cipher.encrypt(
                old_cipher.decrypt(
                    old_file.readline().replace(b'\n', b'')
                )
            )
        except InvalidToken:
            sleep(constants.INVALID_PASSWORD_DELAY)
            raise exceptions.InvalidPassword("Invalid Password")

        with open(path + constants.TEMPORAL_FILE_EXTENSION, "wb") as new_file:
            new_file.write(version)

            new_file.write(encrypted_keys)
            new_file.write(b'\n')

            for line in old_file:
                new_file.write(line)

    if not constants.PRESERVE_ORIGINAL_FILES:
        remove(path)
        rename(path + constants.TEMPORAL_FILE_EXTENSION, path)
        status = "Password updated successfully"
    else:
        old_filename = basename(path)
        new_filename = get_filename(
            dirname(path),
            old_filename[:constants.ENCRYPTED_FILENAME_ORIGINAL_CHARS],
            constants.ENCRYPTED_FILE_EXTENSION
        )
        rename(path + constants.TEMPORAL_FILE_EXTENSION, os_join(dirname(path), new_filename))
        status = f"{old_filename} -> {new_filename}"

    return status
