import binascii
from os import remove
from os.path import basename, dirname, join as os_join
from time import sleep

from cryptography.fernet import Fernet, InvalidToken, InvalidSignature

from crycript import constants, exceptions
from crycript.utils import extract


def decrypt(path: str, key: bytes) -> str:
    try:
        key_cipher = Fernet(key)
    except (ValueError, binascii.Error):
        raise exceptions.InvalidKey("An invalid key was provided")

    filename = basename(path)
    parent_dir = dirname(path)

    with open(path, "rb") as original_file:
        original_file.readline()

        try:
            file_keys = tuple(key_cipher.decrypt(original_file.readline()[:-1]).split(b' '))
        except InvalidToken:
            sleep(constants.INVALID_PASSWORD_DELAY)
            raise exceptions.InvalidPassword("Invalid Password")

        try:
            file_ciphers = tuple(Fernet(key) for key in file_keys)
        except (ValueError, Exception):
            raise exceptions.ReplacedBlock("Key block was replaced")

        del file_keys
        del key_cipher

        try:
            new_filename = file_ciphers[0].decrypt(original_file.readline().replace(b'\n', b'')).decode()
        except InvalidToken:
            raise exceptions.ReplacedBlock("Filename block was replaced")

        with open(os_join(parent_dir, new_filename), "wb") as decrypted_file:
            for line, cipher in enumerate(file_ciphers[1:]):
                try:
                    decrypted_file.write(
                        cipher.decrypt(
                            original_file.readline().replace(b'\n', b'')
                        )
                    )
                except InvalidToken:
                    remove(os_join(parent_dir, new_filename))
                    raise exceptions.ReplacedBlock(f'Encrypted block line {line + 4} was modified')

    if not constants.PRESERVE_ORIGINAL_FILES:
        remove(path)

    extract(os_join(parent_dir, new_filename), parent_dir)
    new_filename = new_filename.replace(constants.COMPRESSED_FILE_EXTENSION, '')

    return f"{filename} -> {new_filename}"
