from os import R_OK, W_OK, access, listdir, remove, rmdir, walk
from os.path import abspath, basename, dirname, exists, isabs, isdir, isfile, join as os_join
from secrets import choice
from tarfile import open as tar_open

from crycript import constants, exceptions


def validator(path: str, action: tuple = (False, False, False)) -> tuple:
    if not isabs(path):
        path = abspath(path)

    filename = basename(path)

    if not exists(path):
        raise exceptions.InvalidPath(f"{filename}: does not exist")

    if not isfile(path) and not isdir(path):
        raise exceptions.InvalidPath(f"{filename}: is not a file or a directory")

    if not (access(path, R_OK) and access(path, W_OK)):
        raise exceptions.InvalidPath(f"{filename}: must have read and write permissions")

    if not (access(dirname(path), R_OK) and access(dirname(path), W_OK)):
        raise exceptions.InvalidPath(f"{filename}: parent dir must have read and write permissions")

    # Encryption
    if action[0]:
        if path.endswith(constants.ENCRYPTED_FILE_EXTENSION):
            raise exceptions.InvalidPath(f"{filename}: file already encrypted")

        if isdir(path):
            for root, dirs, files in walk(path):

                for d in dirs:
                    current = os_join(root, d)
                    if not (access(current, R_OK) and access(current, W_OK)):
                        raise exceptions.InvalidPath(
                            f"{filename}: everything inside must have read and write permissions"
                        )

                for f in files:
                    current = os_join(root, f)
                    if not (access(current, R_OK) and access(current, W_OK)):
                        raise exceptions.InvalidPath(
                            f"{filename}: everything inside must have read and write permissions"
                        )

    # Decryption or password change
    elif action[1] or action[2]:
        if not path.endswith(constants.ENCRYPTED_FILE_EXTENSION) or not isfile(path):
            raise exceptions.InvalidPath(f"{filename}: is not a crycript file")

        with open(path, "rb") as file:
            version = file.readline().replace(b'\n', b'')
            if version != constants.BYTES_VERSION:
                message = f"{filename}: invalid crycript version\n"
                message += f"crycript version: {constants.VERSION}\n"
                message += f"file version: {version.decode()}"
                raise exceptions.InvalidPath(message)

    return filename, path


def wipe(path: str):
    if isdir(path):
        for root, dirs, files in walk(path, topdown=False):

            for name in files:
                remove(os_join(root, name))

            for name in dirs:
                rmdir(os_join(root, name))

        rmdir(path)
    elif isfile(path):
        remove(path)


def compress(input_path: str, output_path: str):
    with tar_open(output_path, "w:gz") as tar:
        tar.add(input_path, arcname=basename(input_path))

    if not constants.PRESERVE_ORIGINAL_FILES:
        wipe(input_path)


def extract(input_tar_gz: str, output_directory: str):
    with tar_open(input_tar_gz, "r:gz") as tar:
        tar.extractall(members=tar.getmembers(), path=output_directory)

    wipe(input_tar_gz)


def get_filename(parent_dir: str, prefix: str = '', suffix: str = '') -> str:
    for _ in range(constants.FILENAME_ITERATIONS):
        new_filename = prefix + '-' if prefix else ''

        new_filename += ''.join(
            choice(constants.ENCRYPTED_FILENAME_CHARSET)
            for _ in range(constants.ENCRYPTED_FILENAME_RANDOM_CHARS)
        )

        new_filename += suffix

        if new_filename not in listdir(parent_dir):
            return new_filename
    else:
        raise exceptions.NoFilenameAvailable("No filename available, try again?")
