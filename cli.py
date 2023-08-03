from argparse import ArgumentParser

import crycript

parser = ArgumentParser(
    description="Python symmetric encryption by niblit",
    epilog=f"{crycript.VERSION} at {crycript.SOURCE}"
)

parser.add_argument(
    "-v",
    "--version",
    help="show version and exit",
    action="version",
    version=crycript.VERSION
)

parser.add_argument(
    "-k",
    "--keep",
    help="preserve original files",
    action="store_true"
)

parser.add_argument(
    "path",
    help="path to file or directory"
)

core_group = parser.add_mutually_exclusive_group(required=True)

core_group.add_argument(
    "-e",
    "--encrypt",
    help="encrypt a file or directory",
    action="store_true"
)

core_group.add_argument(
    "-d",
    "--decrypt",
    help="decrypt a crycript file",
    action="store_true"
)

core_group.add_argument(
    "-c",
    "--change-password",
    help="change the password of a crycript file",
    action="store_true",
    dest="change_password"
)


def main():
    arguments = parser.parse_args()
    crycript.constants.PRESERVE_ORIGINAL_FILES = arguments.keep

    try:
        core = (arguments.encrypt, arguments.decrypt, arguments.change_password)

        filename, path = crycript.validator(
            arguments.path,
            action=core
        )

        # Encryption
        if core[0]:
            key = crycript.get_key()

            print(
                crycript.encrypt(path, key)
            )

        # Decryption
        elif core[1]:
            key = crycript.get_key(confirm_password=False)

            print(
                crycript.decrypt(path, key)
            )

        # Change password
        elif core[2]:
            old_key = crycript.get_key(
                password_message="Old password: ",
                confirm_password=False
            )

            new_key = crycript.get_key(
                password_message="New password: "
            )

            print(
                crycript.change_password(path, old_key, new_key)
            )

    except crycript.CrycriptException as e:
        print(e)
        raise SystemExit

    except BaseException as e:
        print("An unhandled exception occurred:")
        print(e)
        print(f"please submit a report at {crycript.SOURCE}")


if __name__ == "__main__":
    main()
