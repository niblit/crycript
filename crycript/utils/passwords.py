from base64 import urlsafe_b64encode
from getpass import getpass
from hashlib import sha3_512

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA3_512
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crycript import constants, exceptions


def lfsr_salt(password) -> bytes:
    binary = bin(
        int(
            sha3_512(
                password.encode()
            ).hexdigest(),
            16
        )
    )[-128:]

    salt = sha3_512()

    def str_xor(a: str, b: str) -> str:
        return '0' if a == b else '1'

    for _ in range(constants.SALT_ITERATIONS):
        num = ""
        for _ in range(8):
            xor = str_xor(binary[-1], binary[-2])
            xor = str_xor(xor, binary[-3])
            xor = str_xor(xor, binary[-8])

            binary = xor + binary[:-1]
            num += binary[-1]

        salt.update(
            chr(
                int(num, 2)
            ).encode()
        )
    return salt.hexdigest().encode()


def get_key(
        confirm_password: bool = True,
        password_message: str = 'Password: ',
        confirmation_message: str = 'Repeat Password: '
) -> bytes:
    try:
        password = getpass(password_message)
    except (KeyboardInterrupt, EOFError):
        print()
        raise SystemExit

    if len(password) < constants.MINIMUM_PASSWORD_LENGTH:
        raise exceptions.InvalidPassword(f"Minimum password length is {constants.MINIMUM_PASSWORD_LENGTH} characters")

    if len(password) > constants.MAXIMUM_PASSWORD_LENGTH:
        raise exceptions.InvalidPassword(f"Maximum password length is {constants.MAXIMUM_PASSWORD_LENGTH} characters")

    is_invalid = False

    is_invalid |= not any(
        char.islower()
        for char in password
    )

    is_invalid |= not any(
        char.isupper()
        for char in password
    )

    is_invalid |= not any(
        char.isdigit()
        for char in password
    )

    is_invalid |= not any(
        char.isprintable() and not char.isalnum()
        for char in password
    )

    if is_invalid:
        raise exceptions.InvalidPassword("Password must have lowercase, uppercase, digits and symbols")

    if confirm_password:
        try:
            if getpass(confirmation_message) != password:
                raise exceptions.InvalidPassword("Passwords do not match")
        except (KeyboardInterrupt, EOFError):
            print()
            raise SystemExit

    kdf = PBKDF2HMAC(
        algorithm=SHA3_512(),
        length=32,
        salt=lfsr_salt(password),
        iterations=constants.PBKDF2_ITERATIONS,
        backend=default_backend()
    )

    return urlsafe_b64encode(
        kdf.derive(
            password.encode()
        )
    )
