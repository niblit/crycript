from base64 import urlsafe_b64encode
from getpass import getpass
from hashlib import sha3_512
from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA3_512
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crycript import constants, exceptions

def generate_salt():
    return urlsafe_b64encode(urandom(32))

def get_key(
        confirm_password: bool = True,
        password_message: str = 'Password: ',
        confirmation_message: str = 'Repeat Password: ',
        salt: str = None
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

    if salt is None:
        salt = generate_salt()

    kdf = PBKDF2HMAC(
        algorithm=SHA3_512(),
        length=32,
        salt=salt,
        iterations=constants.PBKDF2_ITERATIONS,
        backend=default_backend()
    )

    return salt, urlsafe_b64encode(
        kdf.derive(
            password.encode()
        )
    )
