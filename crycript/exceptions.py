class CrycriptException(BaseException):
    """Base exception for crycript, can be used as a catch all"""
    pass


class CoreException(CrycriptException):
    """Base exception for core subpackage"""
    pass


class InvalidKey(CoreException):
    """Used when an invalid cryptography.fernet.Fernet key is provided as a parameter"""
    pass


class InvalidPassword(CoreException):
    """Not the encryption password for that crycript file"""
    pass


class ReplacedBlock(CoreException):
    """Some line(s) of the file were replaced / modified so decryption is impossible"""
    pass


class NoFilenameAvailable(CoreException):
    """Every random filename tried is in use in the parent dir"""
    pass


class UtilsException(CrycriptException):
    """Base exception for Utils subpackage"""
    pass


class InvalidPath(UtilsException):
    """Path does not meet the requirements for encryption / decryption"""
    pass
