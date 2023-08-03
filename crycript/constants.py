VERSION:                               str = "crycript 2021.11.27"
BYTES_VERSION:                         bytes = b"crycript 2021.11.27"

MINIMUM_PASSWORD_LENGTH:               int = 8
MAXIMUM_PASSWORD_LENGTH:               int = 4_000
INVALID_PASSWORD_DELAY:                float = 2.0

PBKDF2_ITERATIONS:                     int = 200_000
SALT_ITERATIONS:                       int = 100_000

ENCRYPTED_FILENAME_ORIGINAL_CHARS:     int = 2
ENCRYPTED_FILENAME_RANDOM_CHARS:       int = 4
ENCRYPTED_FILENAME_CHARSET:            str = "abcdefghijklmnopqrstuvwxyz"
FILENAME_ITERATIONS:                   int = 100_000

ENCRYPTED_FILE_EXTENSION:              str = ".cry"
TEMPORAL_FILE_EXTENSION:               str = ".cry_t"
COMPRESSED_FILE_EXTENSION:             str = ".cry_c"

PRESERVE_ORIGINAL_FILES:               bool = False

ENCRYPTION_BUFFER_SIZE:                int = 10_000_000

SOURCE:                                str = "https://github.com/niblit/crycript"
