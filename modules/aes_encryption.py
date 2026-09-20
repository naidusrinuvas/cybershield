"""
AES File Encryption
Uses Fernet (AES-128-CBC + HMAC) from the `cryptography` library,
with a key derived from a user-supplied password via PBKDF2-HMAC-SHA256.
"""

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
PBKDF2_ITERATIONS = 390_000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    salt = os.urandom(SALT_SIZE)
    key = _derive_key(password, salt)
    fernet = Fernet(key)

    with open(input_path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)

    # Prepend salt so decryption can re-derive the same key
    with open(output_path, "wb") as f:
        f.write(salt + encrypted)


def decrypt_file(input_path: str, output_path: str, password: str) -> bool:
    with open(input_path, "rb") as f:
        raw = f.read()

    salt, encrypted = raw[:SALT_SIZE], raw[SALT_SIZE:]
    key = _derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken:
        return False

    with open(output_path, "wb") as f:
        f.write(decrypted)
    return True
