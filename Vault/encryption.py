import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding,hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 480000,
        
    )
    key = kdf.derive(password.encode())
    return key