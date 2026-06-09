import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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

def encrypt(data:bytes, password:str) -> bytes:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = derive_key(password,salt)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce,data,None)
        blob = salt + nonce + ciphertext
        return blob
    
    
def decrypt(blob:bytes, password:str) -> bytes:
        salt = blob[:16]
        nonce = blob[16:28]
        ciphertext = blob[28:]
        derived_key = derive_key(password,salt)
        aesgcm = AESGCM(derived_key)
        aesgcm_decrypted = aesgcm.decrypt(nonce,ciphertext,None)
        return aesgcm_decrypted
        
    