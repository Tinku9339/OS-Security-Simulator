import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

MAGIC = b"OSV1"

def derive_key(passphrase, salt):
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode())

def encrypt(passphrase, plaintext, aad=b""):
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive_key(passphrase, salt)).encrypt(nonce, plaintext, MAGIC + aad)
    return MAGIC + salt + nonce + ct

def decrypt(passphrase, blob, aad=b""):
    if blob[:4] != MAGIC: raise ValueError("bad format")
    salt, nonce, ct = blob[4:20], blob[20:32], blob[32:]
    try:
        return AESGCM(derive_key(passphrase, salt)).decrypt(nonce, ct, MAGIC + aad)
    except InvalidTag:
        raise ValueError("authentication failed: wrong key or tampered data")
