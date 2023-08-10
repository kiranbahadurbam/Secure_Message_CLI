import secrets
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

KEY_LENGTH = 128

def format_key(key: str) -> str:
    key_str = ''
    count = 0

    for i in str(key):
        if count <= 3:
            key_str += i
            count += 1
        else:
            count = 0
            key_str += ' '

    return key_str.strip()

def generate_key() -> int:
    return secrets.randbits(KEY_LENGTH)

def hash_data(data: str) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode())
    return digest.finalize()

def create_hmac(key: bytes, message: str) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode())
    return h.finalize()
