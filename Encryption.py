from cryptography.fernet import Fernet


# Init encryption method
def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


# Init decryption method
def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)
