import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(key, plaintext):
    # Ensure the key length is 16, 24, or 32 bytes for AES
    key = key.ljust(32)[:32].encode('utf-8')

    # IV should be random but static in this context for deterministic output
    iv = b'1234567890123456'

    # Create a Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the plaintext to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Combine IV and ciphertext and encode in Base64
    encoded_ciphertext = base64.b64encode(iv + ciphertext).decode('utf-8')

    return encoded_ciphertext


def decrypt(key, encoded_ciphertext):
    # Ensure the key length is 16, 24, or 32 bytes for AES
    key = key.ljust(32)[:32].encode('utf-8')

    # Decode the Base64 encoded ciphertext
    ciphertext = base64.b64decode(encoded_ciphertext)

    # Extract the IV (first 16 bytes)
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Create a Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode('utf-8')
