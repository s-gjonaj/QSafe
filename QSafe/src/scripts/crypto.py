import os
import time
import hashlib
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# upon typing your passcode, its scrambled using scrypt and "salt" is added to the result, so two passwords do not have the same key
def derive_key(password: str, salt: bytes) -> bytes:
    start = time.perf_counter()
    key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,  # 2**14 is considered recommended minimum cost for standard interactive logins
        r=8,
        p=1,
        dklen=32,
    )
    print(f"derive_key (Scrypt):     {(time.perf_counter() - start) * 1000:.3f} ms")
    return key

# generates initnum, 12 bytes. uses said bytes to scramble data using aes-256-gcm, then sticks initnum onto the result
def encrypt(key: bytes, data: bytes) -> bytes:
    start = time.perf_counter()
    initnum = os.urandom(12)
    encrypted = AESGCM(key).encrypt(initnum, data, None)
    print(f"encrypt:   {(time.perf_counter() - start) * 1000:.3f} ms")
    return initnum + encrypted

# takes the blob the encrypt function made, and uses the key from initnum to unscramble
def decrypt(key: bytes, blob: bytes) -> bytes:
    start = time.perf_counter()
    initnum = blob[:12]
    encrypted = blob[12:]
    result = AESGCM(key).decrypt(initnum, encrypted, None)
    print(f"decrypt:   {(time.perf_counter() - start) * 1000:.3f} ms")
    return result

# used once, generates a ML-KEM-768 keypair
def generate_keypair() -> tuple[bytes, bytes]:
    start = time.perf_counter()
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    print(f"generate_keypair / ML-KEM-768: {(time.perf_counter() - start) * 1000:.3f} ms")
    return public_key, secret_key


# encrypts data using ML-KEM-768
def kem_encrypt(public_key: bytes, data: bytes) -> bytes:
    start = time.perf_counter()
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    aes_blob = encrypt(shared_secret, data)
    ct_len = len(ciphertext).to_bytes(4, "big")
    print(f"kem_encrypt (ML-KEM-768 + AES): {(time.perf_counter() - start) * 1000:.3f} ms total")
    return ct_len + ciphertext + aes_blob

# reverses kem_encrypt function when called.
def kem_decrypt(secret_key: bytes, blob: bytes) -> bytes:
    start = time.perf_counter()
    ct_len     = int.from_bytes(blob[:4], "big")
    ciphertext = blob[4:4 + ct_len]
    aes_blob   = blob[4 + ct_len:]
    with oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    result = decrypt(shared_secret, aes_blob)
    print(f"kem_decrypt (ML-KEM-768 + AES): {(time.perf_counter() - start) * 1000:.3f} ms total")
    return result