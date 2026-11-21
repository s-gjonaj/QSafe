
import time
import sqlite3
import json
from pathlib import Path

from crypto import encrypt, decrypt, generate_keypair, kem_encrypt, kem_decrypt

VAULT_PATH = Path(__file__).parent / "vault.db" # creates vault.db on call


def init_db():
    VAULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(VAULT_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            id             INTEGER PRIMARY KEY,
            salt           BLOB NOT NULL,
            public_key     BLOB NOT NULL,
            secret_key_enc BLOB NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id   INTEGER PRIMARY KEY,
            blob BLOB NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def vault_exists() -> bool:
    if not VAULT_PATH.exists():
        return False
    conn = sqlite3.connect(VAULT_PATH)
    row = conn.execute("SELECT id FROM meta WHERE id=1").fetchone()
    conn.close()
    return row is not None


def save_meta(salt: bytes, scrypt_key: bytes):
    start = time.perf_counter()
    public_key, secret_key = generate_keypair()
    secret_key_enc = encrypt(scrypt_key, secret_key)
    conn = sqlite3.connect(VAULT_PATH)
    conn.execute(
        "INSERT INTO meta (id, salt, public_key, secret_key_enc) VALUES (1, ?, ?, ?)",
        (salt, public_key, secret_key_enc)
    )
    conn.commit()
    conn.close()
    print(f"[database] save_meta (generate + store keypair): {(time.perf_counter() - start) * 1000:.3f} ms")


def get_salt() -> bytes:
    conn = sqlite3.connect(VAULT_PATH)
    row = conn.execute("SELECT salt FROM meta WHERE id=1").fetchone()
    conn.close()
    return bytes(row[0])


def get_public_key() -> bytes:
    conn = sqlite3.connect(VAULT_PATH)
    row = conn.execute("SELECT public_key FROM meta WHERE id=1").fetchone()
    conn.close()
    return bytes(row[0])


def get_secret_key(scrypt_key: bytes) -> bytes:
    conn = sqlite3.connect(VAULT_PATH)
    row = conn.execute("SELECT secret_key_enc FROM meta WHERE id=1").fetchone()
    conn.close()
    return decrypt(scrypt_key, bytes(row[0]))


def load_entries(scrypt_key: bytes) -> list:
    start = time.perf_counter()
    conn = sqlite3.connect(VAULT_PATH)
    row = conn.execute("SELECT blob FROM vault WHERE id=1").fetchone()
    conn.close()
    if row is None:
        return []
    secret_key = get_secret_key(scrypt_key)
    plaintext  = kem_decrypt(secret_key, bytes(row[0]))
    result = json.loads(plaintext.decode())
    print(f"load_entries (total):  {(time.perf_counter() - start) * 1000:.3f} ms")
    return result


def save_entries(scrypt_key: bytes, entries: list):
    start = time.perf_counter()
    public_key = get_public_key()
    plaintext  = json.dumps(entries).encode()
    blob       = kem_encrypt(public_key, plaintext)
    conn = sqlite3.connect(VAULT_PATH)
    conn.execute("""
        INSERT INTO vault (id, blob) VALUES (1, ?)
        ON CONFLICT(id) DO UPDATE SET blob=excluded.blob
    """, (blob,))
    conn.commit()
    conn.close()
    print(f"save_entries (total):  {(time.perf_counter() - start) * 1000:.3f} ms")