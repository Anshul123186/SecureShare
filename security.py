import base64
import os
from dataclasses import dataclass
from hashlib import sha256
from typing import Tuple

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from flask import current_app


def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def file_sha256(data: bytes) -> str:
    return sha256(data).hexdigest()


def _get_aes_key() -> bytes:
    raw = current_app.config["FILE_ENCRYPTION_KEY"]
    # Accept hex-encoded 32-byte key for AES-256
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass

    # Fallback: derive from arbitrary string with SHA-256
    return sha256(raw.encode("utf-8")).digest()


@dataclass
class EncryptedData:
    nonce: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        # Simple concatenation: nonce || ciphertext
        return self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, raw: bytes) -> "EncryptedData":
        nonce = raw[:12]
        ciphertext = raw[12:]
        return cls(nonce=nonce, ciphertext=ciphertext)


def encrypt_file_bytes(plaintext: bytes, associated_data: bytes | None = None) -> Tuple[bytes, str]:
    key = _get_aes_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    encrypted = EncryptedData(nonce=nonce, ciphertext=ciphertext)
    digest = file_sha256(plaintext)
    return encrypted.to_bytes(), digest


def decrypt_file_bytes(encrypted_bytes: bytes, associated_data: bytes | None = None) -> bytes:
    key = _get_aes_key()
    aesgcm = AESGCM(key)
    encrypted = EncryptedData.from_bytes(encrypted_bytes)
    return aesgcm.decrypt(encrypted.nonce, encrypted.ciphertext, associated_data)

