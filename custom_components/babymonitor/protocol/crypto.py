"""Cryptographic primitives for Tuya LAN, Cloud, and Media protocols."""

from __future__ import annotations

import hashlib
import hmac
import struct
import zlib
from typing import Tuple

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TUYA_PREFIX_55AA = 0x000055AA
TUYA_SUFFIX_AA55 = 0x0000AA55
TUYA_PREFIX_6699 = 0x00006699
TUYA_SUFFIX_9966 = 0x00009966

# UDP discovery key: MD5("yGAdlopoPVldABfn")
UDP_DISCOVERY_KEY = hashlib.md5(b"yGAdlopoPVldABfn").digest()


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS7 padding."""
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Remove PKCS7 padding."""
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-128-ECB + PKCS7."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt with AES-128-ECB + PKCS7."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)


def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Encrypt with AES-128-GCM, returning (ciphertext, tag)."""
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, plaintext, aad)
    return ct_and_tag[:-16], ct_and_tag[-16:]


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt with AES-128-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext + tag, aad)


def decrypt_media_packet(media_key: bytes, packet: bytes) -> bytes:
    """Decrypt a Tuya KCP media packet (AES-128-CBC + HMAC-SHA1).

    Format: [16-byte IV] [ciphertext] [20-byte HMAC-SHA1]
    """
    if len(packet) < 36:
        raise ValueError(f"Media packet too short: {len(packet)} bytes")

    iv = packet[:16]
    mac = packet[-20:]
    ciphertext = packet[16:-20]

    expected_mac = hmac.new(media_key, packet[:-20], hashlib.sha1).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("Media packet HMAC-SHA1 verification failed")

    cipher = Cipher(algorithms.AES(media_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)


def sign_tuya_request(params: dict[str, str], secret: str) -> str:
    """Compute Tuya mobile-app MD5 signature over sorted key=value pairs."""
    sorted_keys = sorted(params.keys())
    parts = [f"{k}={params[k]}" for k in sorted_keys if params[k] != ""]
    payload = "||".join(parts) + f"||{secret}"
    return hashlib.md5(payload.encode("utf-8")).hexdigest()


def pack_frame_55aa(seq: int, cmd: int, payload: bytes) -> bytes:
    """Pack a Tuya 55AA LAN frame."""
    length = len(payload) + 8  # crc32 (4) + suffix (4)
    header = struct.pack(">IIII", TUYA_PREFIX_55AA, seq, cmd, length)
    body = header + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack(">II", crc, TUYA_SUFFIX_AA55)


def unpack_frame_55aa(data: bytes) -> Tuple[int, int, bytes, int]:
    """Unpack a Tuya 55AA LAN frame.

    Returns (seq, cmd, payload, total_consumed_bytes).
    """
    if len(data) < 20:
        raise ValueError("Incomplete 55AA frame header")
    prefix, seq, cmd, length = struct.unpack(">IIII", data[:16])
    if prefix != TUYA_PREFIX_55AA:
        raise ValueError(f"Invalid 55AA prefix: {prefix:#x}")
    total_len = 16 + length
    if len(data) < total_len:
        raise ValueError("Incomplete 55AA frame body")
    payload = data[16 : total_len - 8]
    crc, suffix = struct.unpack(">II", data[total_len - 8 : total_len])
    if suffix != TUYA_SUFFIX_AA55:
        raise ValueError(f"Invalid 55AA suffix: {suffix:#x}")
    expected_crc = zlib.crc32(data[: total_len - 8]) & 0xFFFFFFFF
    if crc != expected_crc:
        raise ValueError(f"CRC mismatch: got {crc:#x}, expected {expected_crc:#x}")
    return seq, cmd, payload, total_len
