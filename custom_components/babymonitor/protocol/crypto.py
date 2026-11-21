"""Cryptographic primitives for Tuya LAN, Cloud (ATOP ET=3), and Media protocols."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import zlib
from typing import Optional, Tuple

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TUYA_PREFIX_55AA = 0x000055AA
TUYA_SUFFIX_AA55 = 0x0000AA55
TUYA_PREFIX_6699 = 0x00006699
TUYA_SUFFIX_9966 = 0x00009966

# UDP discovery key: MD5("yGAdlopoPVldABfn")
UDP_DISCOVERY_KEY = hashlib.md5(b"yGAdlopoPVldABfn").digest()

APP_PACKAGE_NAME = "com.philips.ph.babymonitorplus"

SIGN_WHITELIST = {
    "a",
    "v",
    "lat",
    "lon",
    "lang",
    "deviceId",
    "appVersion",
    "ttid",
    "isH5",
    "h5Token",
    "os",
    "clientId",
    "postData",
    "time",
    "requestId",
    "et",
    "n4h5",
    "sid",
    "chKey",
    "sp",
}


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


def aes_gcm_encrypt(
    key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b""
) -> Tuple[bytes, bytes]:
    """Encrypt with AES-128-GCM, returning (ciphertext, tag)."""
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, plaintext, aad)
    return ct_and_tag[:-16], ct_and_tag[-16:]


def aes_gcm_decrypt(
    key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""
) -> bytes:
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


# ─────────────────────────────────────────────────────────────────────────────
# Tuya Mobile-App ("ATOP") Signing & ET=3 Encryption (ported from sign.rs)
# ─────────────────────────────────────────────────────────────────────────────


def swap_sign_string(s: str) -> str:
    """Permute 32-char MD5 hex: s[8:16] + s[0:8] + s[24:32] + s[16:24]."""
    if len(s) != 32 or not s.isascii():
        raise ValueError(f"swap_sign_string expects 32 ASCII chars, got {len(s)}")
    return s[8:16] + s[0:8] + s[24:32] + s[16:24]


def post_data_digest_hex(body: bytes) -> str:
    """Compute postData digest: swap_sign_string(md5_hex_lower(body))."""
    md5_hex = hashlib.md5(body).hexdigest()
    return swap_sign_string(md5_hex)


def canonical_string(params: dict[str, str]) -> str:
    """Build the Tuya canonical string-to-sign (str2) from whitelisted envelope params."""
    keys = sorted(k for k, v in params.items() if k in SIGN_WHITELIST and v != "")
    return "||".join(f"{k}={params[k]}" for k in keys)


def assemble_master_key_g(
    package_name: str,
    cert_colon_upper: str,
    bmp_token_hex: str,
    app_secret: str,
) -> bytes:
    """Assemble the 4-part raw byte master key G:
    packageName + '_' + certColonUpper + '_' + hex_decode(bmp_token) + '_' + appSecret
    """
    matrix_key0 = bytes.fromhex(bmp_token_hex.strip())
    return (
        package_name.encode("utf-8")
        + b"_"
        + cert_colon_upper.encode("utf-8")
        + b"_"
        + matrix_key0
        + b"_"
        + app_secret.encode("utf-8")
    )


def compute_ch_key(
    app_key: str,
    package_name: str,
    cert_colon_upper: str,
) -> str:
    """Compute the 8-char per-app channel-auth token (chKey)."""
    msg = f"{package_name}_{cert_colon_upper}".encode("utf-8")
    mac_hex = hmac.new(app_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return mac_hex[8:16]


def et3_encrypto_key(
    request_id: str,
    master_key_g: bytes,
    ecode: Optional[str] = None,
) -> bytes:
    """Derive the 16-byte ET=3 AES-128-GCM key for postData and response decryption."""
    msg = master_key_g
    if ecode:
        msg = msg + b"_" + ecode.encode("utf-8")
    mac_hex = hmac.new(request_id.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return mac_hex[:16].encode("ascii")


def encrypt_et3_post_data(
    request_id: str,
    master_key_g: bytes,
    post_data_json: str,
    ecode: Optional[str] = None,
    nonce: Optional[bytes] = None,
) -> str:
    """Encrypt postData JSON using ET=3 AES-128-GCM and return base64(nonce||ct||tag)."""
    key = et3_encrypto_key(request_id, master_key_g, ecode)
    iv = nonce if nonce is not None else os.urandom(12)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, post_data_json.encode("utf-8"), b"")
    return base64.b64encode(iv + ct_and_tag).decode("ascii")


def decrypt_et3_result(
    request_id: str,
    master_key_g: bytes,
    result_b64: str,
    ecode: Optional[str] = None,
) -> bytes:
    """Decrypt an ET=3 base64(nonce||ct||tag) response envelope."""
    key = et3_encrypto_key(request_id, master_key_g, ecode)
    raw = base64.b64decode(result_b64)
    if len(raw) < 28:
        raise ValueError("ET=3 response too short")
    iv, ct_and_tag = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ct_and_tag, b"")


def sign_atop_request(params: dict[str, str], master_key_g: bytes) -> str:
    """Compute the 64-char lowercase hex HMAC-SHA256 request signature over str2."""
    str2 = canonical_string(params)
    return hmac.new(master_key_g, str2.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_tuya_request(params: dict[str, str], secret: str) -> str:
    """Compute legacy MD5 signature over sorted key=value pairs."""
    sorted_keys = sorted(params.keys())
    parts = [f"{k}={params[k]}" for k in sorted_keys if params[k] != ""]
    payload = "||".join(parts) + f"||{secret}"
    return hashlib.md5(payload.encode("utf-8")).hexdigest()


def rsa_encrypt_password(public_key_modulus: str, exponent: str, password: str) -> str:
    """RSA-PKCS1v15 encrypt the 32-char lowercase MD5 hex of the password."""
    mod_str = public_key_modulus.strip()
    n = int(mod_str, 10) if mod_str.isdigit() else int(mod_str, 16)
    exp_str = exponent.strip()
    e = int(exp_str, 10) if exp_str.isdigit() else 65537
    pub_numbers = rsa.RSAPublicNumbers(e, n)
    pub_key = pub_numbers.public_key()
    pw_md5_hex = hashlib.md5(password.encode("utf-8")).hexdigest().encode("ascii")
    ct = pub_key.encrypt(pw_md5_hex, asym_padding.PKCS1v15())
    return ct.hex()


def generate_phone_util_device_id(
    brand: str = "google",
    model: str = "Pixel 8 Pro",
    rand_a: Optional[bytes] = None,
    rand_b: Optional[bytes] = None,
) -> str:
    """Generate a 44-char lowercase hex PhoneUtil-shaped deviceId."""
    ra = rand_a if rand_a is not None else os.urandom(32)
    rb = rand_b if rand_b is not None else os.urandom(32)
    seg1 = hashlib.md5(f"{brand}{model}".encode("utf-8")).hexdigest()[4:16]
    seg2 = hashlib.md5(ra).hexdigest()[8:24]
    seg3 = hashlib.md5(rb).hexdigest()[16:32]
    return f"{seg1}{seg2}{seg3}"


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
