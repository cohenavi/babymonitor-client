"""Pure Python port of the APK cert SHA-256 and t_s.bmp matrix token extraction."""

from __future__ import annotations

from fractions import Fraction
import hashlib
from pathlib import Path
from typing import List, Optional, Tuple
import zipfile


def strhash(s: bytes) -> int:
    """Port of libthing_security_algorithm.so strhash (FUN_0010509c)."""
    nul = s.find(b"\x00")
    if nul != -1:
        s = s[:nul]
    acc = 0
    for c in s:
        acc = (acc * 31 + c) & 0xFFFFFFFF
    if acc >= 0x80000000:
        acc -= 0x100000000
    return abs(acc)


def xorstep_u32(px: bytes, off: int) -> int:
    """Port of xorstep_583c (FUN_0010583c): read 4 big-endian pixel bytes mod L."""
    length = len(px)
    b0 = px[off % length]
    b1 = px[(off + 1) % length]
    b2 = px[(off + 2) % length]
    b3 = px[(off + 3) % length]
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


def _hexstr_to_fraction(hexstr: str) -> Fraction:
    if not hexstr:
        return Fraction(0)
    if "/" in hexstr:
        num, den = hexstr.split("/", 1)
        return Fraction(int(num, 16), int(den, 16))
    return Fraction(int(hexstr, 16))


def _matrix_solve(pairs: List[Tuple[str, str]]) -> Optional[bytes]:
    """Solve Vandermonde system over exact rationals; require denominator == 1."""
    n = len(pairs)
    if n == 0:
        return None
    a_vals = [_hexstr_to_fraction(a) for a, _ in pairs]
    b_vals = [_hexstr_to_fraction(b) for _, b in pairs]
    mat: List[List[Fraction]] = []
    for i in range(n):
        row = [a_vals[i] ** (n - 1 - j) for j in range(n)]
        row.append(b_vals[i])
        mat.append(row)
    for col in range(n):
        piv = None
        for r in range(col, n):
            if mat[r][col] != 0:
                piv = r
                break
        if piv is None:
            return None
        mat[col], mat[piv] = mat[piv], mat[col]
        for r in range(col + 1, n):
            if mat[r][col] != 0:
                factor = mat[r][col] / mat[col][col]
                for k in range(col, n + 1):
                    mat[r][k] -= factor * mat[col][k]
    denom_pivot = mat[n - 1][n - 1]
    if denom_pivot == 0:
        return None
    c = mat[n - 1][n] / denom_pivot
    if c.denominator != 1:
        return None
    num = c.numerator
    if num < 0:
        return None
    if num == 0:
        return b""
    byte_len = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_len, "big").lstrip(b"\x00")


def decode_bmp_token(app_key: str, bmp_raw: bytes) -> str:
    """Decode the 64-hex bmp_token (matrixKey0) from raw t_s.bmp bytes and appKey."""
    if bmp_raw[:2] != b"BM":
        raise ValueError("Invalid t_s.bmp: missing BM header")
    filesize = int.from_bytes(bmp_raw[2:6], "little")
    bf_off_bits = int.from_bytes(bmp_raw[10:14], "little")
    pixel_len = filesize - bf_off_bits
    if pixel_len <= 0 or 0x36 + pixel_len > len(bmp_raw):
        raise ValueError("Invalid t_s.bmp pixel dimensions")

    px = bmp_raw[0x36 : 0x36 + pixel_len]
    config = app_key.encode("utf-8")
    h = strhash(config)
    r = (h % pixel_len) // 2
    base = r % pixel_len
    sel = px[base]
    if sel != 1:
        raise ValueError(f"Unsupported t_s.bmp selector byte: {sel}")

    num_keys = px[(base + 1) % pixel_len]
    num_coeffs = px[(base + 2) % pixel_len]
    if not (0 < num_keys < 6) or num_coeffs == 0:
        raise ValueError("Invalid t_s.bmp key/coefficient counts")

    off = (xorstep_u32(px, (base + 3) % pixel_len) ^ r) % pixel_len
    pairs: List[Tuple[str, str]] = []
    for _ in range(num_coeffs):
        pair_start = off
        alen = px[off % pixel_len]
        a_hex = "".join(
            f"{px[(off + 1 + i) % pixel_len]:02x}" for i in range(alen)
        )
        off2 = (off + 1 + alen) % pixel_len
        blen = px[off2 % pixel_len]
        b_hex = "".join(
            f"{px[(off2 + 1 + i) % pixel_len]:02x}" for i in range(blen)
        )
        off = (off2 + 1 + blen) % pixel_len
        pairs.append((a_hex, b_hex))
        off = (xorstep_u32(px, off) ^ pair_start) % pixel_len

    group = num_coeffs // num_keys if num_keys else num_coeffs
    keys: List[str] = []
    for g in range(num_keys):
        chunk = pairs[g * group : (g + 1) * group]
        solved = _matrix_solve(chunk)
        if solved is None:
            raise ValueError("t_s.bmp Vandermonde solve failed")
        keys.append(solved.hex())
    return "_".join(keys)


def _der_length(b: bytes, at: int) -> Optional[Tuple[int, int]]:
    if at >= len(b):
        return None
    first = b[at]
    if (first & 0x80) == 0:
        return at + 1, first
    n = first & 0x7F
    if n == 0 or n > 4 or at + 1 + n > len(b):
        return None
    length = 0
    for k in range(n):
        length = (length << 8) | b[at + 1 + k]
    return at + 1 + n, length


def _der_tlv(b: bytes, at: int, tag: int) -> Optional[Tuple[int, int]]:
    if at >= len(b) or b[at] != tag:
        return None
    res = _der_length(b, at + 1)
    if res is None:
        return None
    cs, cl = res
    end = cs + cl
    return (cs, end) if end <= len(b) else None


def extract_leaf_cert_der(pkcs7_der: bytes) -> bytes:
    """Extract the leaf X.509 certificate DER from a PKCS#7 SignedData block."""
    ci = _der_tlv(pkcs7_der, 0, 0x30)
    if ci is None:
        raise ValueError("PKCS#7: outer ContentInfo SEQUENCE not found")
    ci_content, _ = ci
    oid = _der_tlv(pkcs7_der, ci_content, 0x06)
    if oid is None:
        raise ValueError("PKCS#7: contentType OID not found")
    _, after_oid = oid
    c0 = _der_tlv(pkcs7_der, after_oid, 0xA0)
    if c0 is None:
        raise ValueError("PKCS#7: content [0] EXPLICIT tag not found")
    c0_content, _ = c0
    sd = _der_tlv(pkcs7_der, c0_content, 0x30)
    if sd is None:
        raise ValueError("PKCS#7: SignedData SEQUENCE not found")
    sd_content, sd_end = sd

    p = sd_content
    while p < sd_end:
        tag = pkcs7_der[p]
        res = _der_length(pkcs7_der, p + 1)
        if res is None:
            raise ValueError("PKCS#7: bad length in SignedData")
        content, cl = res
        end = content + cl
        if tag == 0xA0:
            # Return the first certificate SEQUENCE in certificates [0]
            cert_res = _der_length(pkcs7_der, content + 1)
            if cert_res is None or pkcs7_der[content] != 0x30:
                raise ValueError("PKCS#7: certificate SEQUENCE not found")
            cert_cs, cert_cl = cert_res
            return pkcs7_der[content : cert_cs + cert_cl]
        p = end
    raise ValueError("PKCS#7: no certificates [0] block found")


def format_cert_colon_upper(digest: bytes) -> str:
    """Format a 32-byte SHA-256 digest as colon-grouped UPPERCASE hex (95 chars)."""
    return ":".join(f"{b:02X}" for b in digest)


def extract_apk_signing_secrets(apk_path: str | Path, app_key: str) -> Tuple[str, str]:
    """Extract (cert_sha256_colon_upper, bmp_token) offline from an APK file."""
    with zipfile.ZipFile(apk_path, "r") as zf:
        bmp_raw: Optional[bytes] = None
        pkcs7_der: Optional[bytes] = None
        for name in zf.namelist():
            if name == "assets/t_s.bmp" or name.endswith("/t_s.bmp"):
                bmp_raw = zf.read(name)
            elif name.startswith("META-INF/") and name.upper().endswith(
                (".RSA", ".DSA", ".EC")
            ):
                pkcs7_der = zf.read(name)

        if pkcs7_der is None:
            raise ValueError("No META-INF/*.RSA signature block found in APK")
        if bmp_raw is None:
            raise ValueError("No assets/t_s.bmp found in APK")

        cert_der = extract_leaf_cert_der(pkcs7_der)
        digest = hashlib.sha256(cert_der).digest()
        cert_colon_upper = format_cert_colon_upper(digest)
        bmp_token = decode_bmp_token(app_key, bmp_raw)
        return cert_colon_upper, bmp_token
