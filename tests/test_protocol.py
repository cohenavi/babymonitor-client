"""Unit tests for the Baby Monitor+ pure Python protocol layer."""

from __future__ import annotations

import json
import sys
import types
import unittest
from pathlib import Path

# Allow importing protocol modules without homeassistant installed
ROOT = Path(__file__).resolve().parent.parent
PKG_PATH = ROOT / "custom_components" / "babymonitor"
sys.path.insert(0, str(ROOT))

# Stub custom_components.babymonitor package so relative imports work
if "custom_components" not in sys.modules:
    cc = types.ModuleType("custom_components")
    cc.__path__ = [str(ROOT / "custom_components")]
    sys.modules["custom_components"] = cc
if "custom_components.babymonitor" not in sys.modules:
    bm = types.ModuleType("custom_components.babymonitor")
    bm.__path__ = [str(PKG_PATH)]
    sys.modules["custom_components.babymonitor"] = bm

from custom_components.babymonitor.protocol.bmp_decode import (  # noqa: E402
    _matrix_solve,
    format_cert_colon_upper,
    strhash,
)
from custom_components.babymonitor.protocol.crypto import (  # noqa: E402
    APP_PACKAGE_NAME,
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    assemble_master_key_g,
    canonical_string,
    compute_ch_key,
    decrypt_et3_result,
    encrypt_et3_post_data,
    generate_phone_util_device_id,
    pack_frame_55aa,
    post_data_digest_hex,
    sign_atop_request,
    sign_tuya_request,
    swap_sign_string,
    unpack_frame_55aa,
)
from custom_components.babymonitor.protocol.lan import LocalStunServer  # noqa: E402


class TestCrypto(unittest.TestCase):
    """Test cryptographic primitives and framing."""

    def test_frame_55aa_roundtrip(self) -> None:
        payload = b'{"dps":{"101":true}}'
        frame = pack_frame_55aa(seq=42, cmd=0x07, payload=payload)
        seq, cmd, unpacked, consumed = unpack_frame_55aa(frame)
        self.assertEqual(seq, 42)
        self.assertEqual(cmd, 0x07)
        self.assertEqual(unpacked, payload)
        self.assertEqual(consumed, len(frame))

    def test_aes_ecb_roundtrip(self) -> None:
        key = b"0123456789abcdef"
        pt = b"hello tuya lan!"
        ct = aes_ecb_encrypt(key, pt)
        self.assertEqual(aes_ecb_decrypt(key, ct), pt)

    def test_aes_gcm_roundtrip(self) -> None:
        key = b"0123456789abcdef"
        iv = b"123456789012"
        pt = b"secret gcm payload"
        ct, tag = aes_gcm_encrypt(key, iv, pt, aad=b"aad")
        self.assertEqual(aes_gcm_decrypt(key, iv, ct, tag, aad=b"aad"), pt)

    def test_sign_tuya_request(self) -> None:
        sig = sign_tuya_request({"a": "tuya.m.user.token.get", "v": "1.0"}, "mysecret")
        self.assertEqual(len(sig), 32)
        self.assertEqual(
            sig,
            sign_tuya_request({"v": "1.0", "a": "tuya.m.user.token.get"}, "mysecret"),
        )

    def test_atop_signing_and_et3_roundtrip(self) -> None:
        digest = bytes(range(32))
        cert_upper = format_cert_colon_upper(digest)
        self.assertEqual(len(cert_upper), 95)

        bmp_token = "cd" * 32
        g = assemble_master_key_g(
            APP_PACKAGE_NAME, cert_upper, bmp_token, "SYNTH_SECRET"
        )
        self.assertEqual(len(g), len(APP_PACKAGE_NAME) + 1 + 95 + 1 + 32 + 1 + 12)

        ch_key = compute_ch_key("SYNTH_APPKEY", APP_PACKAGE_NAME, cert_upper)
        self.assertEqual(len(ch_key), 8)

        req_id = "11111111-2222-4333-8444-555555555555"
        pd_json = json.dumps({"gid": 12345}, separators=(",", ":"))
        enc_b64 = encrypt_et3_post_data(req_id, g, pd_json, ecode="SYNTH_ECODE")
        dec_bytes = decrypt_et3_result(req_id, g, enc_b64, ecode="SYNTH_ECODE")
        self.assertEqual(dec_bytes.decode("utf-8"), pd_json)

        params = {
            "a": "m.life.my.group.device.list",
            "v": "2.2",
            "time": "1700000000",
            "requestId": req_id,
            "postData": post_data_digest_hex(enc_b64.encode("utf-8")),
            "notWhitelisted": "ignored",
        }
        str2 = canonical_string(params)
        self.assertNotIn("notWhitelisted", str2)
        sig = sign_atop_request(params, g)
        self.assertEqual(len(sig), 64)

    def test_swap_sign_string_and_device_id(self) -> None:
        s = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"
        self.assertEqual(swap_sign_string(s), "BBBBBBBBAAAAAAAADDDDDDDDCCCCCCCC")
        dev_id = generate_phone_util_device_id(
            "google", "Pixel 8 Pro", b"\x11" * 32, b"\x22" * 32
        )
        self.assertEqual(len(dev_id), 44)

    def test_bmp_vandermonde_solve(self) -> None:
        # Constant polynomial b = 0x1234 -> 1x1 Vandermonde [1 | 0x1234]
        solved = _matrix_solve([("05", "1234")])
        self.assertEqual(solved, bytes.fromhex("1234"))
        self.assertGreater(strhash(b"SYNTH_APPKEY"), 0)


class TestLocalStunServer(unittest.IsolatedAsyncioTestCase):
    """Test local STUN server lifecycle."""

    async def test_stun_start_stop(self) -> None:
        server = LocalStunServer(host="127.0.0.1", port=0)
        port = await server.start()
        self.assertGreater(port, 0)
        server.stop()


if __name__ == "__main__":
    unittest.main()
