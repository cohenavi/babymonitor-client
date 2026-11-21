"""Unit tests for the Baby Monitor+ pure Python protocol layer."""

from __future__ import annotations

import asyncio
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

from custom_components.babymonitor.protocol.crypto import (  # noqa: E402
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    pack_frame_55aa,
    sign_tuya_request,
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


class TestLocalStunServer(unittest.IsolatedAsyncioTestCase):
    """Test local STUN server lifecycle."""

    async def test_stun_start_stop(self) -> None:
        server = LocalStunServer(host="127.0.0.1", port=0)
        port = await server.start()
        self.assertGreater(port, 0)
        server.stop()


if __name__ == "__main__":
    unittest.main()
