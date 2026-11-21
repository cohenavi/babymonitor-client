"""Tuya LAN discovery, TCP 6668 signaling, DP control, and local STUN responder."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
import logging
import os
import struct
import time
from typing import Any, Callable, Coroutine

from .crypto import (
    UDP_DISCOVERY_KEY,
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    pack_frame_55aa,
    unpack_frame_55aa,
)
from ..const import (
    DEFAULT_DISCOVERY_PORT_ENC,
    DEFAULT_DISCOVERY_PORT_PLAIN,
    DEFAULT_LAN_PORT,
    STUN_MAGIC_COOKIE,
)

_LOGGER = logging.getLogger(__name__)

# Tuya LAN Command IDs
CMD_DP_QUERY = 0x0A
CMD_CONTROL = 0x07
CMD_CONTROL_NEW = 0x0D
CMD_HEARTBEAT = 0x09
CMD_SESS_KEY_NEG_START = 0x03
CMD_SESS_KEY_NEG_RESP = 0x04
CMD_SESS_KEY_NEG_FINISH = 0x05
CMD_IPC_LAN_302 = 0x20  # Frame type 32


@dataclass
class DiscoveredDevice:
    """Represents a Tuya device discovered on the LAN."""

    device_id: str
    ip: str
    version: str
    product_key: str = ""


class _DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, devices: dict[str, DiscoveredDevice], encrypted: bool) -> None:
        self._devices = devices
        self._encrypted = encrypted

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            _, _, payload, _ = unpack_frame_55aa(data)
            if self._encrypted:
                payload = aes_ecb_decrypt(UDP_DISCOVERY_KEY, payload)
            info = json.loads(payload.decode("utf-8"))
            dev_id = info.get("gwId") or info.get("devId")
            if dev_id:
                self._devices[dev_id] = DiscoveredDevice(
                    device_id=dev_id,
                    ip=info.get("ip", addr[0]),
                    version=str(info.get("version", "3.4")),
                    product_key=info.get("productKey", ""),
                )
        except Exception:  # noqa: BLE001
            pass


async def discover_lan_devices(timeout: float = 3.0) -> list[DiscoveredDevice]:
    """Listen for Tuya UDP broadcast packets on ports 6666 and 6667."""
    loop = asyncio.get_running_loop()
    devices: dict[str, DiscoveredDevice] = {}
    transports: list[asyncio.DatagramTransport] = []

    for port, encrypted in (
        (DEFAULT_DISCOVERY_PORT_PLAIN, False),
        (DEFAULT_DISCOVERY_PORT_ENC, True),
    ):
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda enc=encrypted: _DiscoveryProtocol(devices, enc),
                local_addr=("0.0.0.0", port),
                allow_broadcast=True,
            )
            transports.append(transport)
        except OSError as err:
            _LOGGER.debug("Could not bind UDP discovery port %s: %s", port, err)

    try:
        await asyncio.sleep(timeout)
    finally:
        for transport in transports:
            transport.close()

    return list(devices.values())


class _StunProtocol(asyncio.DatagramProtocol):
    """Minimal RFC 5389 STUN Binding responder for local ICE."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < 20 or self.transport is None:
            return
        msg_type, _msg_len, magic = struct.unpack(">HHI", data[:8])
        tx_id = data[8:20]
        if msg_type != 0x0001 or magic != STUN_MAGIC_COOKIE:
            return

        # Build XOR-MAPPED-ADDRESS (0x0020)
        ip_parts = [int(x) for x in addr[0].split(".")]
        ip_int = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]
        xport = addr[1] ^ (STUN_MAGIC_COOKIE >> 16)
        xip = ip_int ^ STUN_MAGIC_COOKIE
        attr = struct.pack(">HHBBHI", 0x0020, 8, 0, 0x01, xport, xip)
        header = struct.pack(">HHI", 0x0101, len(attr), STUN_MAGIC_COOKIE) + tx_id
        self.transport.sendto(header + attr, addr)


class LocalStunServer:
    """Local STUN server so the camera can gather its LAN host candidate."""

    def __init__(self, host: str = "0.0.0.0", port: int = 0) -> None:
        self._host = host
        self._port = port
        self._transport: asyncio.DatagramTransport | None = None
        self.bound_port: int = 0

    async def start(self) -> int:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            _StunProtocol,
            local_addr=(self._host, self._port),
        )
        self._transport = transport
        sock = transport.get_extra_info("socket")
        self.bound_port = sock.getsockname()[1]
        return self.bound_port

    def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None


class TuyaLanClient:
    """Async Tuya LAN TCP 6668 client for DPs and IPC_LAN_302 signaling."""

    def __init__(
        self,
        host: str,
        device_id: str,
        local_key: str,
        port: int = DEFAULT_LAN_PORT,
        version: str = "3.4",
    ) -> None:
        self.host = host
        self.device_id = device_id
        self.local_key = local_key.encode("utf-8")[:16]
        self.port = port
        self.version = version

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._seq = 0
        self._session_key: bytes = self.local_key
        self._read_task: asyncio.Task[None] | None = None
        self._dp_callbacks: list[Callable[[dict[str, Any]], Coroutine[Any, Any, None]]] = []
        self._sig_callbacks: list[Callable[[dict[str, Any]], Coroutine[Any, Any, None]]] = []
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    def on_dp_update(self, cb: Callable[[dict[str, Any]], Coroutine[Any, Any, None]]) -> None:
        self._dp_callbacks.append(cb)

    def on_signaling(self, cb: Callable[[dict[str, Any]], Coroutine[Any, Any, None]]) -> None:
        self._sig_callbacks.append(cb)

    async def connect(self) -> None:
        """Connect to the camera on TCP 6668 and negotiate session if needed."""
        self._reader, self._writer = await asyncio.open_connection(self.host, self.port)
        self._connected = True
        if self.version.startswith("3.4"):
            await self._negotiate_v34()
        self._read_task = asyncio.create_task(self._read_loop())

    async def disconnect(self) -> None:
        """Close the TCP connection."""
        self._connected = False
        if self._read_task is not None:
            self._read_task.cancel()
            self._read_task = None
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._writer = None

    async def _negotiate_v34(self) -> None:
        """Perform Tuya v3.4 session key negotiation."""
        assert self._reader is not None and self._writer is not None
        local_nonce = os.urandom(16)
        self._seq += 1
        frame = pack_frame_55aa(self._seq, CMD_SESS_KEY_NEG_START, local_nonce)
        self._writer.write(frame)
        await self._writer.drain()

        data = await asyncio.wait_for(self._reader.read(4096), timeout=5.0)
        _, cmd, payload, _ = unpack_frame_55aa(data)
        if cmd != CMD_SESS_KEY_NEG_RESP:
            raise ConnectionError(f"Expected SESS_KEY_NEG_RESP, got {cmd:#x}")

        decrypted = aes_ecb_decrypt(self.local_key, payload)
        remote_nonce = decrypted[:16]
        expected_hmac = hmac.new(self.local_key, local_nonce, hashlib.sha256).digest()
        if len(decrypted) >= 48 and not hmac.compare_digest(decrypted[16:48], expected_hmac):
            raise ConnectionError("v3.4 session negotiation HMAC mismatch")

        self._seq += 1
        finish_hmac = hmac.new(self.local_key, remote_nonce, hashlib.sha256).digest()
        self._writer.write(pack_frame_55aa(self._seq, CMD_SESS_KEY_NEG_FINISH, finish_hmac))
        await self._writer.drain()

        xor_nonce = bytes(a ^ b for a, b in zip(local_nonce, remote_nonce))
        self._session_key = aes_ecb_encrypt(self.local_key, xor_nonce)[:16]

    async def _send_encrypted(self, cmd: int, payload_dict: dict[str, Any]) -> None:
        if self._writer is None:
            raise ConnectionError("Not connected")
        self._seq += 1
        raw = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
        encrypted = aes_ecb_encrypt(self._session_key, raw)
        self._writer.write(pack_frame_55aa(self._seq, cmd, encrypted))
        await self._writer.drain()

    async def query_dps(self) -> None:
        """Request current Data Points from the camera."""
        await self._send_encrypted(
            CMD_DP_QUERY,
            {"gwId": self.device_id, "devId": self.device_id, "t": int(time.time())},
        )

    async def set_dp(self, dp_id: str, value: Any) -> None:
        """Set a Data Point on the camera."""
        await self._send_encrypted(
            CMD_CONTROL_NEW,
            {
                "devId": self.device_id,
                "uid": "",
                "t": str(int(time.time())),
                "dps": {dp_id: value},
            },
        )

    async def send_302_signaling(self, message: dict[str, Any]) -> None:
        """Send an IPC_LAN_302 (frame type 32) WebRTC signaling envelope."""
        await self._send_encrypted(CMD_IPC_LAN_302, message)

    async def _read_loop(self) -> None:
        assert self._reader is not None
        buf = b""
        while self._connected:
            try:
                chunk = await self._reader.read(4096)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 20:
                    try:
                        _, cmd, payload, consumed = unpack_frame_55aa(buf)
                        buf = buf[consumed:]
                    except ValueError:
                        break
                    await self._handle_frame(cmd, payload)
            except asyncio.CancelledError:
                break
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("LAN read loop error: %s", err)
                break
        self._connected = False

    async def _handle_frame(self, cmd: int, payload: bytes) -> None:
        if cmd == CMD_HEARTBEAT:
            return
        try:
            decrypted = aes_ecb_decrypt(self._session_key, payload)
            data = json.loads(decrypted.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return

        if cmd == CMD_IPC_LAN_302:
            for cb in self._sig_callbacks:
                await cb(data)
        elif "dps" in data:
            for cb in self._dp_callbacks:
                await cb(data["dps"])
