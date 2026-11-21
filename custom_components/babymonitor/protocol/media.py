"""Local MPEG-TS HTTP stream server and JPEG snapshot extractor."""

from __future__ import annotations

import asyncio
import io
import logging
from typing import Set

from aiohttp import web

_LOGGER = logging.getLogger(__name__)


class LocalStreamServer:
    """Serves live MPEG-TS bytes over local HTTP for Home Assistant's stream_source()."""

    def __init__(self) -> None:
        self._app = web.Application()
        self._app.router.add_get("/stream.ts", self._handle_stream)
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._clients: Set[asyncio.Queue[bytes]] = set()
        self._latest_h264_frame: bytes | None = None
        self._latest_jpeg: bytes | None = None
        self.port: int = 0

    @property
    def stream_url(self) -> str:
        """Return the local HTTP MPEG-TS URL."""
        return f"http://127.0.0.1:{self.port}/stream.ts"

    async def start(self) -> int:
        """Start the local HTTP server on an ephemeral port."""
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await self._site.start()
        sockets = self._site._server.sockets  # type: ignore[union-attr]
        self.port = sockets[0].getsockname()[1]
        _LOGGER.debug("Local MPEG-TS stream server listening on %s", self.stream_url)
        return self.port

    async def stop(self) -> None:
        """Stop the local HTTP server."""
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
        self._clients.clear()

    def push_ts_chunk(self, chunk: bytes) -> None:
        """Broadcast an MPEG-TS chunk to all connected HTTP clients."""
        for queue in list(self._clients):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(chunk)

    def update_h264_frame(self, nal_unit: bytes) -> None:
        """Store the latest H.264 frame for on-demand JPEG snapshot decoding."""
        self._latest_h264_frame = nal_unit
        self._latest_jpeg = None

    async def get_snapshot(self) -> bytes | None:
        """Decode the latest H.264 frame to JPEG using PyAV if available."""
        if self._latest_jpeg is not None:
            return self._latest_jpeg
        if self._latest_h264_frame is None:
            return None

        try:
            import av  # type: ignore[import-not-found]

            codec = av.CodecContext.create("h264", "r")
            packets = codec.parse(self._latest_h264_frame)
            for packet in packets:
                frames = codec.decode(packet)
                for frame in frames:
                    img = frame.to_image()
                    buf = io.BytesIO()
                    img.save(buf, format="JPEG", quality=85)
                    self._latest_jpeg = buf.getvalue()
                    return self._latest_jpeg
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Snapshot decode failed: %s", err)
        return None

    async def _handle_stream(self, request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": "video/mp2t",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
        await response.prepare(request)
        queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=64)
        self._clients.add(queue)
        try:
            while True:
                chunk = await queue.get()
                await response.write(chunk)
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        finally:
            self._clients.discard(queue)
        return response
