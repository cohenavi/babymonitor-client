"""DataUpdateCoordinator for the Philips Avent Baby Monitor+ integration."""

from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    CONF_DEVICE_ID,
    CONF_HOST,
    CONF_LOCAL_KEY,
    CONF_MODE,
    CONF_PORT,
    CONF_PROTOCOL_VERSION,
    DEFAULT_LAN_PORT,
    DEFAULT_PROTOCOL_VERSION,
    DOMAIN,
    MODE_LAN,
)
from .protocol.lan import LocalStunServer, TuyaLanClient
from .protocol.media import LocalStreamServer

_LOGGER = logging.getLogger(__name__)


class BabyMonitorCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinates Baby Monitor+ connection, DPs, and media streaming."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{entry.entry_id}",
            update_interval=timedelta(seconds=30),
        )
        self.entry = entry
        self.mode: str = entry.data.get(CONF_MODE, MODE_LAN)
        self.device_id: str = entry.data.get(CONF_DEVICE_ID, "")
        self.dps: dict[str, Any] = {}

        self.lan_client: TuyaLanClient | None = None
        if self.mode == MODE_LAN and entry.data.get(CONF_HOST):
            self.lan_client = TuyaLanClient(
                host=entry.data[CONF_HOST],
                device_id=self.device_id,
                local_key=entry.data.get(CONF_LOCAL_KEY, ""),
                port=entry.data.get(CONF_PORT, DEFAULT_LAN_PORT),
                version=entry.data.get(CONF_PROTOCOL_VERSION, DEFAULT_PROTOCOL_VERSION),
            )
            self.lan_client.on_dp_update(self._handle_dp_update)

        self.stun_server = LocalStunServer()
        self.stream_server = LocalStreamServer()

    async def async_setup(self) -> None:
        """Start local STUN/stream servers and connect to the camera."""
        await self.stun_server.start()
        await self.stream_server.start()
        if self.lan_client is not None:
            try:
                await self.lan_client.connect()
                await self.lan_client.query_dps()
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("Initial LAN connection failed (will retry): %s", err)

    async def async_shutdown(self) -> None:
        """Clean up connections and local servers."""
        if self.lan_client is not None:
            await self.lan_client.disconnect()
        await self.stream_server.stop()
        self.stun_server.stop()

    async def _handle_dp_update(self, new_dps: dict[str, Any]) -> None:
        self.dps.update(new_dps)
        self.async_set_updated_data(dict(self.dps))

    async def async_set_dp(self, dp_id: str, value: Any) -> None:
        """Send a DP update to the camera."""
        if self.lan_client is not None and self.lan_client.connected:
            await self.lan_client.set_dp(dp_id, value)
        self.dps[dp_id] = value
        self.async_set_updated_data(dict(self.dps))

    async def _async_update_data(self) -> dict[str, Any]:
        if self.lan_client is not None:
            if not self.lan_client.connected:
                try:
                    await self.lan_client.connect()
                except Exception as err:  # noqa: BLE001
                    _LOGGER.debug("LAN reconnect failed: %s", err)
                    return dict(self.dps)
            try:
                await self.lan_client.query_dps()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("DP query failed: %s", err)
        return dict(self.dps)
