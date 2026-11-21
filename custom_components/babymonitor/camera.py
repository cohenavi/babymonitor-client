"""Camera platform for Philips Avent Baby Monitor+."""

from __future__ import annotations

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import BabyMonitorCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Baby Monitor+ camera entity."""
    coordinator: BabyMonitorCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BabyMonitorCamera(coordinator, entry)])


class BabyMonitorCamera(CoordinatorEntity[BabyMonitorCoordinator], Camera):
    """Representation of a Philips Avent Baby Monitor+ camera."""

    _attr_has_entity_name = True
    _attr_name = "Camera"
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(
        self, coordinator: BabyMonitorCoordinator, entry: ConfigEntry
    ) -> None:
        CoordinatorEntity.__init__(self, coordinator)
        Camera.__init__(self)
        self._attr_unique_id = f"{entry.entry_id}_camera"

    async def stream_source(self) -> str | None:
        """Return the local HTTP MPEG-TS stream URL."""
        if self.coordinator.stream_server.port:
            return self.coordinator.stream_server.stream_url
        return None

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a JPEG snapshot from the latest H.264 frame."""
        return await self.coordinator.stream_server.get_snapshot()
