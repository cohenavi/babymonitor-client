"""Sensor platform for Philips Avent Baby Monitor+."""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
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
    """Set up Baby Monitor+ sensors."""
    coordinator: BabyMonitorCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BabyMonitorModeSensor(coordinator, entry)])


class BabyMonitorModeSensor(CoordinatorEntity[BabyMonitorCoordinator], SensorEntity):
    """Reports the active connection mode (LAN or Cloud)."""

    _attr_has_entity_name = True
    _attr_name = "Connection Mode"

    def __init__(
        self, coordinator: BabyMonitorCoordinator, entry: ConfigEntry
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_connection_mode"

    @property
    def native_value(self) -> str:
        return self.coordinator.mode
