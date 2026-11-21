"""Light platform for Philips Avent Baby Monitor+ (Night Light)."""

from __future__ import annotations

from typing import Any

from homeassistant.components.light import ColorMode, LightEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, DP_NIGHT_LIGHT
from .coordinator import BabyMonitorCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Baby Monitor+ night light."""
    coordinator: BabyMonitorCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BabyMonitorNightLight(coordinator, entry)])


class BabyMonitorNightLight(CoordinatorEntity[BabyMonitorCoordinator], LightEntity):
    """Night light entity backed by Tuya DP."""

    _attr_has_entity_name = True
    _attr_name = "Night Light"
    _attr_color_mode = ColorMode.ONOFF
    _attr_supported_color_modes = {ColorMode.ONOFF}

    def __init__(
        self, coordinator: BabyMonitorCoordinator, entry: ConfigEntry
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_night_light"

    @property
    def is_on(self) -> bool:
        return bool(self.coordinator.dps.get(DP_NIGHT_LIGHT, False))

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_set_dp(DP_NIGHT_LIGHT, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_set_dp(DP_NIGHT_LIGHT, False)
