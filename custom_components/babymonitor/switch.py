"""Switch platform for Philips Avent Baby Monitor+ (Lullaby, Night Vision)."""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, DP_LULLABY, DP_NIGHT_VISION
from .coordinator import BabyMonitorCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Baby Monitor+ switches."""
    coordinator: BabyMonitorCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            BabyMonitorDpSwitch(coordinator, entry, DP_LULLABY, "Lullaby", "lullaby"),
            BabyMonitorDpSwitch(
                coordinator, entry, DP_NIGHT_VISION, "Night Vision", "night_vision"
            ),
        ]
    )


class BabyMonitorDpSwitch(CoordinatorEntity[BabyMonitorCoordinator], SwitchEntity):
    """Switch entity backed by a Tuya Data Point."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: BabyMonitorCoordinator,
        entry: ConfigEntry,
        dp_id: str,
        name: str,
        key: str,
    ) -> None:
        super().__init__(coordinator)
        self._dp_id = dp_id
        self._attr_name = name
        self._attr_unique_id = f"{entry.entry_id}_{key}"

    @property
    def is_on(self) -> bool:
        return bool(self.coordinator.dps.get(self._dp_id, False))

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_set_dp(self._dp_id, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_set_dp(self._dp_id, False)
