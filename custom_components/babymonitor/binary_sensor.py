"""Binary sensor platform for Philips Avent Baby Monitor+."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, DP_CRY_DETECTION, DP_MOTION_DETECTION
from .coordinator import BabyMonitorCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Baby Monitor+ binary sensors."""
    coordinator: BabyMonitorCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            BabyMonitorConnectivitySensor(coordinator, entry),
            BabyMonitorDpBinarySensor(
                coordinator,
                entry,
                dp_id=DP_CRY_DETECTION,
                name="Cry Detected",
                key="cry_detected",
                device_class=BinarySensorDeviceClass.SOUND,
            ),
            BabyMonitorDpBinarySensor(
                coordinator,
                entry,
                dp_id=DP_MOTION_DETECTION,
                name="Motion Detected",
                key="motion_detected",
                device_class=BinarySensorDeviceClass.MOTION,
            ),
        ]
    )


class BabyMonitorConnectivitySensor(
    CoordinatorEntity[BabyMonitorCoordinator], BinarySensorEntity
):
    """Connectivity sensor for the camera."""

    _attr_has_entity_name = True
    _attr_name = "Connectivity"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(
        self, coordinator: BabyMonitorCoordinator, entry: ConfigEntry
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_connectivity"

    @property
    def is_on(self) -> bool:
        if self.coordinator.lan_client is not None:
            return self.coordinator.lan_client.connected
        return False


class BabyMonitorDpBinarySensor(
    CoordinatorEntity[BabyMonitorCoordinator], BinarySensorEntity
):
    """Binary sensor backed by a Tuya Data Point."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: BabyMonitorCoordinator,
        entry: ConfigEntry,
        dp_id: str,
        name: str,
        key: str,
        device_class: BinarySensorDeviceClass,
    ) -> None:
        super().__init__(coordinator)
        self._dp_id = dp_id
        self._attr_name = name
        self._attr_device_class = device_class
        self._attr_unique_id = f"{entry.entry_id}_{key}"

    @property
    def is_on(self) -> bool:
        return bool(self.coordinator.dps.get(self._dp_id, False))
