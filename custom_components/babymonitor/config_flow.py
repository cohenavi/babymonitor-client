"""Config flow for Philips Avent Baby Monitor+."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_DEVICE_ID,
    CONF_EMAIL,
    CONF_HOST,
    CONF_LOCAL_KEY,
    CONF_MFA_CODE,
    CONF_MODE,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_PROTOCOL_VERSION,
    CONF_REGION,
    DEFAULT_LAN_PORT,
    DEFAULT_PROTOCOL_VERSION,
    DEFAULT_REGION,
    DOMAIN,
    MODE_CLOUD,
    MODE_LAN,
    TUYA_REGIONS,
)
from .protocol.lan import discover_lan_devices


class BabyMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Philips Avent Baby Monitor+."""

    VERSION = 1

    def __init__(self) -> None:
        self._mode: str = MODE_LAN

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step: choose LAN or Cloud mode."""
        if user_input is not None:
            self._mode = user_input[CONF_MODE]
            if self._mode == MODE_LAN:
                return await self.async_step_lan()
            return await self.async_step_cloud()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_MODE, default=MODE_LAN): vol.In(
                        {
                            MODE_LAN: "LAN-only (TCP 6668, no cloud)",
                            MODE_CLOUD: "Cloud MQTT (Tuya account + email MFA)",
                        }
                    )
                }
            ),
        )

    async def async_step_lan(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Configure LAN-only connection."""
        errors: dict[str, str] = {}
        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_DEVICE_ID])
            self._abort_if_unique_id_configured()
            return self.async_create_entry(
                title=f"Baby Monitor ({user_input[CONF_HOST]})",
                data={
                    CONF_MODE: MODE_LAN,
                    CONF_HOST: user_input[CONF_HOST],
                    CONF_PORT: user_input.get(CONF_PORT, DEFAULT_LAN_PORT),
                    CONF_DEVICE_ID: user_input[CONF_DEVICE_ID],
                    CONF_LOCAL_KEY: user_input[CONF_LOCAL_KEY],
                    CONF_PROTOCOL_VERSION: user_input.get(
                        CONF_PROTOCOL_VERSION, DEFAULT_PROTOCOL_VERSION
                    ),
                },
            )

        discovered = await discover_lan_devices(timeout=1.5)
        default_host = discovered[0].ip if discovered else ""
        default_id = discovered[0].device_id if discovered else ""

        return self.async_show_form(
            step_id="lan",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_HOST, default=default_host): str,
                    vol.Required(CONF_DEVICE_ID, default=default_id): str,
                    vol.Required(CONF_LOCAL_KEY): str,
                    vol.Optional(CONF_PORT, default=DEFAULT_LAN_PORT): int,
                    vol.Optional(
                        CONF_PROTOCOL_VERSION, default=DEFAULT_PROTOCOL_VERSION
                    ): vol.In(["3.3", "3.4", "3.5"]),
                }
            ),
            errors=errors,
        )

    async def async_step_cloud(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Configure Cloud MQTT connection."""
        errors: dict[str, str] = {}
        if user_input is not None:
            await self.async_set_unique_id(f"cloud_{user_input[CONF_EMAIL]}")
            self._abort_if_unique_id_configured()
            return self.async_create_entry(
                title=f"Baby Monitor Cloud ({user_input[CONF_EMAIL]})",
                data={
                    CONF_MODE: MODE_CLOUD,
                    CONF_EMAIL: user_input[CONF_EMAIL],
                    CONF_PASSWORD: user_input[CONF_PASSWORD],
                    CONF_REGION: user_input.get(CONF_REGION, DEFAULT_REGION),
                    CONF_MFA_CODE: user_input.get(CONF_MFA_CODE, ""),
                },
            )

        return self.async_show_form(
            step_id="cloud",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Required(CONF_REGION, default=DEFAULT_REGION): vol.In(
                        list(TUYA_REGIONS.keys())
                    ),
                    vol.Optional(CONF_MFA_CODE, default=""): str,
                }
            ),
            errors=errors,
        )
