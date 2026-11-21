"""Config flow for Philips Avent Baby Monitor+ with automatic localKey extraction."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_APK_PATH,
    CONF_APP_KEY,
    CONF_APP_SECRET,
    CONF_APP_VERSION,
    CONF_BMP_TOKEN,
    CONF_CERT_SHA256,
    CONF_COUNTRY_CODE,
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
    CONF_SESSION_DATA,
    DEFAULT_APP_VERSION,
    DEFAULT_COUNTRY_CODE,
    DEFAULT_LAN_PORT,
    DEFAULT_PROTOCOL_VERSION,
    DEFAULT_REGION,
    DOMAIN,
    MODE_AUTO_KEY,
    MODE_CLOUD,
    MODE_LAN,
    TUYA_REGIONS,
)
from .protocol.cloud import AppSigningConfig, CloudDevice, MfaRequiredError, TuyaCloudClient
from .protocol.lan import discover_lan_devices

_LOGGER = logging.getLogger(__name__)


class BabyMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Philips Avent Baby Monitor+."""

    VERSION = 1

    def __init__(self) -> None:
        self._mode: str = MODE_AUTO_KEY
        self._cloud_client: TuyaCloudClient | None = None
        self._cloud_inputs: dict[str, Any] = {}
        self._extracted_devices: list[CloudDevice] = []

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step: choose automatic key extraction, manual LAN, or Cloud mode."""
        if user_input is not None:
            self._mode = user_input[CONF_MODE]
            if self._mode == MODE_LAN:
                return await self.async_step_lan()
            return await self.async_step_cloud()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_MODE, default=MODE_AUTO_KEY): vol.In(
                        {
                            MODE_AUTO_KEY: "LAN-only with Automatic Local Key Extraction (Recommended)",
                            MODE_LAN: "LAN-only with Manual Local Key (TCP 6668, no cloud)",
                            MODE_CLOUD: "Cloud MQTT (Tuya account + email MFA)",
                        }
                    )
                }
            ),
        )

    async def async_step_lan(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Configure LAN-only connection with a known/extracted localKey."""
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
        default_key = ""

        # If we came from automatic key extraction, pre-fill the extracted device_id and local_key
        if self._extracted_devices:
            cam = self._extracted_devices[0]
            default_id = cam.device_id
            default_key = cam.local_key
            for d in discovered:
                if d.device_id == cam.device_id:
                    default_host = d.ip
                    break
            if not default_host and cam.ip:
                default_host = cam.ip

        return self.async_show_form(
            step_id="lan",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_HOST, default=default_host): str,
                    vol.Required(CONF_DEVICE_ID, default=default_id): str,
                    vol.Required(CONF_LOCAL_KEY, default=default_key): str,
                    vol.Optional(CONF_PORT, default=DEFAULT_LAN_PORT): int,
                    vol.Optional(
                        CONF_PROTOCOL_VERSION, default=DEFAULT_PROTOCOL_VERSION
                    ): vol.In(["3.3", "3.4", "3.5"]),
                }
            ),
            errors=errors,
        )

    def _build_signing_config(self, user_input: dict[str, Any]) -> AppSigningConfig:
        """Build AppSigningConfig from either an APK file path or explicit cert/bmp_token."""
        apk_path = user_input.get(CONF_APK_PATH, "").strip()
        app_key = user_input[CONF_APP_KEY].strip()
        app_secret = user_input[CONF_APP_SECRET].strip()
        app_version = user_input.get(CONF_APP_VERSION, DEFAULT_APP_VERSION).strip()

        if apk_path:
            return AppSigningConfig.from_apk(
                apk_path=apk_path,
                app_key=app_key,
                app_secret=app_secret,
                app_version=app_version,
            )

        cert_sha256 = user_input.get(CONF_CERT_SHA256, "").strip()
        bmp_token = user_input.get(CONF_BMP_TOKEN, "").strip()
        if not cert_sha256 or not bmp_token:
            raise ValueError(
                "Provide either APK Path (to auto-extract cert & t_s.bmp token) or both cert_sha256 and bmp_token."
            )
        return AppSigningConfig(
            app_key=app_key,
            app_secret=app_secret,
            cert_sha256_colon_upper=cert_sha256,
            bmp_token=bmp_token,
            app_version=app_version,
        )

    async def async_step_cloud(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Authenticate with Tuya Cloud to extract localKey or configure Cloud mode."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                signing_cfg = await self.hass.async_add_executor_job(
                    self._build_signing_config, user_input
                )
                session = async_get_clientsession(self.hass)
                self._cloud_client = TuyaCloudClient(
                    session=session,
                    signing_config=signing_cfg,
                    region=user_input.get(CONF_REGION, DEFAULT_REGION),
                    country_code=user_input.get(
                        CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE
                    ),
                )
                self._cloud_inputs = dict(user_input)
                await self._cloud_client.login_with_password(
                    email=user_input[CONF_EMAIL],
                    password=user_input[CONF_PASSWORD],
                    mfa_code=user_input.get(CONF_MFA_CODE, "").strip(),
                )
                return await self._finish_cloud_or_auto_key()
            except MfaRequiredError:
                return await self.async_step_mfa()
            except ValueError as err:
                _LOGGER.warning("Signing config error: %s", err)
                errors["base"] = "invalid_signing_config"
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("Tuya cloud authentication failed: %s", err)
                errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="cloud",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Required(CONF_REGION, default=DEFAULT_REGION): vol.In(
                        list(TUYA_REGIONS.keys())
                    ),
                    vol.Required(
                        CONF_COUNTRY_CODE, default=DEFAULT_COUNTRY_CODE
                    ): str,
                    vol.Required(CONF_APP_KEY): str,
                    vol.Required(CONF_APP_SECRET): str,
                    vol.Optional(CONF_APK_PATH, default=""): str,
                    vol.Optional(CONF_CERT_SHA256, default=""): str,
                    vol.Optional(CONF_BMP_TOKEN, default=""): str,
                    vol.Optional(
                        CONF_APP_VERSION, default=DEFAULT_APP_VERSION
                    ): str,
                    vol.Optional(CONF_MFA_CODE, default=""): str,
                }
            ),
            errors=errors,
        )

    async def async_step_mfa(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the 6-digit email MFA verification step."""
        errors: dict[str, str] = {}
        if user_input is not None and self._cloud_client is not None:
            try:
                await self._cloud_client.login_with_password(
                    email=self._cloud_inputs[CONF_EMAIL],
                    password=self._cloud_inputs[CONF_PASSWORD],
                    mfa_code=user_input[CONF_MFA_CODE].strip(),
                )
                return await self._finish_cloud_or_auto_key()
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("MFA verification failed: %s", err)
                errors["base"] = "invalid_mfa"

        return self.async_show_form(
            step_id="mfa",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_MFA_CODE): str,
                }
            ),
            errors=errors,
        )

    async def _finish_cloud_or_auto_key(self) -> FlowResult:
        """Fetch device list (with localKey) after successful cloud login."""
        assert self._cloud_client is not None
        self._extracted_devices = await self._cloud_client.list_devices()

        if self._mode == MODE_AUTO_KEY:
            # Transition to LAN step with device_id and local_key pre-filled!
            return await self.async_step_lan()

        # Cloud mode: store extracted device + cloud session
        dev_id = (
            self._extracted_devices[0].device_id
            if self._extracted_devices
            else f"cloud_{self._cloud_inputs[CONF_EMAIL]}"
        )
        local_key = (
            self._extracted_devices[0].local_key
            if self._extracted_devices
            else ""
        )
        await self.async_set_unique_id(dev_id)
        self._abort_if_unique_id_configured()

        cs = self._cloud_client.cloud_session
        return self.async_create_entry(
            title=f"Baby Monitor Cloud ({self._cloud_inputs[CONF_EMAIL]})",
            data={
                CONF_MODE: MODE_CLOUD,
                CONF_DEVICE_ID: dev_id,
                CONF_LOCAL_KEY: local_key,
                CONF_EMAIL: self._cloud_inputs[CONF_EMAIL],
                CONF_REGION: self._cloud_inputs.get(CONF_REGION, DEFAULT_REGION),
                CONF_SESSION_DATA: {
                    "sid": cs.sid if cs else "",
                    "uid": cs.uid if cs else "",
                    "ecode": cs.ecode if cs else "",
                    "mobile_api_url": cs.mobile_api_url if cs else "",
                },
            },
        )
