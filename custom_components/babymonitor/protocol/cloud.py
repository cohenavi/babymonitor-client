"""Tuya Cloud mobile-app (ATOP ET=3) authentication and automatic localKey extractor."""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from pathlib import Path
import time
from typing import Any, Optional
import uuid

import aiohttp

from .bmp_decode import extract_apk_signing_secrets
from .crypto import (
    APP_PACKAGE_NAME,
    assemble_master_key_g,
    compute_ch_key,
    decrypt_et3_result,
    encrypt_et3_post_data,
    generate_phone_util_device_id,
    post_data_digest_hex,
    rsa_encrypt_password,
    sign_atop_request,
)
from ..const import TUYA_REGIONS

_LOGGER = logging.getLogger(__name__)

THING_SDK_VERSION = "6.7.0"
APP_RN_VERSION = "5.92"
TTID_CHANNEL_FINGERPRINT = "international"


class MfaRequiredError(Exception):
    """Raised when the Tuya cloud login requires an emailed MFA verification code."""


@dataclass
class AppSigningConfig:
    """Holds the static APK signing material needed for ATOP ET=3 requests."""

    app_key: str
    app_secret: str
    cert_sha256_colon_upper: str
    bmp_token: str
    app_version: str = "1.9.0"
    device_id: str = ""

    def __post_init__(self) -> None:
        if not self.device_id:
            self.device_id = generate_phone_util_device_id()

    @classmethod
    def from_apk(
        cls,
        apk_path: str | Path,
        app_key: str,
        app_secret: str,
        app_version: str = "1.9.0",
    ) -> AppSigningConfig:
        """Extract cert_sha256 and bmp_token directly from the APK file."""
        cert_colon_upper, bmp_token = extract_apk_signing_secrets(apk_path, app_key)
        return cls(
            app_key=app_key,
            app_secret=app_secret,
            cert_sha256_colon_upper=cert_colon_upper,
            bmp_token=bmp_token,
            app_version=app_version,
        )

    @property
    def master_key_g(self) -> bytes:
        return assemble_master_key_g(
            APP_PACKAGE_NAME,
            self.cert_sha256_colon_upper,
            self.bmp_token,
            self.app_secret,
        )

    @property
    def ch_key(self) -> str:
        return compute_ch_key(
            self.app_key,
            APP_PACKAGE_NAME,
            self.cert_sha256_colon_upper,
        )


@dataclass
class CloudSession:
    """Authenticated Tuya cloud session."""

    region: str
    sid: str
    uid: str
    ecode: str
    mobile_api_url: str
    expire_time: int


@dataclass
class CloudDevice:
    """Device metadata (including local_key) returned by Tuya cloud."""

    device_id: str
    name: str
    local_key: str
    product_id: str
    ip: str = ""
    online: bool = False
    p2p_type: int = 4


def _rewrite_action(action: str) -> str:
    if action.startswith("thing"):
        return "smartlife" + action[5:]
    return action


def _build_login_options(mfa_code: str) -> str:
    return f'{{"group": 1,"mfaCode": "{mfa_code}"}}'


class TuyaCloudClient:
    """Async client for Tuya mobile-app ATOP ET=3 API and automatic localKey discovery."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        signing_config: AppSigningConfig,
        region: str = "eu",
        country_code: str = "45",
    ) -> None:
        self._http = session
        self.cfg = signing_config
        self.region = region
        self.country_code = country_code
        self.endpoint = TUYA_REGIONS.get(region, TUYA_REGIONS["eu"])
        self.cloud_session: Optional[CloudSession] = None

    def _assemble_envelope(
        self,
        wire_action: str,
        version: str,
        request_id: str,
        now_s: int,
        sid: str = "",
    ) -> dict[str, str]:
        env: dict[str, str] = {
            "a": wire_action,
            "v": version,
            "time": str(now_s),
            "requestId": request_id,
            "et": "3",
            "lang": "en",
            "os": "Android",
            "appVersion": self.cfg.app_version,
            "ttid": f"sdk_{TTID_CHANNEL_FINGERPRINT}@{self.cfg.app_key}",
            "clientId": self.cfg.app_key,
            "deviceId": self.cfg.device_id,
            "chKey": self.cfg.ch_key,
            "sdkVersion": THING_SDK_VERSION,
            "deviceCoreVersion": THING_SDK_VERSION,
            "channel": "oem",
            "nd": "1",
            "osSystem": "16",
            "platform": "Pixel 8 Pro",
            "timeZoneId": "UTC",
            "cp": "gzip",
            "appRnVersion": APP_RN_VERSION,
            "bizData": json.dumps(
                {
                    "customDomainSupport": "1",
                    "nd": "1",
                    "sdkInt": "36",
                    "brand": "google",
                },
                separators=(",", ":"),
            ),
        }
        if sid:
            env["sid"] = sid
        return env

    async def _send_atop(
        self,
        action: str,
        version: str,
        post_data_str: Optional[str] = None,
        sid: str = "",
        ecode: Optional[str] = None,
    ) -> dict[str, Any]:
        wire_action = _rewrite_action(action)
        now_s = int(time.time())
        request_id = str(uuid.uuid4())
        g = self.cfg.master_key_g

        envelope = self._assemble_envelope(wire_action, version, request_id, now_s, sid)
        sign_params = dict(envelope)

        form_data: dict[str, str] = {}
        if post_data_str is not None:
            wire_post_data = encrypt_et3_post_data(request_id, g, post_data_str, ecode)
            sign_params["postData"] = post_data_digest_hex(
                wire_post_data.encode("utf-8")
            )
            form_data["postData"] = wire_post_data

        envelope["sign"] = sign_atop_request(sign_params, g)
        form_data.update(envelope)

        headers = {
            "User-Agent": f"Thing-UA=APP/Android/{self.cfg.app_version}/SDK/{THING_SDK_VERSION}",
            "x-client-trace-id": request_id,
        }
        async with self._http.post(
            self.endpoint, data=form_data, headers=headers
        ) as resp:
            resp.raise_for_status()
            outer = await resp.json(content_type=None)

        if "success" in outer or "errorCode" in outer:
            inner = outer
        elif isinstance(outer.get("result"), str):
            decrypted = decrypt_et3_result(request_id, g, outer["result"], ecode)
            inner = json.loads(decrypted.decode("utf-8"))
        else:
            inner = outer

        return inner

    async def _token_get(self, email: str) -> dict[str, str]:
        post_data = json.dumps(
            {
                "countryCode": self.country_code,
                "username": email,
                "isUid": False,
            },
            separators=(",", ":"),
        )
        res = await self._send_atop("thing.m.user.username.token.get", "2.0", post_data)
        if not res.get("success", False):
            raise RuntimeError(
                f"token.get failed: {res.get('errorCode')} - {res.get('errorMsg')}"
            )
        result = res.get("result") or {}
        return {
            "publicKey": str(result.get("publicKey", "")),
            "exponent": str(result.get("exponent", "65537")),
            "token": str(result.get("token", "")),
        }

    async def trigger_mfa_email(self, email: str, password: str) -> None:
        """Run graphic-captcha precheck + fresh token.get + mfa.code.get to email MFA code."""
        await self._send_atop(
            "m.life.app.property.graphic.verification.code.get",
            "1.0",
            post_data_str=None,
        )
        tk = await self._token_get(email)
        enc_pw = rsa_encrypt_password(tk["publicKey"], tk["exponent"], password)
        post_data = json.dumps(
            {
                "countryCode": self.country_code,
                "username": email,
                "passwd": enc_pw,
                "token": tk["token"],
                "ifencrypt": 1,
                "options": _build_login_options("null"),
            },
            separators=(",", ":"),
        )
        res = await self._send_atop("thing.m.user.username.mfa.code.get", "1.0", post_data)
        if not res.get("success", False):
            raise RuntimeError(
                f"mfa.code.get failed: {res.get('errorCode')} - {res.get('errorMsg')}"
            )

    async def login_with_password(
        self,
        email: str,
        password: str,
        mfa_code: str = "",
    ) -> CloudSession:
        """Perform Tuya mobile-app ATOP ET=3 login.

        If mfa_code is empty and the server returns MFA_NEED_SEND_CODE, automatically
        triggers the MFA email and raises MfaRequiredError.
        """
        tk = await self._token_get(email)
        enc_pw = rsa_encrypt_password(tk["publicKey"], tk["exponent"], password)
        post_data = json.dumps(
            {
                "countryCode": self.country_code,
                "email": email,
                "passwd": enc_pw,
                "token": tk["token"],
                "ifencrypt": 1,
                "options": _build_login_options(mfa_code),
            },
            separators=(",", ":"),
        )
        res = await self._send_atop(
            "thing.m.user.email.password.login", "3.0", post_data
        )
        if not res.get("success", False):
            err_code = str(res.get("errorCode", "")).upper()
            if err_code == "MFA_NEED_SEND_CODE":
                await self.trigger_mfa_email(email, password)
                raise MfaRequiredError("Email MFA code required; code has been sent.")
            raise RuntimeError(
                f"password.login failed: {res.get('errorCode')} - {res.get('errorMsg')}"
            )

        user = res.get("result") or {}
        domain = user.get("domain") or {}
        mobile_api_url = domain.get("mobileApiUrl") or self.endpoint
        if not mobile_api_url.endswith("/api.json"):
            mobile_api_url = mobile_api_url.rstrip("/") + "/api.json"
        self.endpoint = mobile_api_url

        self.cloud_session = CloudSession(
            region=self.region,
            sid=str(user.get("sid", "")),
            uid=str(user.get("uid", "")),
            ecode=str(user.get("ecode", "")),
            mobile_api_url=mobile_api_url,
            expire_time=int(time.time()) + 43200,
        )
        return self.cloud_session

    async def list_devices(self) -> list[CloudDevice]:
        """Run the two-step ATOP discovery (home.space.list -> my.group.device.list)
        to extract all paired cameras and their `localKey`s.
        """
        if self.cloud_session is None:
            raise RuntimeError("Not logged in")

        sid = self.cloud_session.sid
        ecode = self.cloud_session.ecode

        # Step 1: m.life.home.space.list v1.0 (no postData)
        homes_res = await self._send_atop(
            "m.life.home.space.list",
            "1.0",
            post_data_str=None,
            sid=sid,
            ecode=ecode,
        )
        homes = homes_res.get("result")
        gids: list[int] = []
        if isinstance(homes, list):
            for h in homes:
                if isinstance(h, dict) and isinstance(h.get("gid"), int):
                    gids.append(h["gid"])

        # Step 2: m.life.my.group.device.list v2.2 per gid
        devices: list[CloudDevice] = []
        for gid in gids:
            pd = json.dumps({"gid": gid}, separators=(",", ":"))
            dev_res = await self._send_atop(
                "m.life.my.group.device.list",
                "2.2",
                post_data_str=pd,
                sid=sid,
                ecode=ecode,
            )
            raw_list = dev_res.get("result")
            if isinstance(raw_list, dict):
                raw_list = raw_list.get("deviceList", [])
            if not isinstance(raw_list, list):
                continue

            for item in raw_list:
                if not isinstance(item, dict):
                    continue
                skills = item.get("skills") or {}
                p2p_type = skills.get("p2pType") or item.get("p2pType")
                devices.append(
                    CloudDevice(
                        device_id=str(item.get("devId", "")),
                        name=str(item.get("name", "Baby Monitor+")),
                        local_key=str(item.get("localKey", "")),
                        product_id=str(item.get("productId", "")),
                        ip=str(item.get("ip", "")),
                        online=bool(item.get("isOnline", False)),
                        p2p_type=int(p2p_type) if p2p_type is not None else 4,
                    )
                )
        return devices
