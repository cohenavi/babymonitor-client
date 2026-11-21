"""Tuya Cloud mobile-app authentication and MQTT 302 signaling fallback."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import logging
import time
from typing import Any

import aiohttp

from .crypto import sign_tuya_request
from ..const import TUYA_REGIONS

_LOGGER = logging.getLogger(__name__)


@dataclass
class CloudSession:
    """Authenticated Tuya cloud session."""

    region: str
    sid: str
    uid: str
    ecode: str
    expire_time: int


@dataclass
class CloudDevice:
    """Device metadata returned by Tuya cloud."""

    device_id: str
    name: str
    local_key: str
    product_id: str
    ip: str = ""
    online: bool = False


class TuyaCloudClient:
    """Async client for Tuya mobile-app API (token.get -> login -> email MFA)."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        region: str = "eu",
        client_id: str = "",
        secret: str = "",
    ) -> None:
        self._http = session
        self.region = region
        self.endpoint = TUYA_REGIONS.get(region, TUYA_REGIONS["eu"])
        self.client_id = client_id
        self.secret = secret
        self.cloud_session: CloudSession | None = None

    async def _api_call(
        self,
        action: str,
        post_data: dict[str, Any] | None = None,
        sid: str = "",
    ) -> dict[str, Any]:
        ts = str(int(time.time() * 1000))
        params: dict[str, str] = {
            "a": action,
            "clientId": self.client_id,
            "v": "1.0",
            "time": ts,
        }
        if sid:
            params["sid"] = sid
        if post_data is not None:
            params["postData"] = json.dumps(post_data, separators=(",", ":"))

        params["sign"] = sign_tuya_request(params, self.secret)
        async with self._http.post(self.endpoint, data=params) as resp:
            resp.raise_for_status()
            body = await resp.json(content_type=None)
            if not body.get("success", False):
                raise RuntimeError(
                    f"Tuya API {action} failed: {body.get('errorCode')} - {body.get('errorMsg')}"
                )
            return body.get("result", {})

    async def request_email_mfa(self, email: str, country_code: str = "1") -> None:
        """Request an email MFA verification code."""
        await self._api_call(
            "tuya.m.user.email.code.send",
            {"email": email, "countryCode": country_code, "type": 1},
        )

    async def login_with_password(
        self,
        email: str,
        password: str,
        country_code: str = "1",
        mfa_code: str | None = None,
    ) -> CloudSession:
        """Perform Tuya mobile-app login (with optional email MFA code)."""
        token_res = await self._api_call(
            "tuya.m.user.token.get",
            {"email": email, "countryCode": country_code},
        )
        token = token_res.get("token", "")
        pw_hash = hashlib.md5(password.encode("utf-8")).hexdigest()

        login_payload: dict[str, Any] = {
            "email": email,
            "countryCode": country_code,
            "passwd": pw_hash,
            "token": token,
        }
        if mfa_code:
            login_payload["code"] = mfa_code

        res = await self._api_call("tuya.m.user.email.password.login", login_payload)
        self.cloud_session = CloudSession(
            region=self.region,
            sid=res.get("sid", ""),
            uid=res.get("uid", ""),
            ecode=res.get("ecode", ""),
            expire_time=int(time.time()) + int(res.get("expireTime", 86400)),
        )
        return self.cloud_session

    async def list_devices(self) -> list[CloudDevice]:
        """Fetch devices associated with the authenticated account."""
        if self.cloud_session is None:
            raise RuntimeError("Not logged in")
        res = await self._api_call(
            "tuya.m.my.group.device.list",
            {},
            sid=self.cloud_session.sid,
        )
        devices: list[CloudDevice] = []
        for item in res if isinstance(res, list) else []:
            devices.append(
                CloudDevice(
                    device_id=item.get("devId", ""),
                    name=item.get("name", "Baby Monitor"),
                    local_key=item.get("localKey", ""),
                    product_id=item.get("productId", ""),
                    ip=item.get("ip", ""),
                    online=bool(item.get("isOnline", False)),
                )
            )
        return devices
