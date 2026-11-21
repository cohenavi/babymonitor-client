"""Constants for the Philips Avent Baby Monitor+ integration."""

from __future__ import annotations

DOMAIN = "babymonitor"

PLATFORMS = [
    "camera",
    "binary_sensor",
    "switch",
    "light",
    "sensor",
]

# Connection modes
CONF_MODE = "mode"
MODE_LAN = "lan"
MODE_CLOUD = "cloud"
MODE_AUTO_KEY = "auto_key"

# LAN configuration
CONF_HOST = "host"
CONF_PORT = "port"
CONF_DEVICE_ID = "device_id"
CONF_LOCAL_KEY = "local_key"
CONF_PROTOCOL_VERSION = "protocol_version"

DEFAULT_LAN_PORT = 6668
DEFAULT_DISCOVERY_PORT_PLAIN = 6666
DEFAULT_DISCOVERY_PORT_ENC = 6667
DEFAULT_PROTOCOL_VERSION = "3.3"

# Cloud / Automatic Key Extraction configuration
CONF_EMAIL = "email"
CONF_PASSWORD = "password"
CONF_REGION = "region"
CONF_COUNTRY_CODE = "country_code"
CONF_MFA_CODE = "mfa_code"
CONF_SESSION_DATA = "session_data"
CONF_APP_KEY = "app_key"
CONF_APP_SECRET = "app_secret"
CONF_APK_PATH = "apk_path"
CONF_CERT_SHA256 = "cert_sha256"
CONF_BMP_TOKEN = "bmp_token"
CONF_APP_VERSION = "app_version"

DEFAULT_REGION = "eu"
DEFAULT_COUNTRY_CODE = "45"
DEFAULT_APP_VERSION = "1.9.0"

TUYA_REGIONS = {
    "eu": "https://a1.tuyaeu.com/api.json",
    "us": "https://a1-us.iotbing.com/api.json",
    "in": "https://a1-in.iotbing.com/api.json",
    "cn": "https://a1.iot334.com/api.json",
}

# Tuya IPC / Baby Monitor Data Points (DPs)
DP_NIGHT_LIGHT = "101"
DP_LULLABY = "102"
DP_CRY_DETECTION = "103"
DP_MOTION_DETECTION = "104"
DP_NIGHT_VISION = "108"
DP_STATUS_LED = "101"

# Streaming
DEFAULT_STREAM_PORT = 0  # Ephemeral local HTTP port for MPEG-TS
STUN_MAGIC_COOKIE = 0x2112A442
