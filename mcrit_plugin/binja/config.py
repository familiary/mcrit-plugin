import json
import os

from binaryninja import SecretsProvider, Settings, log_error

from mcrit_plugin.core.config import PLUGIN_ROOT, McritConfig

GROUP = "mcrit"
SECRET_SETTINGS = {"mcritweb_api_token"}
KEYCHAIN_PROVIDER = "SystemSecretsProvider"
# ida-settings only has string/boolean, so numeric settings are declared as strings in the manifest
NUMBER_SETTINGS = {
    "mcrit_request_timeout": (0, 3600),
    "blocks_min_size": (4, 20),
    "function_min_score": (0, 100),
    "overview_min_score": (0, 100),
}


def _read_json(filename):
    with open(os.path.join(PLUGIN_ROOT, filename), "r", encoding="utf-8") as handle:
        return json.load(handle)


VERSION = _read_json("plugin.json")["version"]
# shared with ida-plugin.json (kept identical by scripts/common/verify_settings_sync.py); ida-plugin.json
# itself is excluded from GitHub source archives, which is what Binary Ninja installs
_DECLARED_SETTINGS = {
    setting["key"]: setting
    for setting in _read_json(os.path.join("mcrit_plugin", "core", "settings.json"))
}


def register_settings():
    settings = Settings()
    settings.register_group(GROUP, "MCRIT")
    for key, declared in _DECLARED_SETTINGS.items():
        properties = {
            "title": declared["name"],
            "type": declared["type"],
            "default": declared["default"],
            "description": declared["documentation"],
            "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
        }
        if key in NUMBER_SETTINGS:
            properties["type"] = "number"
            properties["default"] = int(declared["default"])
            properties["minValue"], properties["maxValue"] = NUMBER_SETTINGS[key]
        if key in SECRET_SETTINGS:
            properties["hidden"] = True
            properties["description"] += (
                " Stored in the system keychain; the field is cleared once the value is moved there."
            )
        if not settings.register_setting(f"{GROUP}.{key}", json.dumps(properties)):
            log_error(f"Failed to register MCRIT setting {GROUP}.{key}")


def _get_secret(key, settings):
    """Move a value typed into Settings into the system keychain, then read it from there."""
    full_key = f"{GROUP}.{key}"
    provider = SecretsProvider.get(KEYCHAIN_PROVIDER)
    typed_value = settings.get_string(full_key)
    if typed_value:
        if provider is None or not provider.store_data(full_key, typed_value):
            # no usable keychain on this system: keep the value in Settings
            return typed_value
        settings.reset(full_key)
        return typed_value
    if provider is not None and provider.has_data(full_key):
        return provider.get_data(full_key)
    raise KeyError(key)


def clear_stored_secrets():
    provider = SecretsProvider.get(KEYCHAIN_PROVIDER)
    settings = Settings()
    for key in SECRET_SETTINGS:
        full_key = f"{GROUP}.{key}"
        if provider is not None and provider.has_data(full_key):
            provider.delete_data(full_key)
        settings.reset(full_key)


def _get_setting(key):
    full_key = f"{GROUP}.{key}"
    settings = Settings()
    if not settings.contains(full_key):
        raise KeyError(key)
    if key in SECRET_SETTINGS:
        return _get_secret(key, settings)
    if key in NUMBER_SETTINGS:
        return settings.get_integer(full_key)
    if _DECLARED_SETTINGS[key]["type"] == "boolean":
        return settings.get_bool(full_key)
    return settings.get_string(full_key)


config = McritConfig(VERSION, _get_setting)
