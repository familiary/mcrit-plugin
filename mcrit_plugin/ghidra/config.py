"""Settings of the Ghidra plugin: the keys declared in mcrit_plugin/core/settings.json, registered
under Edit > Tool Options > MCRIT. config_override.json in the plugin's root folder (the clone's
root, or the installed extension's folder) still takes precedence, as in IDA and Binary Ninja
(McritConfig handles that)."""

import json
import os

from mcrit_plugin.core.config import PLUGIN_ROOT, McritConfig

VERSION = "0.1.0"
OPTIONS_CATEGORY = "MCRIT"
SECRET_SETTINGS = {"mcritweb_api_token"}
# settings.json keeps numbers as strings because ida-settings has no number type; Ghidra has one
NUMBER_SETTINGS = {
    "mcrit_request_timeout": (0, 3600),
    "blocks_min_size": (4, 20),
    "function_min_score": (50, 100),
    "overview_min_score": (0, 100),
}


def declared_settings():
    path = os.path.join(PLUGIN_ROOT, "mcrit_plugin", "core", "settings.json")
    with open(path, "r", encoding="utf-8") as handle:
        return {setting["key"]: setting for setting in json.load(handle)}


def option_name(declared):
    return declared["name"]


def register_options(tool):
    """Declare every setting in the tool's MCRIT options; already registered ones keep their
    values. Returns the Options object."""
    from ghidra.framework.options import OptionType
    from java.lang import Boolean, Integer

    options = tool.getOptions(OPTIONS_CATEGORY)
    for key, declared in declared_settings().items():
        name = option_name(declared)
        if options.isRegistered(name):
            continue
        description = declared["documentation"]
        if key in NUMBER_SETTINGS:
            low, high = NUMBER_SETTINGS[key]
            options.registerOption(
                name,
                OptionType.INT_TYPE,
                # JPype boxes a Python int as Long, which INT_TYPE rejects
                Integer(int(declared["default"])),
                None,
                f"{description} ({low} to {high})",
            )
        elif declared["type"] == "boolean":
            options.registerOption(
                name, OptionType.BOOLEAN_TYPE, Boolean(bool(declared["default"])), None, description
            )
        elif key in SECRET_SETTINGS:
            description += " Stored with Ghidra's tool options in plain text."
            editor = _password_editor_class()
            if editor is not None:
                editor.register(options, name, declared["default"], description)
            else:
                options.registerOption(
                    name, OptionType.STRING_TYPE, declared["default"], None, description
                )
        else:
            options.registerOption(
                name, OptionType.STRING_TYPE, declared["default"], None, description
            )
    return options


def _password_editor_class():
    try:
        from jpype import JClass

        return JClass("mcrit.ghidra.McritPasswordEditor")
    except Exception:
        return None


def make_getter(tool):
    """A McritConfig getter reading the tool's MCRIT options; KeyError means "use the default"."""
    if tool is None:

        def missing(key):
            raise KeyError(key)

        return missing
    options = register_options(tool)
    declared = declared_settings()

    def get_setting(key):
        if key not in declared:
            raise KeyError(key)
        setting = declared[key]
        name = option_name(setting)
        if key in NUMBER_SETTINGS:
            low, high = NUMBER_SETTINGS[key]
            value = int(options.getInt(name, int(setting["default"])))
            return max(low, min(high, value))
        if setting["type"] == "boolean":
            return bool(options.getBoolean(name, bool(setting["default"])))
        return str(options.getString(name, setting["default"]) or "")

    return get_setting


def make_config(tool=None):
    return McritConfig(VERSION, make_getter(tool))
