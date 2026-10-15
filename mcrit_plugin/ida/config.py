import ida_settings

from mcrit_plugin.core.config import McritConfig

try:
    from hcli.lib.ida.plugin.exceptions import PluginNotInstalledError
except ImportError:
    PluginNotInstalledError = RuntimeError

VERSION = "2.0.0"

PLUGIN_NAME = "mcrit-ida"


def _get_setting(key):
    try:
        return ida_settings.get_plugin_setting(PLUGIN_NAME, key)
    except PluginNotInstalledError as exc:
        raise KeyError(key) from exc


config = McritConfig(VERSION, _get_setting)
