import ida_settings

from mcrit_plugin.core.config import McritConfig

try:
    from hcli.lib.ida.plugin.exceptions import PluginNotInstalledError
except ImportError:
    PluginNotInstalledError = RuntimeError

VERSION = "2.0.0"
MCRIT4IDA_PLUGIN_ONLY = False

PLUGIN_NAME = "mcrit-ida"


def _get_setting(key):
    # by name when installed through HCLI; get_current_plugin_setting() instead infers the plugin
    # from the call stack, which covers manual copies into $IDAUSR/plugins
    try:
        return ida_settings.get_plugin_setting(PLUGIN_NAME, key)
    except PluginNotInstalledError:
        return ida_settings.get_current_plugin_setting(key)


config = McritConfig(VERSION, _get_setting)
