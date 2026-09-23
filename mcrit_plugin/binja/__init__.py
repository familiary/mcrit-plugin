import binaryninja

from mcrit_plugin.binja.config import register_settings


def register_plugin():
    register_settings()
    if binaryninja.core_ui_enabled():
        from mcrit_plugin.binja.McritSidebar import register

        register()
