import binaryninja


def register_plugin():
    # imported here, so that importing one module of this package does not import the others
    from mcrit_plugin.binja.config import register_settings
    from mcrit_plugin.binja.MatchRenderLayer import register_layer

    register_settings()
    register_layer()
    if binaryninja.core_ui_enabled():
        from mcrit_plugin.binja.McritSidebar import register

        register()
