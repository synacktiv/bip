
# import everything needed in the plugin manager
from bip.gui import get_plugin_manager


def PLUGIN_ENTRY():
    return get_plugin_manager()
