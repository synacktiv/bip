from bip.gui import *
from bip.gui.pluginmanager import BipPluginManager

import pytest
import importlib
import inspect
import tempfile
import os, sys

"""
    Test for class :class:`BipPlugin` in ``bip/gui/plugin.py``, include
    also the test for the decorators and test for the
    :class:`BipPluginManager` from ``bip/gui/pluginmanager.py``.
    Only few test here because test with user actions are more complex.
"""

### BipPlugin classes for test ###

class Plugin4Test(BipPlugin):
    na = "mytestaction"
    myaction = BipAction(na, handler=lambda *args: 1)
    def __init__(self):
        super(Plugin4Test, self).__init__()

class Plugin4Test2(BipPlugin):
    def __init__(self):
        super(Plugin4Test2, self).__init__()
        self.shortcounter = 0
        self.menucounter = 0
        self.bothcounter = 0

    @shortcut("Ctrl-H")
    def mytest_shortcut(self):
        # self is the MyPlugin object
        self.shortcounter += 1

    @menu("Edit/Plugins/")
    def mytest_menu(self):
        # self is the MyPlugin object
        self.menucounter += 1

    @shortcut("Ctrl-5")
    @menu("Edit/Plugins/")
    def mytest_both(self):
        self.bothcounter += 1

class Plugin4Test3(BipPlugin):
    def __init__(self):
        super(Plugin4Test3, self).__init__()
        self.test4load = 0
        self.activ = 0

    def load(self):
        super(Plugin4Test3, self).load()
        self.test4load = 1

    def unload(self):
        super(Plugin4Test3, self).unload()
        self.test4load = 2

    @menu("Edit/Plugins/")
    def activity_check(self):
        self.activ = 1

### BipPluginLoader ###

def test_bippluginloader00():
    # get_plugins_from_module
    mod = importlib.import_module(Plugin4Test2.__module__)
    assert inspect.ismodule(mod)
    d = BipPluginLoader.get_plugins_from_module(mod)
    assert isinstance(d, dict)
    assert d["Plugin4Test"] == Plugin4Test
    assert d["Plugin4Test2"] == Plugin4Test2
    assert "BipPlugin" not in d
    assert len(d) == 3

def test_bippluginloader01():
    # get_plg_from_files_in_module
    fo = tempfile.mkdtemp()
    modname = "plgtest"
    fold = os.path.join(fo, modname)
    os.mkdir(fold)
    f = open(os.path.join(fold, "__init__.py"), "w")
    f.close()
    f = open(os.path.join(fold, "test.py"), "w")
    f.write("from bip import *\nclass PlgTestLoader(BipPlugin):\n    pass\n")
    f.close()
    f = open(os.path.join(fold, "test2.py"), "w")
    f.write("from bip import *\nclass PlgTestLoader2(BipPlugin):\n    pass\n")
    f.close()
    sys.path.append(fo)
    d = BipPluginLoader.get_plg_from_files_in_module(modname)
    assert isinstance(d, dict)
    assert issubclass(d["PlgTestLoader"], BipPlugin)
    assert issubclass(d["PlgTestLoader2"], BipPlugin)
    assert "BipPlugin" not in d
    assert len(d) == 2
    sys.path.pop()

### Bip Plugin Manager ###

def test_bippluginmanag00():
    # Getting the bip plugin manager.
    bpm = get_plugin_manager()
    assert isinstance(bpm, BipPluginManager) == True
    assert bpm._is_loaded == True
    assert bpm.is_ready == True
    bpm2 = get_plugin_manager()
    assert bpm == bpm2

def test_bippluginmanag01():
    # plugin access
    bpm = get_plugin_manager()
    bpm.addld_plugin("Plugin4Test", Plugin4Test)
    tp = bpm.get_plugin(Plugin4Test)
    assert isinstance(tp, Plugin4Test)
    assert tp == bpm.get_plugin(Plugin4Test)
    assert tp == bpm.get_plugin("Plugin4Test")
    assert tp == bpm[Plugin4Test]
    assert tp == bpm["Plugin4Test"]
    assert Plugin4Test in bpm
    assert "Plugin4Test" in bpm
    assert ("DoNotExist" in bpm) == False
    assert bpm.get_plugin("DoNotExist") is None
    with pytest.raises(KeyError): bpm["DoNotExist"]
    with pytest.raises(RuntimeError): bpm.addld_plugin("Plugin4Test", Plugin4Test)
    bpm.addld_plugin("Plugin4Test", Plugin4Test, ifneeded=True)

### Bip Plugin ###

def test_bipplugin00():
    # base bip plugin
    bp = BipPlugin()
    assert isinstance(bp, BipPlugin)
    assert bp._activities == {}
    assert BipPlugin.to_load() == True
    class TestActivities(object): # Fake object which match BipActivity
        def __init__(self):
            self.plugin = None
            self.is_register = False
        def register(self):
            self.is_register = True
    ta = TestActivities()
    assert ta.plugin is None
    assert ta.is_register == False
    bp._activities["test"] = ta
    bp.load()
    assert ta.is_register == True


def test_bipplugin01():
    # Activities link
    bpm = get_plugin_manager()
    na = "mytestaction"
    tp = bpm.get_plugin(Plugin4Test) #Plugin4Test()
    assert tp.myaction.plugin == tp
    assert tp.myaction.is_register == True # automatically loaded by the pluginmanager
    tp.myaction.unregister()
    assert tp.myaction.is_register == False

def test_bipplugin02():
    # Activities link
    bpm = get_plugin_manager()
    bpm.addld_plugin("Plugin4Test2", Plugin4Test2)
    tp = bpm.get_plugin(Plugin4Test2)
    assert isinstance(tp.mytest_shortcut, BipActivityContainer) == True
    assert isinstance(tp.mytest_menu, BipActivityContainer) == True
    assert isinstance(tp.mytest_both, BipActivityContainer) == True
    assert tp.mytest_shortcut.plugin == tp
    assert tp.mytest_menu.plugin == tp
    assert tp.mytest_both.plugin == tp
    assert tp.mytest_shortcut._activities[0].is_register == True
    assert tp.mytest_menu._activities[0].is_register == True
    assert tp.mytest_both._activities[0].is_register == True
    assert tp.mytest_both._activities[1].is_register == True
    assert len(tp.mytest_shortcut) == 1
    assert len(tp.mytest_menu) == 1
    assert len(tp.mytest_both) == 2
    assert tp.shortcounter == 0
    assert tp.menucounter == 0
    assert tp.bothcounter == 0
    tp.mytest_shortcut()
    assert tp.shortcounter == 1
    tp.mytest_menu()
    assert tp.menucounter == 1
    tp.mytest_both()
    assert tp.bothcounter == 1
    tp.mytest_shortcut.unregister()
    tp.mytest_menu.unregister()
    tp.mytest_both.unregister()
    assert tp.mytest_shortcut._activities[0].is_register == False
    assert tp.mytest_menu._activities[0].is_register == False
    assert tp.mytest_both._activities[0].is_register == False
    assert tp.mytest_both._activities[1].is_register == False

def test_bipplugin03():
    # Load and unload
    bpm = get_plugin_manager()
    bpm.addld_plugin("Plugin4Test3", Plugin4Test3)
    tp = bpm.get_plugin(Plugin4Test3)
    assert tp.test4load == 1
    assert tp._activities["activity_check"]._activities[0].is_register == True
    tp.unload()
    assert tp.test4load == 2
    assert tp._activities["activity_check"]._activities[0].is_register == False
    tp.load()
    assert tp.test4load == 1
    assert tp._activities["activity_check"]._activities[0].is_register == True


