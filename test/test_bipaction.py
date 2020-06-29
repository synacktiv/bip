from bip.gui import *

import pytest

"""
    Test for class :class:`BipAction` in ``bip/gui/actions.py``.
    Only few test here because test with user actions are more complex.
"""

def test_bipaction00():
    # BipAction
    ba = BipAction("test")
    assert isinstance(ba, BipAction)
    assert isinstance(ba, BipActivity)
    with pytest.raises(RuntimeError): ba.handler()
    with pytest.raises(RuntimeError): ba()
    assert ba._name == "test" # TODO: this is an internal property
    assert ba.is_register == False
    ba.register()
    assert ba.is_register == True
    ba2 = BipAction("test")
    ba2.register()
    assert ba2.is_register == False
    ba.unregister()
    assert ba.is_register == False
    ba2.register()
    assert ba2.is_register == True
    ba3 = BipAction("test2", label="test") # diff name, same label
    ba3.register()
    assert ba3.is_register == True
    ba2.unregister()
    assert ba2.is_register == False
    ba3.unregister()
    assert ba3.is_register == False

def test_bipaction01():
    # BipAction handler
    ta = BipAction("test2", handler=lambda act: 2)
    assert ta.handler() == 2
    assert ta() == 2
    ta = BipAction("test3", handler=lambda act: act)
    assert ta() == ta
    def f(act):
        act.test = 2
    ta = BipAction("test4", handler=f)
    ta()
    assert ta.test == 2

def test_bipaction02():
    # BipAction menu
    ta = BipAction("testm0", handler=lambda *args: 2)
    ta.register()
    assert ta.is_register == True
    assert ta.attach_to_menu("Edit/Plugins/") == True
    ta2 = BipAction("testm1", handler=lambda *args: 3, path_menu="Edit/Plugins/")
    ta2.register()
    assert ta2.is_register == True
    ta.unregister()
    ta2.unregister()





