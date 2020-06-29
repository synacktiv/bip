from bip.gui import *

import pytest

"""
    Test for classes :class:`BipActivity` and :class:`BipActivityContainer`
    in ``bip/gui/activity.py``.
"""

def test_bipactivity00():
    # BipActivity
    ba = BipActivity()
    assert ba.plugin is None
    with pytest.raises(RuntimeError): ba()
    with pytest.raises(RuntimeError): ba.register()
    with pytest.raises(RuntimeError): ba.unregister()
    with pytest.raises(RuntimeError): ba.handler()
    # BipActivity child basic
    class TestBA(BipActivity):
        def register(self):
            return 1
        def unregister(self):
            return 2
        def handler(self, a, b):
            return a + b
    tba = TestBA()
    assert tba.plugin is None
    assert tba(2, 3) == 5
    assert tba.handler(2, 3) == 5
    assert tba.register() == 1
    assert tba.unregister() == 2

# TODO: test link BipActivity and plugins


def test_bipactivitycontainer00():
    # base
    def f(plg):
        return 3
    bac = BipActivityContainer(f)
    assert bac.plugin is None
    assert bac.get_original_method() == f
    assert len(bac) == 0
    assert bac.handler() == 3
    assert bac() == 3

def test_bipactivitycontainer01():
    # with activity
    def f(plg):
        return 3
    class TestBA(BipActivity):
        def register(self):
            self.is_register = True
        def unregister(self):
            self.is_register = False
    bac = BipActivityContainer(f)
    ta0 = TestBA()
    ta1 = TestBA()
    bac.add_activity(ta0)
    bac.add_activity(ta1)
    assert len(bac) == 2
    bac.plugin = 3
    assert bac.plugin == 3
    assert ta0.plugin == 3
    assert ta1.plugin == 3
    bac.register()
    assert ta0.is_register
    assert ta1.is_register
    bac.unregister()
    assert ta0.is_register == False
    assert ta1.is_register == False

def test_bipactivitycontainer02():
    # get_container
    def f(plg):
        return 3
    bac = BipActivityContainer.get_container(f)
    assert isinstance(bac, BipActivityContainer)
    assert isinstance(BipActivityContainer.get_container(bac), BipActivityContainer)




