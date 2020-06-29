from bip.gui import *

import pytest

"""
    Small and artificial test for the top menu functions
    in ``bip/gui/menutb.py``. As there is no simple way to test if they are
    correctly set, this just make the calls to the function, this allow at
    minima to check that the API is not broken.
"""

def test_menutb00():
    assert add_top_menu("NewTopLevelMenu", before="Edit")
    assert add_top_menu("NewTopLevelMenu", before="Edit") == False
    assert add_top_menu("NewTopLevelMenu", uid="NewTopLevelMenu2", before="Edit")
    del_top_menu("NewTopLevelMenu")
    del_top_menu("NewTopLevelMenu2")


