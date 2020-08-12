from bip.gui import *

import pytest

"""
    Test for class :class:`BipUserSelect` in ``bip/gui/userselect.py``.
"""

def test_bipuserselect00():
    # staticmethod
    # as complicated to test only call them for checking of API problems
    BipUserSelect.get_curr_highlighted_str()
    BipUserSelect.get_curr_highlighted_int()

