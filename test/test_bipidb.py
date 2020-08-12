from bip import *

import pytest

"""
    Test for class :class:`BipIdb` in ``bip/base/bipidb.py``.
"""


def test_bipidb00():
    assert BipIdb.ptr_size() == 64
    assert BipIdb.min_ea() == 0x180001000
    assert min_ea() == 0x180001000
    assert BipIdb.max_ea() == 0x180174000
    assert max_ea() == 0x180174000
    assert BipIdb.image_base() == 0x180000000
    assert BipIdb.relea(0x0180110018) == 0x110018
    assert BipIdb.absea(0x110018) == 0x180110018
    BipIdb.current_addr() # check for no exception/API changes
    Here()


