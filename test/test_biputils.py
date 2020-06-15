from bip.base import *

import pytest

"""
    Test for functions in ``bip/base/utils.py``. Those functions should be
    removed!
"""

def test_biputils00():
    assert Ptr(0x0180110018) == 0x18011ac70
    assert get_ptr_size() == 0x40
    assert relea(0x0180110018) == 0x110018
    assert absea(0x110018) == 0x180110018
    assert get_addr_by_name("unk_180110020") == 0x110020
    assert get_addr_by_name("donotexist") == 0x0
    assert get_name_by_addr(0x110020) == ('', 0x0)
    assert get_name_by_addr(0x10F010) == ('RtlAllocateMemoryBlockLookaside', 0x0)
    assert min_ea() == 0x180001000
    assert max_ea() == 0x180174000

    # TODO: get_struct_from_lvar, bip_exec_sync, get_highlighted_identifier_as_int

