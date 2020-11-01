from bip.base import *

import pytest

"""
    Test for class :class:`BipData` in ``bip/base/bipdata.py``.
"""

def test_bipdata00():
    # base
    assert BipData(0x0180110000).ea == 0x0180110000
    assert BipData(0x0180110008).ea == 0x0180110008
    assert BipData(0x0180112FC0).ea == 0x0180112FC0
    assert BipData(0x018013202E).ea == 0x018013202E
    with pytest.raises(BipError): BipData(0x01800E1004)
    assert BipData._is_this_elt(0x01800E1004) == False
    assert BipData._is_this_elt(0x0) == False
    assert BipData._is_this_elt(0x0180110000)
    assert BipData._is_this_elt(0x018013202E)
    assert BipData._is_this_elt(0x0180112FC0)
    assert BipData._is_this_elt(0x0180110008)
    assert BipData._is_this_elt(0x018015E800)
    assert BipData(0x0180110000).value == 0xe
    assert BipData(0x018013202E).value == 0x13
    assert BipData(0x0180112FC0).value == 0x9b630
    assert BipData(0x0180110008).value == 0x18011ac60
    assert BipData(0x018015E800).value is None
    assert BipData(0x0180110000).original_value == 0xe
    assert BipData(0x018013202E).original_value == 0x13
    assert BipData(0x0180112FC0).original_value == 0x9b630
    assert BipData(0x0180110008).original_value == 0x18011ac60
    assert BipData(0x018015E800).original_value is None
    BipData(0x0180110000).value = 0xAA
    BipData(0x018013202E).value = 0xAABB
    BipData(0x0180112FC0).value = 0xAABBCCDD
    BipData(0x0180110008).value = 0xAABBCCDD11223344
    BipData(0x018015E800).value = 0xAA
    assert BipData(0x0180110000).value == 0xAA
    assert BipData(0x018013202E).value == 0xAABB
    assert BipData(0x0180112FC0).value == 0xAABBCCDD
    assert BipData(0x0180110008).value == 0xAABBCCDD11223344
    assert BipData(0x018015E800).value == 0xAA
    BipData(0x0180110000).value = 0xAA # reset at the same value
    assert BipData(0x0180110000).value == 0xAA
    assert BipData(0x0180110000).original_value == 0xe
    assert BipData(0x018013202E).original_value == 0x13
    assert BipData(0x0180112FC0).original_value == 0x9b630
    assert BipData(0x0180110008).original_value == 0x18011ac60
    del BipData(0x0180110000).value
    del BipData(0x018013202E).value
    del BipData(0x0180112FC0).value
    del BipData(0x0180110008).value
    del BipData(0x018015E800).value
    assert BipData(0x0180110000).value is None
    assert BipData(0x018013202E).value is None
    assert BipData(0x0180112FC0).value is None
    assert BipData(0x0180110008).value is None
    assert BipData(0x018015E800).value is None
    assert BipData(0x01801237F0).value is None

def test_bipdata01():
    # type
    assert BipData(0x0180110000).is_data == False
    assert BipData(0x0180110000).is_unknown == True
    assert BipData(0x0180110008).is_data == True
    assert BipData(0x0180110008).is_unknown == False
    #assert BipData(0x0180110000).value == 0xe
    assert BipData(0x0180001000).is_byte
    assert not BipData(0x0180001000).is_unknown
    assert BipData(0x0180001000).is_numerable
    assert BipData(0x018013202E).is_word
    assert not BipData(0x018013202E).is_unknown
    assert BipData(0x018013202E).is_numerable
    assert BipData(0x0180112FC0).is_dword
    assert not BipData(0x0180112FC0).is_unknown
    assert BipData(0x0180112FC0).is_numerable
    assert BipData(0x0180110008).is_qword
    assert not BipData(0x0180110008).is_unknown
    assert BipData(0x0180110008).is_numerable
    assert BipData(0x018015E800).is_unknown
    assert BipData(0x018015E800).is_numerable
    assert not BipData(0x01801247C0).is_numerable
    assert not BipData(0x01801247C0).is_unknown
    assert isinstance(BipData(0x0180110008).type, BipType)
    assert BipData(0x018015E800).type is None
    # type change
    assert BipData(0x0180001000).is_byte
    assert not BipData(0x0180001000).is_word
    assert not BipData(0x0180001000).is_dword
    assert not BipData(0x0180001000).is_qword
    assert not BipData(0x0180001000).is_unknown
    BipData(0x0180001000).is_byte = False
    assert not BipData(0x0180001000).is_byte
    assert not BipData(0x0180001000).is_word
    assert not BipData(0x0180001000).is_dword
    assert not BipData(0x0180001000).is_qword
    assert BipData(0x0180001000).is_unknown
    BipData(0x0180001000).is_byte = True
    assert BipData(0x0180001000).is_byte
    assert not BipData(0x0180001000).is_word
    assert not BipData(0x0180001000).is_dword
    assert not BipData(0x0180001000).is_qword
    assert not BipData(0x0180001000).is_unknown
    BipData(0x0180001000).is_word = True
    assert not BipData(0x0180001000).is_byte
    assert BipData(0x0180001000).is_word
    assert not BipData(0x0180001000).is_dword
    assert not BipData(0x0180001000).is_qword
    assert not BipData(0x0180001000).is_unknown
    BipData(0x0180001000).is_dword = True
    assert not BipData(0x0180001000).is_byte
    assert not BipData(0x0180001000).is_word
    assert BipData(0x0180001000).is_dword
    assert not BipData(0x0180001000).is_qword
    assert not BipData(0x0180001000).is_unknown
    BipData(0x0180001000).is_qword = True
    assert not BipData(0x0180001000).is_byte
    assert not BipData(0x0180001000).is_word
    assert not BipData(0x0180001000).is_dword
    assert BipData(0x0180001000).is_qword
    assert not BipData(0x0180001000).is_unknown
    del BipData(0x0180001000).type
    assert not BipData(0x0180001000).is_byte
    assert not BipData(0x0180001000).is_word
    assert not BipData(0x0180001000).is_dword
    assert not BipData(0x0180001000).is_qword
    assert BipData(0x0180001000).is_unknown
    BipData(0x0180001000).type = "__int8"
    assert BipData(0x0180001000).is_byte
    assert not BipData(0x0180001000).is_word
    assert not BipData(0x0180001000).is_dword
    assert not BipData(0x0180001000).is_qword
    assert not BipData(0x0180001000).is_unknown
    BipData(0x018015E800).type = "__int32 *"
    assert BipData(0x018015E800).type.str == '__int32 *'


def test_bipdata02():
    # static method
    assert BipData.get_byte(0x018012E800) == 0x4f
    assert BipData.get_word(0x018012E801) == 0x1e81
    assert BipData.get_dword(0x018012E804) == 0xf5129aee
    assert BipData.get_qword(0x018012E808) == 0x8a7c6a266c2b0836
    assert BipData.get_ptr(0x0180110018) == 0x18011ac70
    assert BipData.get_ptr(0x018012E808) == 0x8a7c6a266c2b0836
    BipData.set_byte(0x018012E800, 0xAA)
    BipData.set_word(0x018012E801, 0xAABB)
    BipData.set_dword(0x018012E804, 0xAABBCCDD)
    BipData.set_qword(0x018012E808, 0xAABBCCDD11223344)
    assert BipData.get_byte(0x018012E800) == 0xAA
    assert BipData.get_word(0x018012E801) == 0xAABB
    assert BipData.get_dword(0x018012E804) == 0xAABBCCDD
    assert BipData.get_qword(0x018012E808) == 0xAABBCCDD11223344
    BipData.set_dword(0x018013202E, 0xCCDD1122)
    assert BipData.get_word(0x018013202E) == 0x1122
    assert BipData.get_word(0x0180132030) == 0xCCDD
    assert BipData.get_cstring(0x0180129090) == b'LdrpLoadResourceFromAlternativeModule'
    assert BipData.get_cstring(0x0180129090, size=4) == b'Ldrp'
    assert BipData.get_cstring(0x01801568C5) is None
    assert BipData.get_c16string(0x0180113EC8) == b'\\AppContainerNamedObjects'
    assert BipData.get_c16string(0x0180113EC8, size=8) == b'\\App'
    assert BipData.get_c16string(0x0180113F44) is None
    assert BipData.get_bytes(0x01800D3242, 6) == b'A\xb8\x08\x00\x00\x00'
    BipData.set_bytes(0x01800D3242, "123")
    assert BipData.get_bytes(0x01800D3242, 6) == b'123\x00\x00\x00'
    assert BipData.get_bytes(0x01800D3242, 6, original=True) == b'A\xb8\x08\x00\x00\x00'
    BipData.set_bytes(0x01800D3242, b"A\xb8\x08")
    assert BipData.get_bytes(0x01800D3242, 6) == b'A\xb8\x08\x00\x00\x00'


