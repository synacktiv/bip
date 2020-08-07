import sys

from bip.base import *

import idc
import ida_bytes

import pytest

"""
Test for classes in ``bip/base/bipelt.py``. Mainly this allows to test the
basic :class:`BipElt` features.
"""


def test_bipelt00():
    # ea, flags, size
    assert BipElt(0x01800D325A).ea == 0x01800D325A
    assert BipElt(0x01800D325A).flags == ida_bytes.get_full_flags(0x01800D325A)
    assert BipElt(0x01800D325A).size == 4
    assert BipElt(0x018015D260).size == 1
    assert BipElt(0x018015D228).size == 8
    # bytes
    assert BipElt(0x01800D325A).bytes == [0x48, 0x83, 0xC4, 0x60]
    BipElt(0x01800D325A).bytes = [0x90, 0x90, 0x90, 0x90]
    assert BipElt(0x01800D325A).bytes == [0x90, 0x90, 0x90, 0x90]
    assert BipElt(0x01800D325A).original_bytes == [0x48, 0x83, 0xC4, 0x60]
    BipElt(0x01800D325A).bytes = b"\xAA" * 4
    assert BipElt(0x01800D325A).bytes == [0xAA, 0xAA, 0xAA, 0xAA]
    BipElt(0x01800D325A).bytes = [0x48, 0x83, 0xC4, 0x60]
    assert BipElt(0x01800D325A).bytes == [0x48, 0x83, 0xC4, 0x60]
    # name
    assert BipElt(0x01800D325A).name == 'loc_1800D325A'
    assert BipElt(0x01800D325A).is_dummy_name
    assert not BipElt(0x01800D325A).is_auto_name
    assert BipElt(0x01800D325A).is_ida_name
    assert not BipElt(0x01800D325A).is_user_name
    ie = BipElt(0x01800D325A)
    prevname = ie.name
    ie.name = "idaelt_test"
    assert ie.name == "idaelt_test"
    assert not BipElt(0x01800D325A).is_dummy_name
    assert not BipElt(0x01800D325A).is_auto_name
    assert not BipElt(0x01800D325A).is_ida_name
    assert BipElt(0x01800D325A).is_user_name
    ie.name = None
    assert BipElt(0x01800D325A).name == 'loc_1800D325A'
    assert BipElt(0x01800D325A).is_dummy_name
    assert not BipElt(0x01800D325A).is_auto_name
    assert BipElt(0x01800D325A).is_ida_name
    assert not BipElt(0x01800D325A).is_user_name
    assert BipElt(0x018014F7FF).is_auto_name
    assert not BipElt(0x018014F7FF).is_dummy_name
    assert BipElt(0x018014F7FF).is_ida_name
    assert BipElt(0x0180125828).demangle_name is None
    # TODO: need other binary for demangle name
    # color
    assert BipElt(0x01800D325A).color == idc.get_color(0x01800D325A, idc.CIC_ITEM)
    ie = BipElt(0x01800D325A)
    prevcolor = ie.color
    ie.color = 0xAABBCC
    assert ie.color == 0xAABBCC
    ie.color = prevcolor


def test_bipelt01():
    # cmp and hash
    assert BipElt(0x01800D325A) == BipElt(0x01800D325A)
    assert BipElt(0x01800D325A) > BipElt(0x01800D325A - 1)
    assert BipElt(0x01800D325A - 1) < BipElt(0x01800D325A)
    assert len([BipElt(0x01800D325A), BipElt(0x01800D325A)]) == 2
    assert len(set([BipElt(0x01800D325A), BipElt(0x01800D325A)])) == 1

def test_bipelt02():
    # comment
    assert BipElt(0x01800D325A).comment is None
    ie = BipElt(0x01800D325A)
    ie.comment = "test"
    res = ie.comment == "test"
    ie.comment = None
    assert res
    assert BipElt(0x01800D325A).rcomment is None
    ie = BipElt(0x01800D325A)
    ie.rcomment = "test"
    res = ie.rcomment == "test"
    ie.rcomment = None
    assert res
    assert BipElt(0x01800D325A).has_comment == False
    ie = BipElt(0x01800D325A)
    ie.comment = "test"
    res = ie.has_comment
    ie.comment = ""
    assert res

def test_bipelt03():
    # flags
    assert BipElt(0x01800D325A).is_code == True
    assert BipElt(0x01800D325A).is_data == False
    assert BipElt(0x01800D325A).is_unknown == False
    assert BipElt(0x01800D325A).is_head == True
    assert BipElt(0x01800D325B).is_head == False
    assert BipElt(0x018015D228).is_code == False
    assert BipElt(0x018015D228).is_data == True
    assert BipElt(0x018015D228).is_unknown == False
    assert BipElt(0x018015D228).is_head == True
    assert BipElt(0x018015D260).is_head == False
    assert BipElt(0x018015D261).is_head == False
    assert BipElt(0x018015D260).is_unknown == True
    assert BipElt(0x018013183C).is_unknown == True
    assert BipElt(0x018015A410).has_data == False
    assert BipElt(0x01800D325A).has_data == True
    assert BipElt(0x018015D228).has_data == False
    assert BipElt(0x018013183C).has_data == True

def test_bipelt04():
    # GetElt class creation
    assert GetElt(0x018015D228).__class__ == BipData
    assert GetElt(0x01800D325A).__class__ == BipInstr
    assert GetElt(0).__class__ == BipElt
    assert GetElt(0xAAAAA).__class__ == BipElt
    with pytest.raises(RuntimeError):
        GetElt(idc.BADADDR)
    assert GetEltByName('loc_1800D325A') == GetElt(0x01800D325A)
    assert GetEltByName('donotexist') is None
    # TODO: need test GetElt for other objects such as struct and struct member

def test_bipelt05():
    ## static method of BipElt
    # is_mapped
    assert not BipElt.is_mapped(0)
    assert not BipElt.is_mapped(0xAAAA)
    assert not BipElt.is_mapped(0xFFFFFFFF)
    assert not BipElt.is_mapped(0xFFFFFFFFFFFFFFFF)
    assert BipElt.is_mapped(0x018015D228)
    # next_data
    assert BipElt.next_data_addr(ea=0x1800d324b, down=True) == 0x1800d3284
    assert BipElt.next_data_addr(ea=0x1800d324b, down=False) == 0x1800d2fe1
    assert BipElt.next_data(ea=0x1800d324b, down=True).ea == 0x1800d3284
    assert BipElt.next_data(ea=0x1800d324b, down=False).ea == 0x1800d2fe1
    # next code
    assert BipElt.next_code_addr(ea=0x1800d324b, down=True) == 0x1800d324e
    assert BipElt.next_code_addr(ea=0x1800d324b, down=False) == 0x1800d3248
    assert BipElt.next_code(ea=0x1800d324b, down=True).ea == 0x1800d324e
    assert BipElt.next_code(ea=0x1800d324b, down=False).ea == 0x1800d3248
    assert isinstance(BipElt.next_code(ea=0x1800d324b, down=True), BipInstr)
    assert isinstance(BipElt.next_code(ea=0x1800d324b, down=False), BipInstr)
    # next unknown
    assert BipElt.next_unknown_addr(ea=0x1800d324b, down=True) == 0x180110000
    assert BipElt.next_unknown_addr(ea=0x1800d324b, down=False) is None
    assert BipElt.next_unknown_addr(ea=0x180110000, down=True) == 0x180110001
    assert BipElt.next_unknown_addr(ea=0x180110001, down=False) == 0x180110000
    assert BipElt.next_unknown(ea=0x180110000, down=True).ea == 0x180110001
    assert BipElt.next_unknown(ea=0x180110001, down=False).ea == 0x180110000
    assert isinstance(BipElt.next_unknown(ea=0x180110000, down=True), BipData)
    assert isinstance(BipElt.next_unknown(ea=0x180110001, down=False), BipData)
    # next defined
    assert BipElt.next_defined_addr(ea=0x1800d324b, down=True) == 0x1800d324e
    assert BipElt.next_defined_addr(ea=0x1800d324b, down=False) == 0x1800d3248
    assert BipElt.next_defined_addr(ea=0x180110000, down=True) == 0x180110008
    assert BipElt.next_defined(ea=0x1800d324b, down=True).ea == 0x1800d324e
    assert BipElt.next_defined(ea=0x1800d324b, down=False).ea == 0x1800d3248
    assert BipElt.next_defined(ea=0x180110000, down=True).ea == 0x180110008

def test_bipelt06():
    ## static method of BipElt: search
    # search_bytes
    assert BipElt.search_bytes_addr("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 00 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x180000000) == 0x18011A808
    assert BipElt.search_bytes_addr("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 ? 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x180000000) == 0x18011A808
    assert BipElt.search_bytes_addr("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 ? 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x18011a808) is None
    assert BipElt.search_bytes_addr("49 8B CD", start_ea=0x01800D324B) == 0x1800D4FCA
    assert BipElt.search_bytes_addr("49 8B CD", start_ea=0x01800D324B, nxt=False) == 0x1800D324B
    assert BipElt.search_bytes_addr("49 8B CD", start_ea=0x01800D3242, end_ea=0x01800D3248) is None
    assert BipElt.search_bytes("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 00 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x180000000).ea == 0x18011A808
    assert BipElt.search_bytes("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 ? 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x180000000).ea == 0x18011A808
    assert BipElt.search_bytes("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 ? 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x18011a808) is None
    assert BipElt.search_bytes("49 8B CD", start_ea=0x01800D324B).ea == 0x1800D4FCA
    assert BipElt.search_bytes("49 8B CD", start_ea=0x01800D324B, nxt=False).ea == 0x1800D324B
    assert BipElt.search_bytes("49 8B CD", start_ea=0x01800D3242, end_ea=0x01800D3248) is None
    # search string
    assert BipElt.search_str_addr("Wow64SuspendLocalThread", start_ea=0x180000000) == 0x18011a3b8
    assert BipElt.search_str_addr("Wow64SuspendLocalThread\x00", start_ea=0x180000000) == 0x18011A3B8
    assert BipElt.search_str_addr("Wow64SuspendLocalThreat", start_ea=0x180000000) is None
    assert BipElt.search_str("Wow64SuspendLocalThread", start_ea=0x180000000).ea == 0x18011a3b8
    assert BipElt.search_str("Wow64SuspendLocalThread\x00", start_ea=0x180000000).ea == 0x18011A3B8
    assert isinstance(BipElt.search_str("Wow64SuspendLocalThread", start_ea=0x180000000), BipData)
    assert isinstance(BipElt.search_str("Wow64SuspendLocalThread\x00", start_ea=0x180000000), BipData)
    assert BipElt.search_str("Wow64SuspendLocalThreat", start_ea=0x180000000) is None

def test_bipelt07():
    # bipelt xref (just basic test, not the actual test for the BipXref obj)
    # this basiccally is the test for the BipRefElt
    assert len(BipElt(0x01800D3242).xFrom) == 1
    assert BipElt(0x01800D3242).xFrom[0].src == BipElt(0x01800D3242)
    assert BipElt(0x01800D3242).xFrom[0].dst == BipElt(0x01800D3248)
    assert BipElt(0x01800D3242).xEaFrom == [0x1800d3248]
    assert BipElt(0x01800D3242).xEltFrom == [BipElt(0x01800D3248)]
    assert BipElt(0x01800D3242).xCodeFrom == [BipInstr(0x1800D3248)]
    assert len(BipElt(0x01800D3242).xTo) == 1
    assert BipElt(0x01800D3242).xTo[0].src == BipElt(0x01800D323A)
    assert BipElt(0x01800D3242).xTo[0].dst == BipElt(0x01800D3242)
    assert BipElt(0x01800D3242).xEaTo == [0x1800d323A]
    assert BipElt(0x01800D3242).xEltTo == [BipElt(0x01800D323A)]
    assert BipElt(0x01800D3242).xCodeTo == [BipInstr(0x1800D323A)]

def test_bipelt08():
    # test BipElt.iter_heads
    gen = BipElt.iter_heads()
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x180001000
    elt = next(gen)
    assert elt.__class__ == BipInstr
    assert elt.ea == 0x180001010
    elt = next(gen)
    assert elt.__class__ == BipInstr
    assert elt.ea == 0x180001012
    # with start
    gen = BipElt.iter_heads(start=0x18012F16C)
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x18012F16C
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x18012F172
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x18012F180
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x18012F190
    # BipData.iter_heads
    gen = BipData.iter_heads()
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x180001000
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x180001307
    # BipInstr.iter_heads
    gen = BipInstr.iter_heads()
    elt = next(gen)
    assert elt.__class__ == BipInstr
    assert elt.ea == 0x180001010
    elt = next(gen)
    assert elt.__class__ == BipInstr
    assert elt.ea == 0x180001012


def test_bipelt09():
    # test BipElt.iter_all
    gen = BipElt.iter_all()
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x180001000
    elt = next(gen)
    assert elt.__class__ == BipInstr
    assert elt.ea == 0x180001010
    elt = next(gen)
    assert elt.__class__ == BipInstr
    assert elt.ea == 0x180001012
    # with start
    gen = BipElt.iter_all(start=0x18012F16C)
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x18012F16C
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x18012F172
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x18012F180
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x18012F184
    # BipData.iter_all
    gen = BipData.iter_all()
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x180001000
    elt = next(gen)
    assert elt.__class__ == BipData
    assert elt.ea == 0x180001307
    # BipInstr.iter_all
    gen = BipInstr.iter_all()
    elt = next(gen)
    assert elt.__class__ == BipInstr
    assert elt.ea == 0x180001010
    elt = next(gen)
    assert elt.__class__ == BipInstr
    assert elt.ea == 0x180001012


