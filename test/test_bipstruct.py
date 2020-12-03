import sys

from bip.base import *

import idc

import pytest

"""
Test for classes in ``bip/base/bipstruct.py``. This allows to test the
basic :class:`BipStruct` and :class:`BStructMember` features.
"""

def test_bipstruct00():
    # get, create delete 
    st = BipStruct.get("_UNWIND_HISTORY_TABLE")
    assert isinstance(st, BipStruct)
    with pytest.raises(ValueError): BipStruct.get("DoNotExist")
    with pytest.raises(ValueError): BipStruct.create("_UNWIND_HISTORY_TABLE")
    assert isinstance(next(BipStruct.iter_all()), BipStruct)
    assert next(BipStruct.iter_all()).name == "GUID"
    assert len([s for s in BipStruct.iter_all()]) == 0x15
    st = BipStruct.create("newStruct")
    assert isinstance(st, BipStruct)
    st = BipStruct.get("newStruct")
    assert isinstance(st, BipStruct)
    assert len([s for s in BipStruct.iter_all()]) == 0x16
    BipStruct.delete("newStruct")
    with pytest.raises(ValueError): BipStruct.get("newStruct")
    with pytest.raises(ValueError): BipStruct.delete("newStruct")

def test_bipstruct01():
    # base
    st = BipStruct.get("_UNWIND_HISTORY_TABLE")
    assert isinstance(st, BipStruct)
    assert st._sid == 0xff0000000000629e
    assert BipStruct._is_this_elt(st._sid)
    assert BipStruct._is_this_elt(0x01800D3253) == False
    assert BipStruct(st._sid)._sid == st._sid
    assert st.name == '_UNWIND_HISTORY_TABLE'
    st.name = "test"
    assert st.name == 'test'
    st.name = "_UNWIND_HISTORY_TABLE"
    assert st.name == '_UNWIND_HISTORY_TABLE'
    assert st.size == 0xd8
    assert str(st) == 'Struct: _UNWIND_HISTORY_TABLE (size=0xD8)'
    assert st.comment is None
    st.comment = "test"
    assert st.comment == 'test'
    st.comment = ""
    assert st.comment != 'test'
    assert st.comment is None
    st.comment = "test2"
    assert st.comment == 'test2'
    assert st.rcomment is None
    st.rcomment = "test3"
    assert st.rcomment == 'test3'
    assert st.comment == 'test2'
    st.comment = None
    st.rcomment = None
    assert st.comment is None
    assert st.rcomment is None

def test_bipstruct02():
    # GUI
    st = BipStruct.get("_UNWIND_HISTORY_TABLE")
    assert st.is_hidden == True
    st.is_hidden = False
    assert st.is_hidden == False
    st.is_hidden = True
    assert st.is_hidden == True

def test_bipstruct03():
    # members access
    st = BipStruct.get("_UNWIND_HISTORY_TABLE")
    assert st.nb_members == 0x8
    assert len(st.members) == 0x8
    assert isinstance(st.members[0], BStructMember) == True
    assert st.members[0].name == 'Count'
    assert len([m for m in st.members_iter]) == 0x8
    assert isinstance(next(st.members_iter), BStructMember) == True
    assert next(st.members_iter).name == 'Count'
    assert isinstance(st.member_at(0), BStructMember) == True
    assert st.member_at(0).name == 'Count'
    assert st.member_at(7).name == 'Once'
    assert st.member_at(3).name == 'Count'
    with pytest.raises(IndexError): st.member_at(0x100)
    assert st.member_by_name("Count").name == 'Count'
    assert st.member_by_name("Once").name == 'Once'
    assert st[3].name == 'Count'
    for m in st:
        assert m.name == 'Count'
        break

def test_bipstruct04():
    # members creation
    st = BipStruct.create("newStruct")
    assert st.size == 0
    st.add("testmemb", 4)
    assert st.size == 4
    assert st[0].name == "testmemb"
    with pytest.raises(TypeError): st.add("testmemb2", 3)
    with pytest.raises(TypeError): st.add(3, 4)
    with pytest.raises(ValueError): st.add("testmemb", 4)
    st.add("testmemb2", 1)
    assert st.size == 5
    st.add("testmemb3", 2)
    assert st.size == 7
    st.add("testmemb4", 8)
    assert st.size == 0xF
    st.add_varsize('testvar')
    assert st[0xF].name == 'testvar'
    assert st.size == 0xF
    BipStruct.delete("newStruct")
    st = BipStruct.create("newStruct")
    assert st.size == 0
    st.fill(0x10)
    assert st.size == 0x10
    assert st[0].name == 'field_0'
    assert st[0].size == 8
    st.fill(0x13)
    assert st.size == 0x13
    assert st[0x12].name == 'field_12'
    assert st[0x12].size == 1
    st.fill(0x20)
    assert st.size == 0x20
    st.add_varsize('testvar', comment="testcom")
    assert st[0x20].name == 'testvar'
    assert st[0x20].comment == 'testcom'
    BipStruct.delete("newStruct")


def test_bstructmember00():
    # base
    st = BipStruct.get("_UNWIND_HISTORY_TABLE")
    m = st[0]
    assert m._mid == 0xff0000000000629f
    assert BStructMember._is_this_elt(m._mid) == True
    assert BStructMember._is_this_elt(0x1800D3242) == False
    assert m.name == 'Count'
    m.name = "test"
    assert m.name == 'test'
    m.name = "Count"
    assert m.name == 'Count'
    assert m.fullname == '_UNWIND_HISTORY_TABLE.Count'
    assert m.size == 0x4
    assert m.offset == 0x0
    assert m.end_offset == 0x4
    m2 = st[4]
    assert m2.name == 'LocalHint'
    assert m2.offset == 0x4
    assert m2.end_offset == 0x5
    assert m2.size == 0x1
    assert str(m2) == 'Member: _UNWIND_HISTORY_TABLE.LocalHint (offset=0x4, size=0x1)'

def test_bstructmember01():
    # comments
    st = BipStruct.get("_UNWIND_HISTORY_TABLE")
    m = st[0]
    assert m.comment is None
    m.comment = "test"
    assert m.comment == 'test'
    assert m.rcomment is None
    m.rcomment = "test2"
    assert m.comment == 'test'
    assert m.rcomment == 'test2'
    m.comment = ""
    m.rcomment = None
    assert m.comment is None
    assert m.rcomment is None

def test_bstructmember02():
    # Types
    st = BipStruct.get("_UNWIND_HISTORY_TABLE")
    m = st[0]
    assert m.has_type == True
    assert m.type.str == 'DWORD'
    m.del_type()
    assert m.has_type == False
    with pytest.raises(RuntimeError): m.type
    m.type = "DWORD"
    assert m.has_type == True
    assert m.type.str == 'DWORD'
    assert m.is_nested == False
    with pytest.raises(RuntimeError): m.nested_struct
    m2 = st.member_by_name("Entry")
    assert m2.is_nested == True
    assert isinstance(m2.nested_struct, BipStruct)
    assert m2.nested_struct.name == 'UNWIND_HISTORY_TABLE_ENTRY'

def test_bstructmember03():
    # static method
    st = BipStruct.get("_UNWIND_HISTORY_TABLE")
    m = st[0]
    assert BStructMember._from_member_id(m._mid) == m
    assert BStructMember._is_member_id(m._mid) == True
    assert BStructMember._is_member_id(0x1800D3242) == False
    

def test_bstructmember04():
    st = BipStruct.create("newStruct")
    assert st.size == 0
    st.fill(0x10)
    assert st.size == 0x10
    assert st[0].size == 8
    st[0].size = 4
    assert st[0].size == 4
    with pytest.raises(IndexError): st[4]
    st.add(None, 4, offset=4)
    assert st[4].size == 4
    with pytest.raises(ValueError): st[0].size = 9
    with pytest.raises(RuntimeError): st[0].size = 8
    with pytest.raises(RuntimeError): st[0].size = 0
    BipStruct.delete("newStruct")
