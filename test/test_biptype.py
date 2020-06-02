from bip.base import *

import pytest

from ida_typeinf import tinfo_t

"""
    Test for classes in ``bip/base/biptype.py``, :class:`BipType` and
    inherited classes.
"""

def test_biptype00():
    # bip type base
    assert isinstance(BipType.FromC("int"), BipType)
    with pytest.raises(RuntimeError): BipType.FromC("DoNotExist")
    tint = BipType.FromC("int")
    assert tint.size == 0x4
    assert tint.str == 'int'
    assert tint.is_named == False
    assert tint.name is None
    tstru = BipType.FromC("_UNWIND_HISTORY_TABLE")
    assert tstru.str == '_UNWIND_HISTORY_TABLE'
    assert tstru.size == 0xd8
    assert tstru.is_named == True
    assert tstru.name == '_UNWIND_HISTORY_TABLE'

def test_biptype01():
    # equality
    tint = BipType.FromC("int")
    tintp = BipType.FromC("int *")
    assert tint == BipType.FromC("int")
    assert tint != BipType.FromC("_UNWIND_HISTORY_TABLE")
    assert tint != tintp
    assert tint == tintp.pointed

def test_biptype02():
    # general get/set
    assert BipType.is_set_at(0x018011B7E0) == False
    assert BipType.get_at(0x018011B7E0) == None
    assert BipType.is_set_at(0x018013F000) == False
    assert isinstance(BipType.get_at(0x018013F000), BipType) == True
    assert BipType.get_at(0x018013F000).str == 'UNWIND_INFO_HDR'
    BipType.FromC("void *").set_at(0x018013F000)
    assert BipType.is_set_at(0x018013F000) == True
    assert isinstance(BipType.get_at(0x018013F000), BipType) == True
    assert BipType.get_at(0x018013F000).str == 'void *'
    BipType.FromC("UNWIND_INFO_HDR").set_at(0x018013F000)
    assert BipType.is_set_at(0x018013F000) == True
    BipType.del_at(0x018013F000)
    assert BipType.is_set_at(0x018013F000) == False
    assert BipType.get_at(0x018013F000).str == 'UNWIND_INFO_HDR'

def test_biptype03():
    # childs (basic)
    tint = BipType.FromC("int")
    tintp = BipType.FromC("int *")
    assert tint.childs == []
    assert len(tintp.childs) == 1
    assert isinstance(tintp.childs[0], BipType)

def test_biptype04():
    # object creation
    #   most of this is tested directly by the FromC method
    tint = BipType.FromC("int")
    assert isinstance(tint, BipType)
    assert isinstance(BipType.FromC("int;"), BipType)
    assert BipType.FromC("int;") == tint
    assert isinstance(BipType.FromC("int *;"), BipType)
    assert BipType.is_handling_type(tint._tinfo) == False
    ti = tint._get_tinfo_copy()
    assert isinstance(ti, tinfo_t)
    assert BipType._GetClassBipType(ti) == BTypeInt
    assert isinstance(BipType.GetBipTypeNoCopy(ti), BipType)
    assert isinstance(BipType.GetBipTypeNoCopy(ti), BTypeInt)
    assert id(BipType.GetBipTypeNoCopy(ti)._tinfo) == id(ti)
    assert id(BipType.GetBipType(ti)._tinfo) != id(ti)
    assert BipType.GetBipType(ti)._tinfo == ti

def test_biptype05():
    # empty, partial and void
    ti = tinfo_t()
    assert BTypeEmpty.is_handling_type(ti)
    assert BipType._GetClassBipType(ti) == BTypeEmpty
    assert BipType.GetBipTypeNoCopy(ti).str == '?'
    assert BipType.GetBipTypeNoCopy(ti).size is None
    # partial
    ti = tinfo_t()
    ti.create_simple_type(0x11)
    assert BTypeEmpty.is_handling_type(ti) == False
    assert BTypePartial.is_handling_type(ti)
    assert BipType._GetClassBipType(ti) == BTypePartial
    assert BipType.GetBipTypeNoCopy(ti).str == '_BYTE'
    assert BipType.GetBipTypeNoCopy(ti).size == 1
    # void
    ti = tinfo_t()
    ti.create_simple_type(0x1)
    assert BTypeEmpty.is_handling_type(ti) == False
    assert BTypePartial.is_handling_type(ti) == False
    assert BTypeVoid.is_handling_type(ti)
    assert BipType._GetClassBipType(ti) == BTypeVoid
    assert BipType.GetBipTypeNoCopy(ti).str == 'void'

def test_biptype06():
    # int
    assert isinstance(BipType.FromC("__int8"), BTypeInt) == True
    assert BipType.FromC("__int8").size == 0x1
    assert BipType.FromC("__int8").is_signed == True
    assert BipType.FromC("__int8").is_unsigned == False
    assert BipType.FromC("__int8").str == '__int8'
    assert BipType.FromC("__int8").childs == []
    assert BipType.FromC("unsigned __int16").size == 0x2
    assert BipType.FromC("unsigned __int16").is_signed == False
    assert BipType.FromC("unsigned __int16").is_unsigned == True
    assert isinstance(BipType.FromC("unsigned __int16"), BTypeInt) == True
    assert isinstance(BipType.FromC("unsigned __int32"), BTypeInt) == True
    assert BipType.FromC("unsigned __int32").size == 0x4
    assert BipType.FromC("unsigned __int64").size == 0x8
    assert isinstance(BipType.FromC("unsigned __int64"), BTypeInt) == True

def test_biptype07():
    # bool
    assert isinstance(BipType.FromC("bool"), BTypeBool) == True
    assert BipType.FromC("bool").size == 0x1
    assert BipType.FromC("bool").str == 'bool'
    assert BipType.FromC("bool").childs == []

def test_biptype08():
    # float
    assert isinstance(BipType.FromC("float"), BTypeFloat) == True
    assert BipType.FromC("float").str == 'float'
    assert BipType.FromC("float").size == 0x4
    assert isinstance(BipType.FromC("double"), BTypeFloat) == True
    assert BipType.FromC("double").size == 0x8
    assert BipType.FromC("double").str == 'double'
    assert BipType.FromC("double").childs == []
    assert BipType.FromC("float").childs == []

# TODO: From BTypePtr and after













