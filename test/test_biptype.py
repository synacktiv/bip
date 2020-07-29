from bip.base import *

import pytest
import tempfile
import os

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

def test_biptype09():
    # ptr
    ty = BipType.FromC("void *")
    assert isinstance(ty, BTypePtr) == True
    assert ty.str == "void *"
    assert ty.size == 8
    assert isinstance(ty.pointed, BTypeVoid)
    assert ty.is_pvoid == True
    assert ty.is_pfunc == False
    assert len(ty.childs) == 1
    ty = BipType.FromC("int *")
    assert ty.size == 8
    assert isinstance(ty.pointed, BTypeInt)
    assert ty.is_pvoid == False
    assert ty.is_pfunc == False
    assert len(ty.childs) == 1
    ty = BipType.FromC("void (*f)(int a);")
    assert ty.size == 8
    assert isinstance(ty.pointed, BTypeFunc)
    assert ty.is_pvoid == False
    assert ty.is_pfunc == True
    assert len(ty.childs) == 1

def test_biptype0A():
    # array
    ty = BipType.FromC("int[8]")
    assert isinstance(ty, BTypeArray) == True
    assert ty.str == "int[8]"
    assert ty.size == 0x20
    assert isinstance(ty.elt_type, BTypeInt)
    assert ty.nb_elts == 8
    assert len(ty.childs) == 1
    assert isinstance(ty.childs[0], BTypeInt)

def test_biptype0B():
    # func
    ty = BipType.FromC("int f(int a, void *b)")
    assert isinstance(ty, BTypeFunc) == True
    assert ty.str == "int __stdcall(int a, void *b)"
    assert ty.size is None
    assert ty.nb_args == 2
    assert ty.get_arg_name(0) == 'a'
    assert ty.get_arg_name(1) == 'b'
    with pytest.raises(IndexError): ty.get_arg_name(2)
    assert isinstance(ty.get_arg_type(0), BTypeInt)
    assert isinstance(ty.get_arg_type(1), BTypePtr)
    assert isinstance(ty.args_type, list)
    assert len(ty.args_type) == 2
    assert isinstance(ty.args_type[0], BTypeInt)
    assert isinstance(ty.args_type[1], BTypePtr)
    assert isinstance(ty.return_type, BTypeInt)
    assert len(ty.childs) == 3
    ty = BipType.FromC("int f(int)")
    assert ty.get_arg_name(0) == ''
    assert len(ty.args_type) == 1
    assert len(ty.childs) == 2

def test_biptype0C():
    # struct
    ty = BipType.FromC("_UNWIND_HISTORY_TABLE")
    assert isinstance(ty, BTypeStruct) == True
    assert ty.str == '_UNWIND_HISTORY_TABLE'
    assert ty.size == 0xd8
    assert ty.nb_members == 0x8
    assert ty.get_member_name(0) == 'Count'
    assert ty.get_member_name(1) == 'LocalHint'
    assert isinstance(ty.get_member_type(0), BTypeInt) == True
    assert isinstance(ty.get_member_type(1), BTypeInt) == True
    assert isinstance(ty.members_type, list) == True
    assert len(ty.members_type) == 8
    assert isinstance(ty.members_info, dict) == True
    assert len(ty.members_info) == 8
    assert isinstance(ty.members_info["Count"], BTypeInt) == True
    assert isinstance(ty.members_info["Entry"], BTypeArray) == True
    assert len(ty.childs) == 8

def test_biptype0D():
    # union
    ty = BipType.FromC("_SLIST_HEADER")
    assert isinstance(ty, BTypeUnion) == True
    assert ty.size == 0x10
    assert ty.str == '_SLIST_HEADER'
    assert ty.nb_members == 0x4
    assert isinstance(ty.get_member_type(1), BTypeStruct) == True
    assert ty.get_member_type(1).str == '_SLIST_HEADER::$3F637E9514009DECFE5B852E9243EE23'
    assert ty.get_member_type(0).str == '_SLIST_HEADER::$2AAD3A9E0F86A5BF9BE50654CA710F62'
    assert ty.get_member_name(0) == ''
    assert ty.get_member_name(3) == 'HeaderX64'
    assert ty.get_member_name(1) == 'Header8'
    assert isinstance(ty.members_type, list) == True
    assert len(ty.members_type) == 4
    assert isinstance(ty.members_info, dict) == True
    assert len(ty.members_info) == 4
    assert isinstance(ty.members_info["Header8"], BTypeStruct)
    assert len(ty.childs) == 4

def test_biptype0E():
    # enum
    be = BipEnum.create("testenum") # no enum per default, so create one
    assert be is not None
    ty = BipType.FromC("testenum")
    assert isinstance(ty, BTypeEnum) == True
    assert ty.size == 0x4
    assert ty.str == 'testenum'
    BipEnum.delete("testenum")

def test_biptype0F():
    # ImportCHeader
    fold = tempfile.mkdtemp()
    ptst0 = os.path.join(fold, "test0.h")
    f = open(ptst0, "w")
    f.write("struct testa { char a; int b;};\n")
    f.write("struct testb { int c; char d; char *e;};\n")
    f.write("enum testc { CA, CB};\n")
    f.close()
    BipType.ImportCHeader(ptst0)
    assert BipStruct.get("testa").size == 8
    BipType.ImportCHeader(ptst0, pack=1)
    assert BipStruct.get("testa").size == 5
    assert isinstance(BipStruct.get("testa"), BipStruct)
    assert isinstance(BipStruct.get("testb"), BipStruct)
    assert isinstance(BipEnum.get("testc"), BipEnum)
    BipType.ImportCHeader(ptst0, pack=2)
    assert BipStruct.get("testa").size == 6
    BipType.ImportCHeader(ptst0, pack=4)
    assert BipStruct.get("testa").size == 8
    BipType.ImportCHeader(ptst0, pack=8)
    assert BipStruct.get("testa").size == 0x8
    BipType.ImportCHeader(ptst0, pack=1)
    assert BipStruct.get("testa").size == 5
    BipType.ImportCHeader(ptst0, pack=0)
    assert BipStruct.get("testa").size == 0x8
    f = open(ptst0, "w")
    f.write("struct testd { char a; int b;};\n")
    f.close()
    BipType.ImportCHeader(ptst0, autoimport=False)
    with pytest.raises(ValueError): BipStruct.get("testd") # not automatically import, so this should fail
    f = open(ptst0, "w")
    f.write("struct teste { char a; int b;};\n")
    f.close()
    BipType.ImportCHeader(ptst0)
    with pytest.raises(ValueError): BipStruct.get("testd") # not automatically import, so this should fail
    assert isinstance(BipStruct.get("teste"), BipStruct)





