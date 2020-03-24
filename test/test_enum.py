import sys
sys.path.append(r"E:\bip")
import pytest

from bip.base import *

import idc
import ida_bytes


def test_bipenum1():
    # create
    be = BipEnum.create("testenum")
    assert be is not None
    assert isinstance(be, BipEnum)
    # get
    be2 = BipEnum.get("testenum")
    assert be is not None
    assert isinstance(be, BipEnum)
    # equality
    assert be == be2
    assert (be != be2) == False
    assert be == be._eid
    assert be != 0
    assert be != idc.BADADDR
    # _is_this_elt
    assert BipEnum._is_this_elt(be._eid) == True
    assert BipEnum._is_this_elt(0) == False
    with pytest.raises(TypeError):
       BipEnum._is_this_elt(None)
    assert BipEnum._is_this_elt(idc.BADADDR) == False
    assert BipEnum._is_this_elt(0x01800F1C60) == False
    # name
    assert be.name == "testenum"
    be.name = "testenum_newname"
    assert be.name == "testenum_newname"
    be.name = "testenum"
    # width
    assert be.width == 0
    be.width = 4
    assert be.width == 4
    with pytest.raises(ValueError):
        be.width = 5
    assert be.width == 4
    # bitfield
    assert be.is_bitfield == False
    be.is_bitfield = True
    assert be.is_bitfield == True
    be.is_bitfield = False
    assert be.is_bitfield == False
    # __str__
    str(be)
    # comment
    assert be.comment is None
    assert be.rcomment is None
    be.comment = "hello"
    be.rcomment = "hello2"
    assert be.comment == "hello"
    assert be.rcomment == "hello2"
    BipEnum.delete("testenum")

def test_bipenum2():
    # create, get, delete
    be = BipEnum.create("testenum")
    BipEnum.delete("testenum")
    with pytest.raises(ValueError):
        BipEnum.get("testenum")
    be = BipEnum.create("testenum2")
    BipEnum.delete(be)
    with pytest.raises(ValueError):
        BipEnum.get("testenum2")
    be = BipEnum.create("testenum3")
    with pytest.raises(ValueError):
        be2 = BipEnum.create("testenum3")
    BipEnum.delete(be._eid)
    with pytest.raises(ValueError):
        BipEnum.get("testenum3")

def test_bipenum3():
    # creating, accessing and deleting members
    be = BipEnum.create("testenum")
    assert be.nb_members == 0
    be.add("testmem", 0x10)
    assert be.nb_members == 1
    bem = be.member_by_name("testmem")
    assert bem is not None
    assert isinstance(bem, BEnumMember)
    assert bem.name == "testmem"
    assert bem.value == 0x10
    assert bem == be["testmem"]
    beml = be.members_by_value(0x10)
    assert len(beml) == 1
    assert beml[0] == bem
    with pytest.raises(RuntimeError):
        be.add("testmem", 0x11)
    be.add("testmem2", 0x10)
    beml = be.members_by_value(0x10)
    assert len(beml) == 2
    assert beml[0] != beml[1]
    be.add("testmem3", 0x10)
    be.add("testmem4", 0x1)
    assert be.nb_members == 4
    be.del_member("testmem2")
    assert be.nb_members == 3
    with pytest.raises(ValueError):
        be.del_member("testmem2")
    beml = be.members_by_value(0x10)
    assert len(beml) == 2
    assert beml[0] != beml[1]
    assert "testmem3" in [m.name for m in beml]
    assert "testmem4" not in [m.name for m in beml]
    assert len(be.members) == 3
    for m in be:
        str(m)
    BipEnum.delete("testenum")

def test_bipenum4():
    # members
    be = BipEnum.create("testenum")
    assert be.nb_members == 0
    be.add("testmem", 0x10)
    assert be.nb_members == 1
    bem = be.member_by_name("testmem")
    bem2 = BEnumMember.get("testmem")
    assert bem == bem2
    assert bem.name == "testmem"
    assert bem.value == 0x10
    bem.name = "newname"
    assert bem.name == "newname"
    assert bem2.name == "newname"
    assert bem2.enum == be
    assert bem2.value == 0x10
    bem.name = "testmem"
    assert bem.name == "testmem"
    assert bem.comment is None
    assert bem.rcomment is None
    bem.comment = "hello"
    bem.rcomment = "test rcom"
    assert bem.comment == "hello"
    assert bem.rcomment == "test rcom"
    BipEnum.delete("testenum")



