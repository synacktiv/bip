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
        







