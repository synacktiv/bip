from bip.hexrays import *
from bip.base import *

import pytest

"""
    Test for class :class:`HxLvar` in ``bip/hexrays/hx_lvar.py``.
"""

def test_biphxlvar00():
    # base
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    lv1 = hxf.lvar_at(0)
    lv2 = hxf.lvar_at(2)
    assert isinstance(lv1, HxLvar)
    assert lv1.name == 'a1'
    assert isinstance(lv2, HxLvar)
    assert lv2.name == 'v2'
    assert lv1.has_user_name == False
    assert lv2.has_user_name == False
    lv1.name = "newname"
    assert lv1.name == "newname"
    assert lv1.has_user_name == True
    assert lv2.has_user_name == False
    lv1.name = "newname"
    assert lv1.name == "newname"
    hxf.invalidate_cache() # check for the save
    assert lv1.name == "newname"
    assert lv1.has_user_name == True
    assert lv2.has_user_name == False
    lv2.name = "newname2"
    assert lv2.name == 'newname2'
    assert lv1.size == 8
    assert lv2.size == 8 
    assert lv1.hxfunc == hxf
    assert lv2.hxfunc == hxf
    assert lv1.comment == ""
    assert lv2.comment == ""
    lv1.comment = "new comment"
    assert lv1.comment == "new comment"
    assert lv2.comment == ""
    lv2.comment = "new comment2"
    assert lv1.comment == "new comment"
    assert lv2.comment == "new comment2"
    lv1.comment = ""
    lv2.comment = ""
    assert lv1.comment == ""
    assert lv2.comment == ""
    assert isinstance(lv1.type, BipType)
    assert isinstance(lv2.type, BipType)
    assert isinstance(lv1.type, BTypeInt)
    assert isinstance(lv2.type, BTypePtr)
    assert lv1.has_user_type == False
    assert lv2.has_user_type == False
    lv1.type = BipType.FromC("__int16 *")
    assert isinstance(lv1.type, BTypePtr)
    assert lv1.size == 8
    lv1.type = "__int64"
    assert isinstance(lv1.type, BTypeInt)
    assert lv1.size == 8
    lv1.type = "char"
    assert isinstance(lv1.type, BTypeInt)
    assert lv1.size == 1
    assert lv1.has_user_type == True
    assert lv2.has_user_type == False
    with pytest.raises(TypeError): lv1.type = 8
    with pytest.raises(RuntimeError): lv1.type = "void"

def test_biphxlvar01():
    # flags
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    lv1 = hxf.lvar_at(0)
    lv2 = hxf.lvar_at(2)
    lvstck = hxf.lvar_at(13)
    assert lv1.is_arg == True
    assert lv2.is_arg == False
    assert lvstck.is_arg == False
    assert lv1.is_reg == True
    assert lv2.is_reg == True
    assert lvstck.is_reg == False
    assert lv1.is_stk == False
    assert lv2.is_stk == False
    assert lvstck.is_stk == True
    assert lvstck.has_user_name == False # also tested in 00
    assert lvstck.has_user_type == False # also tested in 00

def test_biphxlvar02():
    # cmp
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    lv1 = hxf.lvar_at(0)
    lv1_bis = hxf.lvar_at(0)
    lv2 = hxf.lvar_at(2)
    assert lv1 != lv2
    assert not (lv1 == lv2)
    assert lv1 == lv1
    assert lv1 == lv1_bis
    assert lv1.__eq__(3) == NotImplemented
    assert lv1.__ne__(3) == NotImplemented
    assert lv1 != 3


