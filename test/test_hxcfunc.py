from bip.hexrays import *
from bip.base import BipDecompileError, BipFunction, BipInstr

import idc

import pytest

"""
    Test for basics in class :class:`HxCFunc` in ``bip/hexrays/hx_cfunc.py``.
    This do not include test for visitor, cnodes and hxitem.
"""

def test_biphxcfunc00():
    # hxcfunc base, other and class methods
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    assert isinstance(hxf, HxCFunc)
    assert hxf.ea == 0x01800D2FF0
    assert isinstance(BipFunction(0x01800D2FF0).hxcfunc, HxCFunc)
    assert hxf.ea == BipFunction(0x01800D2FF0).hxcfunc.ea
    hxf = HxCFunc.from_addr(0x01800D2FF7)
    assert isinstance(hxf, HxCFunc)
    assert hxf.ea == 0x01800D2FF0
    assert hxf.bfunc == BipFunction(0x01800D2FF0)
    assert isinstance(hxf.cstr, str)
    with pytest.raises(BipDecompileError): HxCFunc.from_addr(0x018012D400)
    with pytest.raises(BipDecompileError): HxCFunc.from_addr(idc.BADADDR)
    hxf.invalidate_cache() # just check it exist and do not raise an exception
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    HxCFunc.invalidate_all_caches() # same as before
    hxf2 = next(HxCFunc.iter_all())
    assert isinstance(hxf2, HxCFunc)
    assert hxf2.ea == 0x180001010

def test_biphxcfunc01():
    # cmp
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    hxf2 = HxCFunc.from_addr(0x01800D2FF7)
    hxf3 = HxCFunc.from_addr(0x01800DDDA0)
    assert hxf == hxf2
    assert hxf != hxf3
    assert (hxf == hxf3) == False
    assert hxf == BipFunction(0x01800D2FF0)
    assert hxf != BipFunction(0x01800DDDA0)
    assert hxf.__eq__("test") == NotImplemented
    assert hxf.__ne__("test") == NotImplemented
    assert hxf != "test"

def test_biphxcfunc02():
    # comment
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    assert hxf.get_cmt(0x01800D322E) is None
    hxf.add_cmt(0x01800D322E, "newcmt")
    assert hxf.get_cmt(0x01800D322E) == "newcmt"
    hxf.add_cmt(0x01800D322E, "newcmt2")
    assert hxf.get_cmt(0x01800D322E) == "newcmt2"


def test_biphxcfunc03():
    # lvars access
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    assert isinstance(hxf.lvar_at(0), HxLvar)
    assert isinstance(hxf.lvars, list)
    count = 0
    for lv in hxf.lvars_iter():
        assert isinstance(lv, HxLvar)
        lv2 = hxf.lvars[count]
        assert isinstance(lv2, HxLvar)
        assert lv == lv2
        count += 1
    assert isinstance(hxf.lvar_by_name("a1"), HxLvar)
    assert hxf.lvar_by_name("donotexist") is None
    assert isinstance(hxf.args, list)
    assert len(hxf.args) == 1
    assert isinstance(hxf.args[0], HxLvar)

def test_biphxcfunc04():
    # root_node and hx_root_stmt
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    assert hxf.root_node is not None
    assert isinstance(hxf.root_node, CNodeStmtBlock)
    assert hxf.root_node.hxcfunc == hxf
    assert hxf.hx_root_stmt is not None
    assert isinstance(hxf.hx_root_stmt, HxCStmtBlock)

def test_biphxcfunc05():
    # static methods
    assert HxCFunc.get(HxCFunc.from_addr(0x01800D2FF0)).ea == 0x01800D2FF0
    assert HxCFunc.get(0x01800D2FF0).ea == 0x01800D2FF0
    assert HxCFunc.get("RtlQueryProcessLockInformation").ea == 0x01800D2FF0
    assert HxCFunc.get(BipFunction(0x01800D2FF0)).ea == 0x01800D2FF0
    assert HxCFunc.get(BipInstr(0x01800D2FF0)).ea == 0x01800D2FF0





