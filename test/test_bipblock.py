from bip.base import *

import pytest

"""
Test for class :class:`BipBlock` in ``bip/base/bipblock.py``.
"""



def test_bipblock00():
    # base
    assert BipBlock(0x0180099990).ea == BipFunction(0x0180099990).ea
    assert BipBlock(0x0180099990).ea == BipBlock(0x0180099992).ea
    assert BipBlock(0x0180099990).end == 0x01800999DC
    with pytest.raises(TypeError): BipBlock("AString")
    with pytest.raises(ValueError): BipBlock(0x10) # invalid addr
    assert str(BipBlock(0x0180099990)) == 'BipBlock: 0x180099990 (from Func: RtlRaiseStatus (0x180099990))'
    assert isinstance(BipFunction(0x0180099990).blocks[0], BipBlock) == True
    assert BipFunction(0x0180099990).blocks[0].ea == 0x180099990

def test_bipblock01():
    # Type & info
    assert BipBlock(0x0180099990).type == BipBlockType.FCB_NORMAL
    assert BipBlock(0x0180099990).is_ret == False
    assert BipBlock(0x0180099990).is_noret == False
    assert BipBlock(0x0180099990).is_external == False
    assert BipBlock(0x01800999F0).type == BipBlockType.FCB_NORET
    assert BipBlock(0x01800999F0).is_ret == False
    assert BipBlock(0x01800999F0).is_noret == True
    assert BipBlock(0x01800999F0).is_external == False

def test_bipblock02():
    # control flow
    assert len(BipBlock(0x0180099990).succ) == 2
    ss = BipBlock(0x0180099990).succ
    assert isinstance(ss[0], BipBlock)
    assert ss[0].ea == 0x01800999DC
    assert ss[1].ea == 0x01800999F0
    b = BipBlock(0x0180099990)
    ss = b.succ
    i = 0
    for bb in b.succ_iter:
        assert ss[i].ea == bb.ea
        i += 1
    assert len(BipBlock(0x01800999E4).succ) == 1
    assert len(BipBlock(0x01800999F0).succ) == 0
    assert len(BipBlock(0x01800999F0).pred) == 2
    assert len(BipBlock(0x0180099990).pred) == 0
    b = BipBlock(0x01800999F0)
    ss = b.pred
    i = 0
    for bb in b.pred_iter:
        assert ss[i].ea == bb.ea
        i += 1

def test_bipblock03():
    # func, instr, items, bytes
    assert isinstance(BipBlock(0x01800999F0).func, BipFunction)
    assert BipBlock(0x01800999F0).func.ea == 0x0180099990
    assert len(BipBlock(0x01800999DC).items) == 4
    for i in BipBlock(0x01800999DC).items:
        assert i.__class__ == Instr
    assert len(BipBlock(0x01800999DC).instr) == 4
    for i in BipBlock(0x01800999DC).instr:
        assert i.__class__ == Instr
    assert BipBlock(0x01800999DC).instr[-1].ea == 0x01800999EE
    assert BipBlock(0x01800999DC).bytes == [0x48, 0x8D, 0x94, 0x24, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0xD2, 0xCE, 0xF6, 0xFF, 0x84, 0xDB]


def test_bipblock04():
    # color
    assert BipBlock(0x0180099990).color == 0xffffffff
    BipBlock(0x0180099990).color = 0xaabbcc
    assert BipBlock(0x0180099990).color == 0xaabbcc
    BipBlock(0x0180099990).color = None
    assert BipBlock(0x0180099990).color == 0xffffffff
    BipBlock(0x0180099990).color = 0xaabbcc
    assert BipBlock(0x0180099990).color == 0xaabbcc
    del BipBlock(0x0180099990).color
    assert BipBlock(0x0180099990).color == 0xffffffff
    with pytest.raises(TypeError): BipBlock(0x0180099990).color = "abcd"







