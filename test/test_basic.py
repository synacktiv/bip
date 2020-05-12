import sys
sys.path.append(r"E:\bip")

from bip.base import *

import idc
import ida_bytes

import pytest

# TODO:
#   * Operand
#   * xref
#   * struct
#   * utils

###################### BLOCK #########################

def test_block0():
    assert BipBlock(0x0180099990).ea == BipFunction(0x0180099990).ea

def test_block1():
    assert BipBlock(0x0180099990).ea == BipBlock(0x0180099992).ea

def test_block2():
    assert BipBlock(0x0180099990).type == BipBlockType.FCB_NORMAL

def test_block3():
    assert BipBlock(0x0180099990).is_ret == False

def test_block4():
    assert BipBlock(0x0180099990).is_noret == False

def test_block5():
    assert BipBlock(0x0180099990).is_external == False

def test_block6():
    assert BipBlock(0x01800999F0).type == BipBlockType.FCB_NORET

def test_block7():
    assert BipBlock(0x01800999F0).is_ret == False

def test_block8():
    assert BipBlock(0x01800999F0).is_noret == True

def test_block9():
    assert BipBlock(0x01800999F0).is_external == False

def test_blockA():
    assert BipBlock(0x0180099990).end == 0x01800999DC

def test_blockB():
    assert len(BipBlock(0x0180099990).succ) == 2

def test_blockC():
    ss = BipBlock(0x0180099990).succ
    assert ss[0].ea == 0x01800999DC
    assert ss[1].ea == 0x01800999F0

def test_blockD():
    b = BipBlock(0x0180099990)
    ss = b.succ
    i = 0
    for bb in b.succ_iter:
        assert ss[i].ea == bb.ea
        i += 1

def test_blockE():
    assert len(BipBlock(0x01800999E4).succ) == 1

def test_blockF():
    assert len(BipBlock(0x01800999F0).succ) == 0

def test_block10():
    assert len(BipBlock(0x01800999F0).pred) == 2

def test_block11():
    assert len(BipBlock(0x0180099990).pred) == 0

def test_block12():
    b = BipBlock(0x01800999F0)
    ss = b.pred
    i = 0
    for bb in b.pred_iter:
        assert ss[i].ea == bb.ea
        i += 1

def test_block13():
    assert BipBlock(0x01800999F0).func.ea == 0x0180099990

def test_block14():
    assert len(BipBlock(0x01800999DC).items) == 4

def test_block15():
    for i in BipBlock(0x01800999DC).items:
        assert i.__class__ == Instr

def test_block16():
    assert len(BipBlock(0x01800999DC).instr) == 4

def test_block17():
    for i in BipBlock(0x01800999DC).instr:
        assert i.__class__ == Instr

def test_block18():
    assert BipBlock(0x01800999DC).instr[-1].ea == 0x01800999EE

def test_block19():
    assert BipBlock(0x01800999DC).bytes == [0x48, 0x8D, 0x94, 0x24, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0xD2, 0xCE, 0xF6, 0xFF, 0x84, 0xDB]


