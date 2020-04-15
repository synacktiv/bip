import sys
sys.path.append(r"E:\bip")

from bip.base import *

import idc
import ida_bytes

import pytest

"""
Test for classes in ``bip/base/instr.py``. This allows to test the
basic :class:`Instr` features.
"""


def test_bipinstr00():
    # constructor, ea, mnem, str, __str__
    assert Instr(0x01800D325A).ea == 0x01800D325A
    with pytest.raises(BipError):
        Instr(0x0180120800)
    assert GetElt(0x01800D325A).__class__ == Instr
    assert Instr(0x01800D325A).mnem == "add"
    assert Instr(0x01800D325A).mnem != "xadd"
    assert Instr(0x01800D325A).str == 'add     rsp, 60h'
    assert str(Instr(0x01800D325A)) == 'Instr: 0x1800D325A (add     rsp, 60h)'

def test_bipinstr01():
    # operands
    assert Instr(0x01800D325A).countOperand == 2
    assert len(Instr(0x01800D325A).ops) == 2
    assert Instr(0x01800D3269).countOperand == 0
    with pytest.raises(ValueError):
        Instr(0x01800D3269).op(0)
    assert Instr(0x01800D3268).countOperand == 1
    with pytest.raises(ValueError):
        Instr(0x01800D3269).op(1)
    assert Instr(0x01800D3268).op(0).str == 'rbx'
    assert Instr(0x01800D3268).ops[0].str == 'rbx'


def test_bipinstr02():
    # flags
    assert Instr(0x01800D325A).has_prev_instr == True
    assert Instr(0x01800D2FF0).has_prev_instr == False
    assert Instr(0x01800D326A).has_prev_instr == False
    assert Instr(0x01800D2FF0).is_call == False
    assert Instr(0x01800D327F).is_call == False
    assert Instr(0x01800D3011).is_call == True
    assert Instr(0x01800D31E8).is_call == False

    assert Instr(0x01800D324E).is_ret == False
    assert Instr(0x01800D3269).is_ret == True

    assert Instr(0x01800D3269).is_indirect_jmp == False
    assert Instr(0x01800D324E).is_indirect_jmp == False
    assert Instr(0x01800D323A).is_indirect_jmp == False
    assert Instr(0x01800D3240).is_indirect_jmp == False
    assert Instr(0x01800FF5D7).is_indirect_jmp == True

    assert Instr(0x01800D3269).is_end_block == True
    assert Instr(0x01800D324E).is_end_block == True
    assert Instr(0x01800D324B).is_end_block == False
    assert Instr(0x01800D3240).is_end_block == True
    assert Instr(0x01800D3253).is_end_block == True
    assert Instr(0x01800D322E).is_end_block == False

    assert Instr(0x01800D3269).is_end_block_call == True
    assert Instr(0x01800D324E).is_end_block_call == True
    assert Instr(0x01800D324B).is_end_block_call == False
    assert Instr(0x01800D3240).is_end_block_call == True
    assert Instr(0x01800D3253).is_end_block_call == True
    assert Instr(0x01800D322E).is_end_block_call == True

    assert Instr(0x01800D327F).is_in_func == True
    # TODO: add test for Instruction not in func (other binary)

def test_bipinstr03():
    # utils
    assert Instr(0x01800D325A).prev.ea == 0x01800D3253
    assert Instr(0x01800D325A).next.ea == 0x01800D325E
    assert Instr(0x01800D3269).next.ea == 0X01800D326A
    assert Instr(0x01800D327F).next is None

def test_bipinstr04():
    # func and block
    assert Instr(0x01800D6B33).func.ea == 0x01800D6B30
    assert Instr(0x01800D6B33).func.__class__ == BipFunction
    assert Instr(0x01800D323A).block.ea == 0x01800D3227
    assert Instr(0x01800D323A).block.__class__ == BipBlock
    # TODO: add test for instr not in func or block

def test_bipinstr05():
    # control flow
    assert Instr(0x01800D325A).xOrdinaryCfNext.ea == 0x01800D325E
    assert [x.ea for x in Instr(0x01800D325A).xCfNext] == [0x01800D325E]
    assert [x.ea for x in Instr(0x01800D325A).xCfPrev] == [0x01800D3253, 0x01800D3028]
    assert Instr(0x01800D3028).xOrdinaryCfNext is None
    assert [x.ea for x in Instr(0x01800D3028).xCfNext] == [0x01800D325A]
    assert [x.ea for x in Instr(0x01800D3028).xCfPrev] == [0x01800D3023]
    assert [x.ea for x in Instr(0x01800D324E).xCfNext] == [0x01800D3253, 0x01800D35E8]
    assert [x.ea for x in Instr(0x01800D323A).xCfNext] == [0x01800D323C, 0x01800D3242]

def test_bipinstr06():
    # cmp and hash
    assert BipElt(0x01800D325A) == Instr(0x01800D325A)
    assert Instr(0x01800D325A) == Instr(0x01800D325A)
    assert Instr(0x01800D325A) > Instr(0x01800D3028)
    assert Instr(0x01800D3028) < Instr(0x01800D325A)
    assert len([Instr(0x01800D325A), Instr(0x01800D325A)]) == 2
    assert len(set([Instr(0x01800D325A), Instr(0x01800D325A)])) == 1
    assert len(set([BipElt(0x01800D325A), Instr(0x01800D325A)])) == 2



