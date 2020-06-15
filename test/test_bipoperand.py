from bip.base import *

import pytest

"""
    Test for class :class:`BipOperand` in ``bip/base/bipoperand.py``.
"""

def test_bipoperand00():
    # base
    elt = GetElt(0x01800D324B)
    assert isinstance(elt.op(0), Operand) == True
    assert elt.op(0).ea == 0x1800d324b
    assert elt.op(0).instr == elt
    assert elt.op(0).opnum == 0
    assert elt.op(0).str == 'rcx'
    assert elt.op(0).type == OpType.REG
    assert elt.op(0).dtype == 7
    assert elt.op(0).type_info is None
    elt.op(0).type_info = "void *"
    assert isinstance(elt.op(0).type_info, BTypePtr) == True
    del elt.op(0).type_info
    assert elt.op(0).type_info is None
    assert elt.op(0).value == 0x1
    elt = GetElt(0x01800D3242)
    assert elt.op(1).opnum == 1
    assert elt.op(1).value == 0x8
    assert elt.op(1).dtype == 0x2
    assert elt.op(1).type == OpType.IMM
    assert GetElt(0x01800D3094).op(1).value == 0xc0000017

def test_bipoperand01():
    # test type
    assert GetElt(0x01800D314C).op(0).is_void == False # reg
    assert GetElt(0x01800D314C).op(0).is_reg == True
    assert GetElt(0x01800D314C).op(0).is_memref == False
    assert GetElt(0x01800D314C).op(0).is_imm == False
    assert GetElt(0x01800D314C).op(0).is_addr == False
    assert GetElt(0x01800D314C).op(0).is_proc_specific == False

    assert GetElt(0x01800D3094).op(1).is_void == False # imm
    assert GetElt(0x01800D3094).op(1).is_reg == False
    assert GetElt(0x01800D3094).op(1).is_memref == False
    assert GetElt(0x01800D3094).op(1).is_imm == True
    assert GetElt(0x01800D3094).op(1).is_addr == False
    assert GetElt(0x01800D3094).op(1).is_proc_specific == False

    assert GetElt(0x01800D314C).op(1).is_void == False # memref
    assert GetElt(0x01800D314C).op(1).is_reg == False
    assert GetElt(0x01800D314C).op(1).is_memref == True
    assert GetElt(0x01800D314C).op(1).is_imm == False
    assert GetElt(0x01800D314C).op(1).is_addr == False
    assert GetElt(0x01800D314C).op(1).is_proc_specific == False

    assert GetElt(0x01800D31DD).op(0).is_void == False # addr
    assert GetElt(0x01800D31DD).op(0).is_reg == False
    assert GetElt(0x01800D31DD).op(0).is_memref == False
    assert GetElt(0x01800D31DD).op(0).is_imm == False
    assert GetElt(0x01800D31DD).op(0).is_addr == True
    assert GetElt(0x01800D31DD).op(0).is_proc_specific == False

    # TODO: other binary for is_proc_specific

# TODO: set_offset




