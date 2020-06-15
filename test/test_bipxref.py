from bip.base import *

import pytest

"""
    Test for class :class:`BipXref` in ``bip/base/bipxref.py``.
"""

def test_bipxref00():
    # base
    ins = GetElt(0x01800D3138) # recuperate from an instruction
    assert len(ins.xFrom) == 1
    assert isinstance(ins, Instr) == True
    xf = ins.xFrom[0]
    assert isinstance(xf, BipXref) == True
    assert xf.is_userdef == False
    assert xf.src_ea == 0x1800d3138
    assert xf.src.ea == 0x1800d3138
    assert xf.dst_ea == 0x1800d31e9
    assert xf.dst.ea == 0x1800d31e9
    assert isinstance(xf.src, Instr) == True
    assert isinstance(xf.dst, Instr) == True

def test_bipxref01():
    # code flow
    ins = GetElt(0x01800D3138)
    xf = ins.xFrom[0]
    assert xf.is_codepath == True
    assert xf.is_call == False
    assert xf.is_jmp == True
    assert xf.is_ordinaryflow == False
    assert xf.is_src_code == True
    assert xf.is_dst_code == True
    xf = ins.xTo[0]
    assert xf.is_codepath == True
    assert xf.is_call == False
    assert xf.is_jmp == False
    assert xf.is_ordinaryflow == True
    ins = GetElt(0x01800D322E)
    xf = ins.xFrom[1]
    assert xf.is_codepath == True
    assert xf.is_call == True
    assert xf.is_jmp == False
    assert xf.is_ordinaryflow == False
    ins = GetElt(0x01800D3227) # data xref
    xf = ins.xFrom[-1]
    assert xf.is_codepath == False
    assert xf.is_call == False
    assert xf.is_jmp == False
    assert xf.is_ordinaryflow == False
    assert xf.is_src_code == True
    assert xf.is_dst_code == False

def test_bipxref02():
    # data property
    ins = GetElt(0x01800D3138) # instr xref
    xf = ins.xFrom[0]
    assert xf.is_offset == False
    assert xf.is_write_access == False
    assert xf.is_read_access == False
    ins = GetElt(0x01800D3227) # data xref
    xf = ins.xFrom[-1]
    assert xf.is_offset == True
    assert xf.is_write_access == False
    assert xf.is_read_access == False
    ins = GetElt(0x01800D304F)
    xf = ins.xFrom[-1]
    assert xf.is_offset == False
    assert xf.is_write_access == False
    assert xf.is_read_access == True
    ins = GetElt(0x01800DF453)
    xf = ins.xFrom[-1]
    assert xf.is_offset == False
    assert xf.is_write_access == True
    assert xf.is_read_access == False




