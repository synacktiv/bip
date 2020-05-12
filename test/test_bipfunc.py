import sys
sys.path.append(r"E:\bip")

from bip.base import *
from bip.hexrays import HxCFunc

import pytest

"""
Test for classes in ``bip/base/func.py``. This allows to test the
basic :class:`BipFunction` features.
"""

def test_bipfunc00():
    # constructor, ea, end, size, name, demangle_name, flag for the names
    #   ordinal and str repr
    assert BipFunction(0x01800D6B30).ea == BipFunction(0x01800D6B39).ea
    assert BipFunction(0x01800D6B30).ea == 0x01800D6B30
    assert BipFunction(0x01800D6B30).end == 0x01800D6B43
    assert BipFunction(0x01800D6B30).size == 0x13
    assert BipFunction(0x01800D6B30).name == "RtlWow64SetThreadContext"
    BipFunction(0x01800D6B30).name = "test"
    assert BipFunction(0x01800D6B30).name == 'test'
    BipFunction(0x01800D6B30).name = None
    assert BipFunction(0x01800D6B30).name == 'sub_1800D6B30'
    BipFunction(0x01800D6B30).name = 'RtlWow64SetThreadContext'
    assert BipFunction(0x01800D6B30).name == 'RtlWow64SetThreadContext'
    BipFunction(0x01800D6B30).name = ""
    assert BipFunction(0x01800D6B30).name == 'sub_1800D6B30'
    assert BipFunction(0x01800D6B30).is_dummy_name == True
    assert BipFunction(0x01800D6B30).is_auto_name == False
    assert BipFunction(0x01800D6B30).is_ida_name == True
    assert BipFunction(0x01800D6B30).is_user_name == False
    BipFunction(0x01800D6B30).name = 'RtlWow64SetThreadContext'
    assert BipFunction(0x01800D6B30).name == 'RtlWow64SetThreadContext'
    assert BipFunction(0x01800D6B30).is_dummy_name == False
    assert BipFunction(0x01800D6B30).is_auto_name == False
    assert BipFunction(0x01800D6B30).is_ida_name == False
    assert BipFunction(0x01800D6B30).is_user_name == True
    assert BipFunction(0x01800D6B30).demangle_name is None
    # TODO: need test for C++ with valid demangle_name
    assert BipFunction(0x01800D6B30).truename == 'RtlWow64SetThreadContext'
    # TODO need test where truename is different of name
    assert BipFunction(0x01800D6B30).ordinal == 0xb8b
    assert BipFunction.ByOrdinal(BipFunction(0x01800D6B30).ordinal).ea == 0x01800D6B30
    assert str(BipFunction(0x01800D6B30)) ==  'Func: RtlWow64SetThreadContext (0x1800D6B30)'

def test_bipfunc01():
    # cmd, hash and contains
    assert BipFunction(0x01800D6B30) == BipFunction(0x01800D6B39)
    assert BipFunction(0x01800D6B30) != BipFunction(0x01800D6B1B)
    assert BipFunction(0x01800D6B30) != GetElt(0x018011F7F0)
    assert len(set([BipFunction(0x01800D6B30), BipFunction(0x01800D6B30)])) == 1
    assert len(set([BipFunction(0x01800D6B30), BipFunction(0x01800D6B1B)])) == 2
    assert len(set([BipFunction(0x01800D6B30), GetElt(0x01800D6B30)])) == 2
    assert GetElt(0x01800D6B30) in BipFunction(0x01800D6B30)
    assert GetElt(0x01800D6B39) in BipFunction(0x01800D6B30)
    assert GetElt(0x01800D6B1B) not in BipFunction(0x01800D6B30)
    assert GetElt(0x018011F7F0) not in BipFunction(0x01800D6B30)
    assert BipFunction(0x01800D6B30).blocks[0] in BipFunction(0x01800D6B30)
    assert BipFunction(0x01800D6B1B).blocks[0] not in BipFunction(0x01800D6B30)
    assert 0x01800D6B39 in BipFunction(0x01800D6B30)
    assert 0x01800D6B1B not in BipFunction(0x01800D6B30)
    with pytest.raises(TypeError): "test" in BipFunction(0x01800D6B30)


def test_bipfunc02():
    # hexray interface
    assert BipFunction(0x01800D2FF0).can_decompile == True
    assert isinstance(BipFunction(0x01800D2FF0).hxfunc, HxCFunc)
    assert BipFunction(0x01800D2FF0).hxfunc.bfunc == BipFunction(0x01800D2FF0)
    # TODO: test for decompilation failure

def test_bipfunc03():
    # flags & info
    assert BipFunction(0x01800D2FF0).flags == 0x5400
    BipFunction(0x01800D2FF0).flags = 0
    assert BipFunction(0x01800D2FF0).flags == 0x0
    BipFunction(0x01800D2FF0).flags = 0x5400
    assert BipFunction(0x01800D2FF0).flags == 0x5400
    assert BipFunction(0x01800D2FF0).does_return == True
    BipFunction(0x01800D2FF0).does_return = False
    assert BipFunction(0x01800D2FF0).does_return == False
    BipFunction(0x01800D2FF0).does_return = True
    assert BipFunction(0x01800D2FF0).does_return == True
    assert BipFunction(0x0180071490).does_return == False
    assert BipFunction(0x01800D2FF0).is_far == False
    BipFunction(0x01800D2FF0).is_far = True
    assert BipFunction(0x01800D2FF0).is_far == True
    BipFunction(0x01800D2FF0).is_far = False
    assert BipFunction(0x01800D2FF0).is_far == False
    assert BipFunction(0x01800D2FF0).is_lib == False
    BipFunction(0x01800D2FF0).is_lib = True
    assert BipFunction(0x01800D2FF0).is_lib == True
    BipFunction(0x01800D2FF0).is_lib = False
    assert BipFunction(0x01800D2FF0).is_lib == False
    assert BipFunction(0x01800D2FF0).is_static == False
    BipFunction(0x01800D2FF0).is_static = True
    assert BipFunction(0x01800D2FF0).is_static == True
    BipFunction(0x01800D2FF0).is_static = False
    assert BipFunction(0x01800D2FF0).is_static == False
    assert BipFunction(0x01800D2FF0).use_frame == False
    BipFunction(0x01800D2FF0).use_frame = True
    assert BipFunction(0x01800D2FF0).use_frame == True
    BipFunction(0x01800D2FF0).use_frame = False
    assert BipFunction(0x01800D2FF0).use_frame == False
    assert BipFunction(0x01800D2FF0).is_userfar == False
    BipFunction(0x01800D2FF0).is_userfar = True
    assert BipFunction(0x01800D2FF0).is_userfar == True
    BipFunction(0x01800D2FF0).is_userfar = False
    assert BipFunction(0x01800D2FF0).is_userfar == False
    assert BipFunction(0x01800D2FF0).is_hidden == False
    BipFunction(0x01800D2FF0).is_hidden = True
    assert BipFunction(0x01800D2FF0).is_hidden == True
    BipFunction(0x01800D2FF0).is_hidden = False
    assert BipFunction(0x01800D2FF0).is_hidden == False
    assert BipFunction(0x01800D2FF0).is_thunk == False
    BipFunction(0x01800D2FF0).is_thunk = True
    assert BipFunction(0x01800D2FF0).is_thunk == True
    BipFunction(0x01800D2FF0).is_thunk = False
    assert BipFunction(0x01800D2FF0).is_thunk == False
    assert BipFunction(0x01800D6B30).is_inside(GetElt(0x01800D6B30))
    assert BipFunction(0x01800D6B30).is_inside(GetElt(0x01800D6B39))
    assert BipFunction(0x01800D6B30).is_inside(GetElt(0x01800D6B1B)) == False
    assert BipFunction(0x01800D6B30).is_inside(GetElt(0x018011F7F0)) == False
    assert BipFunction(0x01800D6B30).is_inside(0x01800D6B39)
    assert BipFunction(0x01800D6B30).is_inside(0x01800D6B1B) == False
    with pytest.raises(TypeError): BipFunction(0x01800D6B30).is_inside("test")

def test_bipfunc04():
    # comment
    assert BipFunction(0x01800D2FF0).comment == ""
    assert BipFunction(0x01800D2FF0).rcomment == ""
    BipFunction(0x01800D2FF0).comment = "test"
    BipFunction(0x01800D2FF0).rcomment = "test2"
    assert BipFunction(0x01800D2FF0).comment == "test"
    assert BipFunction(0x01800D2FF0).rcomment == "test2"
    BipFunction(0x01800D2FF0).comment = None
    BipFunction(0x01800D2FF0).rcomment = None
    assert BipFunction(0x01800D2FF0).comment == ""
    assert BipFunction(0x01800D2FF0).rcomment == ""
    BipFunction(0x01800D2FF0).comment = "test"
    BipFunction(0x01800D2FF0).rcomment = "test2"
    BipFunction(0x01800D2FF0).comment = ""
    BipFunction(0x01800D2FF0).rcomment = ""
    assert BipFunction(0x01800D2FF0).comment == ""
    assert BipFunction(0x01800D2FF0).rcomment == ""

def test_bipfunc05():
    # basic blocks
    assert BipFunction(0x01800D324E).nb_blocks == 0x21
    assert len(BipFunction(0x01800D324E).blocks) == 0x21
    assert BipFunction(0x01800D324E).blocks[0].ea == 0x1800d2ff0
    assert isinstance(BipFunction(0x01800D324E).blocks[0], BipBlock)
    assert len([b for b in BipFunction(0x01800D324E).blocks_iter]) == 0x21
    assert BipFunction(0x0180099990).nb_blocks == 3
    blck = BipFunction(0x0180099990).blocks
    assert blck[0].ea == 0x0180099990
    assert blck[1].ea == 0x01800999DC
    assert blck[2].ea == 0x01800999F0
    f = BipFunction(0x0180099990)
    blck = f.blocks
    i = 0
    for b in f.blocks_iter:
        assert blck[i].ea == b.ea
        assert blck[i].end == b.end
        i += 1

def test_bipfunc06():
    # items & instr
    assert len(BipFunction(0x01800D324E).items) == 0xa5
    assert len(BipFunction(0x01800D324E).instr) == 0xa5
    assert len([i for i in BipFunction(0x01800D324E).instr_iter]) == 0xa5
    assert len(BipFunction(0x01800D324E).bytes) == 0x294
    assert isinstance(BipFunction(0x01800D324E).items[0], Instr) == True
    assert isinstance(BipFunction(0x01800D324E).instr[0], Instr) == True
    assert isinstance(BipFunction(0x01800D324E).instr_iter.next(), Instr) == True
    assert isinstance(BipFunction(0x01800D324E).bytes, list) == True
    assert isinstance(BipFunction(0x01800D324E).bytes[0], int) == True

def test_funcB():
    assert BipFunction(0x01800D6B30).guess_strtype == "__int64 __fastcall()"

# TODO finish test from TYPE, ARGS, ... (~l750)
# remove the todo test in bip/base/func.py


