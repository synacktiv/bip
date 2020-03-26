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

###################### BIPELT #########################

def test_bipelt00():
    # ea, flags, size
    assert BipElt(0x01800D325A).ea == 0x01800D325A
    assert BipElt(0x01800D325A).flags == ida_bytes.get_full_flags(0x01800D325A)
    assert BipElt(0x01800D325A).size == 4
    assert BipElt(0x018015D260).size == 1
    assert BipElt(0x018015D228).size == 8
    # bytes
    assert BipElt(0x01800D325A).bytes == [0x48, 0x83, 0xC4, 0x60]
    BipElt(0x01800D325A).bytes = [0x90, 0x90, 0x90, 0x90]
    assert BipElt(0x01800D325A).bytes == [0x90, 0x90, 0x90, 0x90]
    BipElt(0x01800D325A).bytes = b"\xAA" * 4
    assert BipElt(0x01800D325A).bytes == [0xAA, 0xAA, 0xAA, 0xAA]
    BipElt(0x01800D325A).bytes = [0x48, 0x83, 0xC4, 0x60]
    assert BipElt(0x01800D325A).bytes == [0x48, 0x83, 0xC4, 0x60]
    # name
    assert BipElt(0x01800D325A).name == 'loc_1800D325A'
    assert BipElt(0x01800D325A).is_dummy_name
    assert not BipElt(0x01800D325A).is_auto_name
    assert BipElt(0x01800D325A).is_ida_name
    assert not BipElt(0x01800D325A).is_user_name
    ie = BipElt(0x01800D325A)
    prevname = ie.name
    ie.name = "idaelt_test"
    assert ie.name == "idaelt_test"
    assert not BipElt(0x01800D325A).is_dummy_name
    assert not BipElt(0x01800D325A).is_auto_name
    assert not BipElt(0x01800D325A).is_ida_name
    assert BipElt(0x01800D325A).is_user_name
    ie.name = None
    assert BipElt(0x01800D325A).name == 'loc_1800D325A'
    assert BipElt(0x01800D325A).is_dummy_name
    assert not BipElt(0x01800D325A).is_auto_name
    assert BipElt(0x01800D325A).is_ida_name
    assert not BipElt(0x01800D325A).is_user_name
    assert BipElt(0x018014F7FF).is_auto_name
    assert not BipElt(0x018014F7FF).is_dummy_name
    assert BipElt(0x018014F7FF).is_ida_name
    # color
    assert BipElt(0x01800D325A).color == idc.get_color(0x01800D325A, idc.CIC_ITEM)
    ie = BipElt(0x01800D325A)
    prevcolor = ie.color
    ie.color = 0xAABBCC
    assert ie.color == 0xAABBCC
    ie.color = prevcolor


def test_bipelt01():
    # cmp and hash
    assert BipElt(0x01800D325A) == BipElt(0x01800D325A)
    assert BipElt(0x01800D325A) > BipElt(0x01800D325A - 1)
    assert BipElt(0x01800D325A - 1) < BipElt(0x01800D325A)
    assert len([BipElt(0x01800D325A), BipElt(0x01800D325A)]) == 2
    assert len(set([BipElt(0x01800D325A), BipElt(0x01800D325A)])) == 1

def test_bipelt02():
    # comment
    assert BipElt(0x01800D325A).comment is None
    ie = BipElt(0x01800D325A)
    ie.comment = "test"
    res = ie.comment == "test"
    ie.comment = None
    assert res
    assert BipElt(0x01800D325A).rcomment is None
    ie = BipElt(0x01800D325A)
    ie.rcomment = "test"
    res = ie.rcomment == "test"
    ie.rcomment = None
    assert res
    assert BipElt(0x01800D325A).has_comment == False
    ie = BipElt(0x01800D325A)
    ie.comment = "test"
    res = ie.has_comment
    ie.comment = ""
    assert res

def test_bipelt03():
    # flags
    assert BipElt(0x01800D325A).is_code == True
    assert BipElt(0x01800D325A).is_data == False
    assert BipElt(0x01800D325A).is_unknown == False
    assert BipElt(0x01800D325A).is_head == True
    assert BipElt(0x01800D325B).is_head == False
    assert BipElt(0x018015D228).is_code == False
    assert BipElt(0x018015D228).is_data == True
    assert BipElt(0x018015D228).is_unknown == False
    assert BipElt(0x018015D228).is_head == True
    assert BipElt(0x018015D260).is_head == False
    assert BipElt(0x018015D261).is_head == False
    assert BipElt(0x018015D260).is_unknown == True
    assert BipElt(0x018013183C).is_unknown == True
    assert BipElt(0x018015A410).has_data == False
    assert BipElt(0x01800D325A).has_data == True
    assert BipElt(0x018015D228).has_data == False
    assert BipElt(0x018013183C).has_data == True

def test_bipelt04():
    # GetElt class creation
    assert GetElt(0x018015D228).__class__ == BipData
    assert GetElt(0x01800D325A).__class__ == Instr
    with pytest.raises(RuntimeError):
        GetElt(idc.BADADDR)
    with pytest.raises(RuntimeError):
        GetElt(0)
    with pytest.raises(RuntimeError):
        GetElt(0xAAAAA)
    assert GetEltByName('loc_1800D325A') == GetElt(0x01800D325A)
    assert GetEltByName('donotexist') is None

def test_bipelt05():
    ## static method of BipElt
    # is_mapped
    assert not BipElt.is_mapped(0)
    assert not BipElt.is_mapped(0xAAAA)
    assert not BipElt.is_mapped(0xFFFFFFFF)
    assert not BipElt.is_mapped(0xFFFFFFFFFFFFFFFF)
    assert BipElt.is_mapped(0x018015D228)
    # next_data
    assert BipElt.next_data_addr(ea=0x1800d324b, down=True) == 0x1800d3284
    assert BipElt.next_data_addr(ea=0x1800d324b, down=False) == 0x1800d2fe1
    assert BipElt.next_data(ea=0x1800d324b, down=True).ea == 0x1800d3284
    assert BipElt.next_data(ea=0x1800d324b, down=False).ea == 0x1800d2fe1
    # next code
    assert BipElt.next_code_addr(ea=0x1800d324b, down=True) == 0x1800d324e
    assert BipElt.next_code_addr(ea=0x1800d324b, down=False) == 0x1800d3248
    assert BipElt.next_code(ea=0x1800d324b, down=True).ea == 0x1800d324e
    assert BipElt.next_code(ea=0x1800d324b, down=False).ea == 0x1800d3248
    assert isinstance(BipElt.next_code(ea=0x1800d324b, down=True), Instr)
    assert isinstance(BipElt.next_code(ea=0x1800d324b, down=False), Instr)
    # next unknown
    assert BipElt.next_unknown_addr(ea=0x1800d324b, down=True) == 0x180110000
    assert BipElt.next_unknown_addr(ea=0x1800d324b, down=False) is None
    assert BipElt.next_unknown_addr(ea=0x180110000, down=True) == 0x180110001
    assert BipElt.next_unknown_addr(ea=0x180110001, down=False) == 0x180110000
    assert BipElt.next_unknown(ea=0x180110000, down=True).ea == 0x180110001
    assert BipElt.next_unknown(ea=0x180110001, down=False).ea == 0x180110000
    assert isinstance(BipElt.next_unknown(ea=0x180110000, down=True), BipData)
    assert isinstance(BipElt.next_unknown(ea=0x180110001, down=False), BipData)
    # next defined
    assert BipElt.next_defined_addr(ea=0x1800d324b, down=True) == 0x1800d324e
    assert BipElt.next_defined_addr(ea=0x1800d324b, down=False) == 0x1800d3248
    assert BipElt.next_defined_addr(ea=0x180110000, down=True) == 0x180110008
    assert BipElt.next_defined(ea=0x1800d324b, down=True).ea == 0x1800d324e
    assert BipElt.next_defined(ea=0x1800d324b, down=False).ea == 0x1800d3248
    assert BipElt.next_defined(ea=0x180110000, down=True).ea == 0x180110008

def test_biptelt06():
    ## static method of BipElt: search
    # search_bytes
    assert BipElt.search_bytes_addr("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 00 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x180000000) == 0x18011A808
    assert BipElt.search_bytes_addr("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 ? 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x180000000) == 0x18011A808
    assert BipElt.search_bytes_addr("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 ? 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x18011a808) is None
    assert BipElt.search_bytes_addr("49 8B CD", start_ea=0x01800D324B) == 0x1800D4FCA
    assert BipElt.search_bytes_addr("49 8B CD", start_ea=0x01800D324B, nxt=False) == 0x1800D324B
    assert BipElt.search_bytes_addr("49 8B CD", start_ea=0x01800D3242, end_ea=0x01800D3248) is None
    assert BipElt.search_bytes("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 00 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x180000000).ea == 0x18011A808
    assert BipElt.search_bytes("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 ? 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x180000000).ea == 0x18011A808
    assert BipElt.search_bytes("43 00 6F 00 6D 00 6D 00 6F 00 6E 00 50 00 72 00 6F 00 67 00 72 ? 61 00 6D 00 46 00 69 00 6C 00  65 00 73 00 28 00 41 00 72 00 6D 00 29 00 00 00", start_ea=0x18011a808) is None
    assert BipElt.search_bytes("49 8B CD", start_ea=0x01800D324B).ea == 0x1800D4FCA
    assert BipElt.search_bytes("49 8B CD", start_ea=0x01800D324B, nxt=False).ea == 0x1800D324B
    assert BipElt.search_bytes("49 8B CD", start_ea=0x01800D3242, end_ea=0x01800D3248) is None
    # search string
    assert BipElt.search_str_addr("Wow64SuspendLocalThread", start_ea=0x180000000) == 0x18011a3b8
    assert BipElt.search_str_addr("Wow64SuspendLocalThread\x00", start_ea=0x180000000) == 0x18011A3B8
    assert BipElt.search_str_addr("Wow64SuspendLocalThreat", start_ea=0x180000000) is None
    assert BipElt.search_str("Wow64SuspendLocalThread", start_ea=0x180000000).ea == 0x18011a3b8
    assert BipElt.search_str("Wow64SuspendLocalThread\x00", start_ea=0x180000000).ea == 0x18011A3B8
    assert isinstance(BipElt.search_str("Wow64SuspendLocalThread", start_ea=0x180000000), BipData)
    assert isinstance(BipElt.search_str("Wow64SuspendLocalThread\x00", start_ea=0x180000000), BipData)
    assert BipElt.search_str("Wow64SuspendLocalThreat", start_ea=0x180000000) is None



def test_biptelt07():
    # xref
    pass # TODO

###################### INSTR #########################

def test_instr0():
    assert Instr(0x01800D325A).mnem == "add"

def test_instr1():
    assert Instr(0x01800D325A).mnem != "xadd"

def test_instr2():
    assert Instr(0x01800D325A).str == 'add     rsp, 60h'

def test_instr3():
    assert Instr(0x01800D325A).countOperand == 2

def test_instr4():
    assert len(Instr(0x01800D325A).ops) == 2

def test_instr5():
    assert Instr(0x01800D325A).has_prev_instr == True

def test_instr6():
    assert Instr(0x01800D325A).ea == 0x01800D325A

def test_instr7():
    assert Instr(0x01800D325A).prev.ea == 0x01800D3253

def test_instr8():
    assert Instr(0x01800D325A).next.ea == 0x01800D325E

def test_instr9():
    assert Instr(0x01800D325A).xOrdinaryCfNext.ea == 0x01800D325E

def test_instrA():
    assert [x.ea for x in Instr(0x01800D325A).xCfNext] == [0x01800D325E]

def test_instrB():
    assert [x.ea for x in Instr(0x01800D325A).xCfPrev] == [0x01800D3253, 0x01800D3028]

def test_instrC():
    assert Instr(0x01800D3028).xOrdinaryCfNext is None

def test_instrD():
    assert [x.ea for x in Instr(0x01800D3028).xCfNext] == [0x01800D325A]

def test_instrE():
    assert [x.ea for x in Instr(0x01800D3028).xCfPrev] == [0x01800D3023]

def test_instrF():
    assert [x.ea for x in Instr(0x01800D324E).xCfNext] == [0x01800D3253, 0x01800D35E8]

def test_instr10():
    assert [x.ea for x in Instr(0x01800D323A).xCfNext] == [0x01800D323C, 0x01800D3242]

def test_instr11():
    assert Instr(0x01800D6B33).func.ea == 0x01800D6B30

def test_instr12():
    assert Instr(0x01800D323A).block.ea == 0x01800D3227


###################### FUNC #########################

def test_func0():
    assert BipFunction(0x01800D6B30).ea == BipFunction(0x01800D6B39).ea

def test_func1():
    assert BipFunction(0x01800D6B30).ea == 0x01800D6B30

def test_func2():
    assert BipFunction(0x01800D6B30).name == "RtlWow64SetThreadContext"

# TODO: test name setter

def test_func3():
    assert BipFunction(0x01800D6B30).end == 0x01800D6B43

def test_func4():
    assert BipFunction(0x01800D6B30).size == 0x13

def test_func5():
    assert BipFunction(0x01800D6B30).ordinal == 0xb8b

def test_func6():
    assert BipFunction(0x01800D6B30).flags == 21504

# TODO: test flags setter

def test_func7():
    assert BipFunction(0x01800D6B30).does_return

def test_func8():
    assert BipFunction(0x01800D6B30).is_inside(0x01800D6B39)

def test_func9():
    assert BipFunction(0x01800D6B30).is_inside(Instr(0x01800D6B39))

def test_funcA():
    assert BipFunction(0x01800D6B30).is_inside(Instr(0x01800D6B50)) == False

def test_funcB():
    assert BipFunction(0x01800D6B30).guess_strtype == "__int64 __fastcall()"

def test_funcC():
    assert BipFunction(0x0180099990).nb_blocks == 3

def test_funcD():
    blck = BipFunction(0x0180099990).blocks
    assert blck[0].ea == 0x0180099990
    assert blck[1].ea == 0x01800999DC
    assert blck[2].ea == 0x01800999F0

def test_funcE():
    f = BipFunction(0x0180099990)
    blck = f.blocks
    i = 0
    for b in f.blocks_iter:
        assert blck[i].ea == b.ea
        assert blck[i].end == b.end
        i += 1

# TODO: finish BipFunction test

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


