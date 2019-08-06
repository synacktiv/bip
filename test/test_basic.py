import sys
sys.path.append(r"E:\bip")

from bip.base import *

import idc

# TODO:
#   * Operand
#   * xref
#   * struct
#   * utils

###################### IDAELT #########################

def test_bipelt00():
    assert BipElt(0x01800D325A).ea == 0x01800D325A

def test_bipelt01():
    assert BipElt(0x01800D325A).flags == idc.GetFlags(0x01800D325A)

def test_bipelt02():
    assert BipElt(0x01800D325A).size == 4

def test_bipelt03():
    assert BipElt(0x01800D325A).bytes == [0x48, 0x83, 0xC4, 0x60]

def test_bipelt04():
    assert BipElt(0x01800D325A).name == 'loc_1800D325A'

def test_bipelt04b():
    # name setter
    ie = BipElt(0x01800D325A)
    prevname = ie.name
    ie.name = "idaelt_test"
    res = ie.name == "idaelt_test"
    ie.name = None
    assert res

def test_bipelt05():
    assert BipElt(0x01800D325A).color == idc.GetColor(0x01800D325A, idc.CIC_ITEM)

def test_bipelt06():
    ie = BipElt(0x01800D325A)
    prevcolor = ie.color
    ie.color = 0xAABBCC
    res = ie.color == 0xAABBCC
    ie.color = prevcolor
    assert res

def test_bipelt07():
    assert BipElt(0x01800D325A).comment is None

def test_bipelt08():
    ie = BipElt(0x01800D325A)
    ie.comment = "test"
    res = ie.comment == "test"
    ie.comment = None
    assert res

def test_bipelt09():
    assert BipElt(0x01800D325A).rcomment is None

def test_bipelt0A():
    ie = BipElt(0x01800D325A)
    ie.rcomment = "test"
    res = ie.rcomment == "test"
    ie.rcomment = None
    assert res
    
def test_bipelt0B():
    assert BipElt(0x01800D325A).has_comment == False

def test_bipelt0C():
    ie = BipElt(0x01800D325A)
    ie.comment = "test"
    res = ie.has_comment
    ie.comment = ""
    assert res

def test_bipelt0D():
    assert BipElt(0x01800D325A).is_code == True

def test_bipelt0E():
    assert BipElt(0x01800D325A).is_data == False

def test_bipelt0F():
    assert BipElt(0x01800D325A).is_unknown == False

def test_bipelt10():
    assert BipElt(0x01800D325A).is_head == True

def test_bipelt11():
    assert BipElt(0x01800D325B).is_head == False

def test_bipelt12():
    assert BipElt(0x018015D228).is_code == False

def test_bipelt13():
    assert BipElt(0x018015D228).is_data == True

def test_bipelt14():
    assert BipElt(0x018015D228).is_unknown == False

def test_bipelt15():
    assert BipElt(0x018015D228).is_head == True

def test_bipelt16():
    assert BipElt(0x018015D228).size == 8

def test_bipelt17():
    assert BipElt(0x018015D260).is_head == False

def test_bipelt18():
    assert BipElt(0x018015D261).is_head == False

def test_bipelt19():
    assert BipElt(0x018015D260).size == 1

def test_bipelt1A():
    assert BipElt(0x018015D260).is_unknown == True

def test_bipelt1B():
    assert GetElt(0x018015D228).__class__ == BipData

def test_bipelt1C():
    assert GetElt(0x01800D325A).__class__ == Instr

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
    for bb in b.iter_succ:
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
    for bb in b.iter_pred:
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


