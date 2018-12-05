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

def test_idaelt00():
    assert IdaElt(0x01800D325A).ea == 0x01800D325A

def test_idaelt01():
    assert IdaElt(0x01800D325A).flags == idc.GetFlags(0x01800D325A)

def test_idaelt02():
    assert IdaElt(0x01800D325A).size == 4

def test_idaelt03():
    assert IdaElt(0x01800D325A).bytes == [0x48, 0x83, 0xC4, 0x60]

def test_idaelt04():
    assert IdaElt(0x01800D325A).name == 'loc_1800D325A'

def test_idaelt04b():
    # name setter
    ie = IdaElt(0x01800D325A)
    prevname = ie.name
    ie.name = "idaelt_test"
    res = ie.name == "idaelt_test"
    ie.name = None
    assert res

def test_idaelt05():
    assert IdaElt(0x01800D325A).color == idc.GetColor(0x01800D325A, idc.CIC_ITEM)

def test_idaelt06():
    ie = IdaElt(0x01800D325A)
    prevcolor = ie.color
    ie.color = 0xAABBCC
    res = ie.color == 0xAABBCC
    ie.color = prevcolor
    assert res

def test_idaelt07():
    assert IdaElt(0x01800D325A).comment is None

def test_idaelt08():
    ie = IdaElt(0x01800D325A)
    ie.comment = "test"
    res = ie.comment == "test"
    ie.comment = None
    assert res

def test_idaelt09():
    assert IdaElt(0x01800D325A).rcomment is None

def test_idaelt0A():
    ie = IdaElt(0x01800D325A)
    ie.rcomment = "test"
    res = ie.rcomment == "test"
    ie.rcomment = None
    assert res
    
def test_idaelt0B():
    assert IdaElt(0x01800D325A).has_comment == False

def test_idaelt0C():
    ie = IdaElt(0x01800D325A)
    ie.comment = "test"
    res = ie.has_comment
    ie.comment = ""
    assert res

def test_idaelt0D():
    assert IdaElt(0x01800D325A).is_code == True

def test_idaelt0E():
    assert IdaElt(0x01800D325A).is_data == False

def test_idaelt0F():
    assert IdaElt(0x01800D325A).is_unknown == False

def test_idaelt10():
    assert IdaElt(0x01800D325A).is_head == True

def test_idaelt11():
    assert IdaElt(0x01800D325B).is_head == False

def test_idaelt12():
    assert IdaElt(0x018015D228).is_code == False

def test_idaelt13():
    assert IdaElt(0x018015D228).is_data == True

def test_idaelt14():
    assert IdaElt(0x018015D228).is_unknown == False

def test_idaelt15():
    assert IdaElt(0x018015D228).is_head == True

def test_idaelt16():
    assert IdaElt(0x018015D228).size == 8

def test_idaelt17():
    assert IdaElt(0x018015D260).is_head == False

def test_idaelt18():
    assert IdaElt(0x018015D261).is_head == False

def test_idaelt19():
    assert IdaElt(0x018015D260).size == 1

def test_idaelt1A():
    assert IdaElt(0x018015D260).is_unknown == True

def test_idaelt1B():
    assert GetElt(0x018015D228).__class__ == IdaElt

def test_idaelt1C():
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
    assert IdaFunction(0x01800D6B30).ea == IdaFunction(0x01800D6B39).ea

def test_func1():
    assert IdaFunction(0x01800D6B30).ea == 0x01800D6B30

def test_func2():
    assert IdaFunction(0x01800D6B30).name == "RtlWow64SetThreadContext"

# TODO: test name setter

def test_func3():
    assert IdaFunction(0x01800D6B30).end == 0x01800D6B43

def test_func4():
    assert IdaFunction(0x01800D6B30).size == 0x13

def test_func5():
    assert IdaFunction(0x01800D6B30).ordinal == 0xb8b

def test_func6():
    assert IdaFunction(0x01800D6B30).flags == 21504

# TODO: test flags setter

def test_func7():
    assert IdaFunction(0x01800D6B30).does_return

def test_func8():
    assert IdaFunction(0x01800D6B30).is_inside(0x01800D6B39)

def test_func9():
    assert IdaFunction(0x01800D6B30).is_inside(Instr(0x01800D6B39))

def test_funcA():
    assert IdaFunction(0x01800D6B30).is_inside(Instr(0x01800D6B50)) == False

def test_funcB():
    assert IdaFunction(0x01800D6B30).guesstype == "__int64 __fastcall()"

def test_funcC():
    assert IdaFunction(0x0180099990).nb_blocks == 3

def test_funcD():
    blck = IdaFunction(0x0180099990).blocks
    assert blck[0].ea == 0x0180099990
    assert blck[1].ea == 0x01800999DC
    assert blck[2].ea == 0x01800999F0

def test_funcE():
    f = IdaFunction(0x0180099990)
    blck = f.blocks
    i = 0
    for b in f.blocks_iter:
        assert blck[i].ea == b.ea
        assert blck[i].end == b.end
        i += 1

# TODO: finish IdaFunction test

###################### BLOCK #########################

def test_block0():
    assert IdaBlock(0x0180099990).ea == IdaFunction(0x0180099990).ea

def test_block1():
    assert IdaBlock(0x0180099990).ea == IdaBlock(0x0180099992).ea

def test_block2():
    assert IdaBlock(0x0180099990).type == IdaBlockType.FCB_NORMAL

def test_block3():
    assert IdaBlock(0x0180099990).is_ret == False

def test_block4():
    assert IdaBlock(0x0180099990).is_noret == False

def test_block5():
    assert IdaBlock(0x0180099990).is_external == False

def test_block6():
    assert IdaBlock(0x01800999F0).type == IdaBlockType.FCB_NORET

def test_block7():
    assert IdaBlock(0x01800999F0).is_ret == False

def test_block8():
    assert IdaBlock(0x01800999F0).is_noret == True

def test_block9():
    assert IdaBlock(0x01800999F0).is_external == False

def test_blockA():
    assert IdaBlock(0x0180099990).end == 0x01800999DC

def test_blockB():
    assert len(IdaBlock(0x0180099990).succ) == 2

def test_blockC():
    ss = IdaBlock(0x0180099990).succ
    assert ss[0].ea == 0x01800999DC
    assert ss[1].ea == 0x01800999F0

def test_blockD():
    b = IdaBlock(0x0180099990)
    ss = b.succ
    i = 0
    for bb in b.iter_succ:
        assert ss[i].ea == bb.ea
        i += 1

def test_blockE():
    assert len(IdaBlock(0x01800999E4).succ) == 1

def test_blockF():
    assert len(IdaBlock(0x01800999F0).succ) == 0

def test_block10():
    assert len(IdaBlock(0x01800999F0).pred) == 2

def test_block11():
    assert len(IdaBlock(0x0180099990).pred) == 0

def test_block12():
    b = IdaBlock(0x01800999F0)
    ss = b.pred
    i = 0
    for bb in b.iter_pred:
        assert ss[i].ea == bb.ea
        i += 1

def test_block13():
    assert IdaBlock(0x01800999F0).func.ea == 0x0180099990

def test_block14():
    assert len(IdaBlock(0x01800999DC).items) == 4

def test_block15():
    for i in IdaBlock(0x01800999DC).items:
        assert i.__class__ == Instr

def test_block16():
    assert len(IdaBlock(0x01800999DC).instr) == 4

def test_block17():
    for i in IdaBlock(0x01800999DC).instr:
        assert i.__class__ == Instr

def test_block18():
    assert IdaBlock(0x01800999DC).instr[-1].ea == 0x01800999EE

def test_block19():
    assert IdaBlock(0x01800999DC).bytes == [0x48, 0x8D, 0x94, 0x24, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0xD2, 0xCE, 0xF6, 0xFF, 0x84, 0xDB]


