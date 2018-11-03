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


