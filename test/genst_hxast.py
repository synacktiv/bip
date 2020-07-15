from bip import *

import pytest


"""
    This regroup generic function for testing nodes of the Hexrays AST. This
    include all the childs class :class:`HxCExpr`, :class:`HxCStmt`,
    :class:`CNodeExpr` and :class:`CNodeStmt`. As most of those classes have
    the same code (dynamic generation of the :class:`CNode` classes), the test
    function support both node type.

    This regroup test for functions in:

    * ``bip/hexrays/hx_cexpr.py``
    * ``bip/hexrays/hx_cstmt.py``
    * ``bip/hexrays/cnode.py``
"""

## Main classes

def gentst_abstractcitem(aci):
    # generic AbstractCItem test
    assert isinstance(aci, AbstractCItem)
    assert isinstance(aci.ea, (int, long))
    assert isinstance(aci._ctype, int)
    assert aci._ctype >= 0 and aci._ctype < HxCType.CIT_END
    assert isinstance(str(aci), str)
    assert aci.is_expr == (aci._ctype >= HxCType.COT_EMPTY and aci._ctype <= HxCType.COT_LAST)
    assert aci.is_statement == (aci._ctype >= HxCType.CIT_EMPTY and aci._ctype < HxCType.CIT_END)
    # label
    assert isinstance(aci.has_label, bool)
    assert isinstance(aci.label_num, int)
    assert (aci.label_num != -1) == aci.has_label

def gentst_cnode(cn):
    # generic CNode, CNodeExpr and CNodeStmt test
    assert isinstance(cn, CNode)
    assert isinstance(cn.closest_ea, (int, long))
    assert cn.closest_ea != idc.BADADDR
    assert (cn.closest_ea == cn.ea) or cn.ea == idc.BADADDR
    assert cn.closest_ea is not None # this case should never happen in practice
    assert isinstance(cn.cstr, str)
    if cn.has_parent:
        assert isinstance(cn.parent, CNode)
    else:
        assert cn == cn.cfunc.root_node
    assert isinstance(cn.cfunc, HxCFunc)
    if isinstance(cn, CNodeExprCast):
        assert cn.ignore_cast != cn
        assert cn.ignore_cast_parent != cn
    else:
        assert cn.ignore_cast == cn
        assert cn.ignore_cast_parent == cn

def gentst_cnodeexpr(cn):
    # generic CNodeExpr test
    assert isinstance(cn, CNodeExpr)
    assert isinstance(cn.ops, list)
    for cno in cn.ops:
        assert isinstance(cno, CNodeExpr)
    assert isinstance(cn.type, BipType)
    if isinstance(cn, CNodeExprFinal):
        assert cn.find_final_left_node() == cn
        assert cn.find_left_node_notmatching([CNodeExpr]) == cn
    else:
        assert isinstance(cn.find_final_left_node(), CNodeExprFinal)
        assert isinstance(cn.find_left_node_notmatching([CNodeExpr]), CNodeExprFinal)
    assert cn.find_left_node_notmatching([]) == cn

def gentst_cnodestmt(cn):
    # generic CNodeStmt test
    assert isinstance(cn, CNodeStmt)
    assert isinstance(cn.st_childs, list)
    assert isinstance(cn.expr_childs, list)
    for cnc in cn.st_childs:
        assert isinstance(cnc, CNodeStmt)
    for cnc in cn.expr_childs:
        assert isinstance(cnc, CNodeExpr)

def gentst_hxcexpr(hi):
    # generic HxCExpr test
    assert isinstance(hi, HxCItem)
    assert isinstance(hi, HxCExpr)
    assert isinstance(hi.ops, list)
    for hio in hi.ops:
        assert isinstance(hio, HxCExpr)
    assert isinstance(hi.type, BipType)

def gentst_hxcstmt(hi):
    # generic HxCStmt test
    assert isinstance(hi, HxCItem)
    assert isinstance(hi, HxCStmt)
    assert isinstance(hi.st_childs, list)
    assert isinstance(hi.expr_childs, list)
    for hic in hi.st_childs:
        assert isinstance(hic, HxCStmt)
    for hic in hi.expr_childs:
        assert isinstance(hic, HxCExpr)


## Expr

def genst_exprnum(cn):
    # ExprNum
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprFinal, CNodeExprFinal))
    assert isinstance(cn, (HxCExprNum, CNodeExprNum))
    assert cn.ops == []
    assert isinstance(cn.value, (int, long))
    assert isinstance(cn.size, (int, long))
    assert cn.value < (1 << (cn.size * 8)) 

def genst_exprfnum(cn):
    # ExprNum
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprFinal, CNodeExprFinal))
    assert isinstance(cn, (HxCExprFNum, CNodeExprFNum))
    assert cn.ops == []
    assert isinstance(cn.value, (int, long))
    assert isinstance(cn.size, (int, long))
    assert cn.size in (4, 8)

def genst_exprstr(cn):
    # ExprStr
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprFinal, CNodeExprFinal))
    assert isinstance(cn, (HxCExprStr, CNodeExprStr))
    assert cn.ops == []
    assert isinstance(cn.value, (str))

def genst_exprobj(cn):
    # ExprObj
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprFinal, CNodeExprFinal))
    assert isinstance(cn, (HxCExprObj, CNodeExprObj))
    assert cn.ops == []
    assert isinstance(cn.value, (int, long))

def genst_exprvar(cn):
    # ExprVar
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprFinal, CNodeExprFinal))
    assert isinstance(cn, (HxCExprVar, CNodeExprVar))
    assert cn.ops == []
    assert isinstance(cn.value, (int, long))
    assert isinstance(cn.index, (int, long))
    assert cn.index == cn.value
    if isinstance(cn, CNodeExprVar): # CNode specific implementation
        assert isinstance(cn.lvar, HxLvar)
        assert isinstance(cn.lvar_name, str)
        assert cn.lvar.name == cn.lvar_name

def genst_exprhelper(cn):
    # ExprHelper
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprFinal, CNodeExprFinal))
    assert isinstance(cn, (HxCExprHelper, CNodeExprHelper))
    assert cn.ops == []
    assert isinstance(cn.value, (str))

# No HxCExprInsn, should not happen

def genst_exprtype(cn):
    # ExprType
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprFinal, CNodeExprFinal))
    assert isinstance(cn, (HxCExprType, CNodeExprType))
    assert cn.ops == []
    assert isinstance(cn.value, BipType)
    assert cn.value == cn.type

def genst_exprternary(cn):
    # ExprTernary
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprTernary, CNodeExprTernary))
    assert len(cn.ops) == 3
    assert isinstance(cn.cond, (HxCExpr, CNodeExpr))
    assert cn.cond == cn.ops[0]
    assert isinstance(cn.expr1, (HxCExpr, CNodeExpr))
    assert cn.expr1 == cn.ops[1]
    assert isinstance(cn.expr2, (HxCExpr, CNodeExpr))
    assert cn.expr2 == cn.ops[2]

def genst_exprdoubleop(cn):
    # ExprDoubleOperation
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprDoubleOperation, CNodeExprDoubleOperation))
    assert len(cn.ops) == 2
    assert isinstance(cn.first_op, (HxCExpr, CNodeExpr))
    assert cn.first_op == cn.ops[0]
    assert isinstance(cn.second_op, (HxCExpr, CNodeExpr))
    assert cn.second_op == cn.ops[1]

# Because a lot of DoubleOperation have nothing in particular, no more test
#   for those

def genst_exprasg(cn):
    # ExprAssignement
    #genst_exprdoubleop(cn) # this is a double operation
    assert isinstance(cn, (HxCExprAssignment, CNodeExprAssignment))
    assert isinstance(cn.src, (HxCExpr, CNodeExpr))
    assert cn.src == cn.ops[1]
    assert isinstance(cn.dst, (HxCExpr, CNodeExpr))
    assert cn.dst == cn.ops[0]

def genst_exprunaryop(cn):
    # ExprUnaryOperation
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprUnaryOperation, CNodeExprUnaryOperation))
    assert len(cn.ops) == 1
    assert isinstance(cn.operand, (HxCExpr, CNodeExpr))
    assert cn.operand == cn.ops[0]

# same as DoubleOperation, the :class:`CNodeExprCast` methods are tested in
#   general cnode (``gentst_cnode``) function

def genst_exprptr(cn):
    # ExprPtr
    #genst_exprunaryop(cn)
    assert isinstance(cn, (HxCExprPtr, CNodeExprPtr))
    assert isinstance(cn.access_size, (int, long))

def genst_exprcall(cn):
    # ExprCall
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprCall, CNodeExprCall))
    ops = cn.ops
    assert len(ops) == cn.number_args + 1
    assert isinstance(cn.type_call, BipType)
    assert isinstance(cn.caller, (HxCExpr, CNodeExpr))
    assert isinstance(cn.is_helper, bool)
    assert isinstance(cn.number_args, (int, long))
    assert cn.caller == ops[0]
    if isinstance(cn, CNodeExpr):
        assert (cn.caller_addr is None) or (isinstance(cn.caller_addr, (int, long)))
        assert (cn.caller_func is None) or (isinstance(cn.caller_func, BipFunction))
        if cn.number_args >= 1:
            iv = cn.get_arg_intval(0)
            assert (isinstance(iv, (int, long))) or (iv is None)
    if isinstance(cn.caller, (HxCExprObj, CNodeExprObj)):
        assert cn.is_helper == False
        if isinstance(cn, CNodeExpr):
            assert cn.caller_addr is not None # base case, it should not be None
            assert cn.caller_addr == cn.caller.value
            assert cn.caller_func == BipFunction(cn.caller.value)
    args = cn.args
    assert isinstance(args, list)
    i = 0
    #for i in range(cn.number_args):
    for ar in cn.args_iter:
        assert isinstance(ar, (HxCExpr, CNodeExpr))
        assert ar == cn.get_arg(i)
        assert ar == args[i]
        assert ar == ops[i + 1]
        if isinstance(ar, CNodeExprObj):
            assert cn.get_arg_intval(i) == ar.value
        i += 1
    assert i == cn.number_args
    with pytest.raises(ValueError): cn.get_arg(cn.number_args + 1)


def genst_expridx(cn):
    # ExprIdx
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprMemAccess, CNodeExprMemAccess))
    assert isinstance(cn, (HxCExprIdx, CNodeExprIdx))
    assert len(cn.ops) == 2
    assert isinstance(cn.array, (HxCExpr, CNodeExpr))
    assert cn.array == cn.obj
    assert cn.array == cn.ops[0]
    assert isinstance(cn.index, (HxCExpr, CNodeExpr))
    assert cn.index == cn.off
    assert cn.index == cn.ops[1]

def genst_exprmemref(cn):
    # ExprMemref
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprMemAccess, CNodeExprMemAccess))
    assert isinstance(cn, (HxCExprMemref, CNodeExprMemref))
    assert len(cn.ops) == 1
    assert isinstance(cn.mem, (HxCExpr, CNodeExpr))
    assert cn.mem == cn.obj
    assert cn.mem == cn.ops[0]
    assert isinstance(cn.off, (int, long))

def genst_exprmemptr(cn):
    # ExprMemptr
    assert isinstance(cn, (HxCExpr, CNodeExpr))
    assert isinstance(cn, (HxCExprMemAccess, CNodeExprMemAccess))
    assert isinstance(cn, (HxCExprMemptr, CNodeExprMemptr))
    assert len(cn.ops) == 1
    assert isinstance(cn.ptr, (HxCExpr, CNodeExpr))
    assert cn.ptr == cn.obj
    assert cn.ptr == cn.ops[0]
    assert isinstance(cn.off, (int, long))
    assert isinstance(cn.access_size, (int, long))

## Stmt


def genst_stmtexpr(cn):
    # StmtExpr
    assert isinstance(cn, (HxCStmt, CNodeStmt))
    assert isinstance(cn, (HxCStmtFinal, CNodeStmtFinal))
    assert isinstance(cn, (HxCStmtExpr, CNodeStmtExpr))
    assert len(cn.st_childs) == 0
    assert len(cn.expr_childs) == 1
    assert isinstance(cn.expr, (HxCExpr, CNodeExpr))
    assert cn.expr == cn.value

def genst_stmtgoto(cn):
    # StmtGoto
    assert isinstance(cn, (HxCStmt, CNodeStmt))
    assert isinstance(cn, (HxCStmtFinal, CNodeStmtFinal))
    assert isinstance(cn, (HxCStmtGoto, CNodeStmtGoto))
    assert len(cn.st_childs) == 0
    assert len(cn.expr_childs) == 0
    assert isinstance(cn.label, (int, long))
    assert cn.label == cn.value
    if isinstance(cn, CNodeStmtGoto):
        assert isinstance(cn.cnode_dst, CNode)

def genst_stmtasm(cn):
    # StmtAsm
    assert isinstance(cn, (HxCStmt, CNodeStmt))
    assert isinstance(cn, (HxCStmtFinal, CNodeStmtFinal))
    assert isinstance(cn, (HxCStmtAsm, CNodeStmtAsm))
    assert len(cn.st_childs) == 0
    assert len(cn.expr_childs) == 0
    assert isinstance(cn.addr_instr, list)
    assert len(cn.addr_instr) > 0
    assert isinstance(cn.addr_instr[0], (int, long))
    assert isinstance(cn.length, (int, long))
    assert len(cn.addr_instr) == cn.length
    assert len(cn) == cn.length
    li = cn.value
    assert isinstance(li, list)
    assert len(li) == cn.length
    assert isinstance(li[0], Instr)

def genst_stmtreturn(cn):
    # StmtReturn
    assert isinstance(cn, (HxCStmt, CNodeStmt))
    assert isinstance(cn, (HxCStmtFinal, CNodeStmtFinal))
    assert isinstance(cn, (HxCStmtReturn, CNodeStmtReturn))
    assert len(cn.st_childs) == 0
    assert len(cn.expr_childs) == 1
    assert cn.value == cn.ret_val
    assert cn.value == cn.expr_childs[0]
    assert isinstance(cn.ret_val, (HxCExpr, CNodeExpr))

def genst_stmtif(cn):
    # StmtIf
    assert isinstance(cn, (HxCStmt, CNodeStmt))
    assert isinstance(cn, (HxCStmtIf, CNodeStmtIf))
    assert len(cn.expr_childs) == 1
    assert isinstance(cn.cond, (HxCExpr, CNodeExpr))
    assert cn.expr_childs[0] == cn.cond
    assert isinstance(cn.st_then, (HxCStmt, CNodeStmt))
    assert cn.st_childs[0] == cn.st_then
    assert isinstance(cn.has_else, bool)
    if cn.has_else:
        assert isinstance(cn.st_else, (HxCStmt, CNodeStmt))
        assert len(cn.st_childs) == 2
        assert cn.st_childs[1] == cn.st_else
    else:
        assert cn.st_else is None
        assert len(cn.st_childs) == 1

def genst_stmtfor(cn):
    # StmtFor
    assert isinstance(cn, (HxCStmt, CNodeStmt))
    assert isinstance(cn, (HxCStmtLoop, CNodeStmtLoop))
    assert isinstance(cn, (HxCStmtFor, CNodeStmtFor))
    assert len(cn.st_childs) == 1
    assert len(cn.expr_childs) == 3
    assert isinstance(cn.init, (HxCExpr, CNodeExpr))
    assert isinstance(cn.cond, (HxCExpr, CNodeExpr))
    assert isinstance(cn.step, (HxCExpr, CNodeExpr))
    assert cn.init == cn.expr_childs[0]
    assert cn.cond == cn.expr_childs[1]
    assert cn.step == cn.expr_childs[2]
    assert isinstance(cn.st_body, (HxCStmt, CNodeStmt))
    assert cn.st_body == cn.st_childs[0]

def genst_stmtwhile(cn):
    # StmtWhile
    assert isinstance(cn, (HxCStmt, CNodeStmt))
    assert isinstance(cn, (HxCStmtLoop, CNodeStmtLoop))
    assert isinstance(cn, (HxCStmtWhile, CNodeStmtWhile))
    assert len(cn.st_childs) == 1
    assert len(cn.expr_childs) == 1
    assert isinstance(cn.cond, (HxCExpr, CNodeExpr))
    assert cn.cond == cn.expr_childs[0]
    assert isinstance(cn.st_body, (HxCStmt, CNodeStmt))
    assert cn.st_body == cn.st_childs[0]

def genst_stmtdowhile(cn):
    # StmtDoWhile
    assert isinstance(cn, (HxCStmt, CNodeStmt))
    assert isinstance(cn, (HxCStmtLoop, CNodeStmtLoop))
    assert isinstance(cn, (HxCStmtDoWhile, CNodeStmtDoWhile))
    assert len(cn.st_childs) == 1
    assert len(cn.expr_childs) == 1
    assert isinstance(cn.cond, (HxCExpr, CNodeExpr))
    assert cn.cond == cn.expr_childs[0]
    assert isinstance(cn.st_body, (HxCStmt, CNodeStmt))
    assert cn.st_body == cn.st_childs[0]

def genst_stmtswitch(cn):
    # StmtSwitch
    assert isinstance(cn, (HxCStmt, CNodeStmt))
    assert isinstance(cn, (HxCStmtLoop, CNodeStmtLoop))
    assert isinstance(cn, (HxCStmtSwitch, CNodeStmtSwitch))
    assert len(cn.st_childs) != 0
    assert len(cn.expr_childs) == 1
    assert isinstance(cn.expr, (HxCExpr, CNodeExpr))
    assert cn.expr == cn.expr_childs[0]
    assert isinstance(cn.max_val, (int, long))
    cas = cn.st_cases
    casv = cn.cases_val
    assert isinstance(cas, list)
    assert isinstance(casv, list)
    assert len(cas) != 0
    assert len(cas) == len(cn.st_childs)
    assert len(cas) == len(casv)
    for i in range(len(cas)):
        assert isinstance(cas[i], (HxCStmt, CNodeStmt))
        assert isinstance(casv[i], list)
        assert isinstance(casv[i][0], (int, long))

# ignore break and continue: nothing particular to test

def genst_stmtblock(cn):
    # StmtBlock
    assert isinstance(cn, (HxCStmt, CNodeStmt))
    assert isinstance(cn, (HxCStmtBlock, CNodeStmtBlock))
    assert len(cn.st_childs) != 0
    assert len(cn.expr_childs) == 0
    assert len(cn.elts) == len(cn.st_childs)

def genst_all(cn):
    gentst_abstractcitem(cn) # all note should inherit from AbstractCItem
    assert isinstance(cn, (CNode, HxCItem))
    if isinstance(cn, CNode):
        gentst_cnode(cn)
        if isinstance(cn, CNodeExpr):
            gentst_cnodeexpr(cn)
        if isinstance(cn, CNodeStmt):
            gentst_cnodestmt(cn)
    else:
        if isinstance(cn, HxCExpr):
            gentst_hxcexpr(cn)
        if isinstance(cn, HxCStmt):
            gentst_hxcstmt(cn)
    if isinstance(cn, (HxCExprNum, CNodeExprNum)):
        genst_exprnum(cn)
    if isinstance(cn, (HxCExprFNum, CNodeExprFNum)):
        genst_exprfnum(cn)
    if isinstance(cn, (HxCExprStr, CNodeExprStr)):
        genst_exprstr(cn)
    if isinstance(cn, (HxCExprObj, CNodeExprObj)):
        genst_exprobj(cn)
    if isinstance(cn, (HxCExprVar, CNodeExprVar)):
        genst_exprvar(cn)
    if isinstance(cn, (HxCExprHelper, CNodeExprHelper)):
        genst_exprhelper(cn)
    if isinstance(cn, (HxCExprType, CNodeExprType)):
        genst_exprtype(cn)
    if isinstance(cn, (HxCExprTernary, CNodeExprTernary)):
        genst_exprternary(cn)
    if isinstance(cn, (HxCExprDoubleOperation, CNodeExprDoubleOperation)):
        genst_exprdoubleop(cn)
    if isinstance(cn, (HxCExprAsg, CNodeExprAsg)):
        genst_exprasg(cn)
    if isinstance(cn, (HxCExprUnaryOperation, CNodeExprUnaryOperation)):
        genst_exprunaryop(cn)
    if isinstance(cn, (HxCExprPtr, CNodeExprPtr)):
        genst_exprptr(cn)
    if isinstance(cn, (HxCExprCall, CNodeExprCall)):
        genst_exprcall(cn)
    if isinstance(cn, (HxCExprIdx, CNodeExprIdx)):
        genst_expridx(cn)
    if isinstance(cn, (HxCExprMemref, CNodeExprMemref)):
        genst_exprmemref(cn)
    if isinstance(cn, (HxCExprMemptr, CNodeExprMemptr)):
        genst_exprmemptr(cn)
    if isinstance(cn, (HxCStmtExpr, CNodeStmtExpr)):
        genst_stmtexpr(cn)
    if isinstance(cn, (HxCStmtGoto, CNodeStmtGoto)):
        genst_stmtgoto(cn)
    if isinstance(cn, (HxCStmtAsm, CNodeStmtAsm)):
        genst_stmtasm(cn)
    if isinstance(cn, (HxCStmtReturn, CNodeStmtReturn)):
        genst_stmtreturn(cn)
    if isinstance(cn, (HxCStmtIf, CNodeStmtIf)):
        genst_stmtif(cn)
    if isinstance(cn, (HxCStmtFor, CNodeStmtFor)):
        genst_stmtfor(cn)
    if isinstance(cn, (HxCStmtWhile, CNodeStmtWhile)):
        genst_stmtwhile(cn)
    if isinstance(cn, (HxCStmtDoWhile, CNodeStmtDoWhile)):
        genst_stmtdowhile(cn)
    if isinstance(cn, (HxCStmtSwitch, CNodeStmtSwitch)):
        genst_stmtswitch(cn)
    if isinstance(cn, (HxCStmtBlock, CNodeStmtBlock)):
        genst_stmtblock(cn)




