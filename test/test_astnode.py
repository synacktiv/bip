from bip import *

import idc

import pytest

"""
    Test for all classes used for representing ast nodes are tested by this
    file, this is also used for testing the visitors.

    Are tested in this file the following:

    * :class:`AbstractCItem` from ``bip/hexrays/astnode.py``
    * :class:`CNode`, :class:`CNodeExpr` and :class:`CNodeStmt` from
      ``bip/hexrays/cnode.py``
    * :class:`HxCItem`, :class:`HxCExpr` and :class:`HxCStmt` from
      ``bip/hexrays/hx_citem.py``
    * classes in ``bip/hexrays/hx_cexpr.py`` and ``bip/hexrays/hx_cstmt.py``
      and their equivalent dynamoically create by ``bip/hexrays/cnode.py``
    * visitors functions in ``bip/hexrays/hx_visitor.py`` and
      ``bip/hexrays/cnode_visitor.py`` (indirectly).

    This also use the function from ``test/genst_hxast.py`` for performing
    test on all nodes through visitors.

    The function starting by ``gentst_`` are made to be able to run on which
    ever node which inherit from this class and check generic properties which
    should be valid for all node. Those are use for allowing to get more test
    executed when using the visitors.
"""

from genst_hxast import *


def test_bipabstractcitem00():
    ## fix abstract citem test, made on the root_node
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    aci = hxf.root_node
    gentst_abstractcitem(aci) # generic test for all abstractcitem
    # base
    #assert aci.ea == 0x1800D300B # first instruction after the header
    assert aci.is_expr == False
    assert aci.is_statement == True
    assert aci._ctype == HxCType.CIT_BLOCK
    # equality
    assert id(aci) != id(hxf.root_node)
    assert aci == hxf.root_node
    assert aci != hxf.root_node.stmt_children[0]
    assert aci.__eq__(0x10) == NotImplemented
    assert aci.__ne__(0x10) == NotImplemented
    assert aci != 0x10

def test_bipcnode00():
    ## fix CNode, CNodeExpr and CNodeStmt test, made from the root_node
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    cn = hxf.root_node
    assert isinstance(cn, CNodeStmtBlock) # root node is always a block
    assert cn.is_statement
    assert not cn.is_expr
    gentst_cnode(cn)
    gentst_cnodestmt(cn)
    cnc = cn.stmt_children[0] # first child, this should be a CNodeStmtExpr
    assert isinstance(cnc, CNodeStmtExpr)
    assert cnc.is_statement
    assert not cnc.is_expr
    gentst_cnode(cnc)
    gentst_cnodestmt(cnc)
    cna = cnc.value # first asg
    assert isinstance(cna, CNodeExprAsg)
    assert cna.is_expr
    assert not cna.is_statement
    gentst_cnodeexpr(cna)
    # base
    #assert cn.closest_ea == 0x1800D300B
    # access
    assert cn.has_parent == False
    assert cnc.has_parent == True
    with pytest.raises(RuntimeError): cn.parent
    assert cnc.parent == cn
    assert cn.hxcfunc == hxf
    # comment
    assert cna.comment is None
    cna.comment = "cmt4test"
    assert cna.comment == "cmt4test"
    # cnodeExpr
    assert len(cna.ops) == 2
    assert isinstance(cna.find_final_left_node(), CNodeExprVar)
    # cnodeStmt
    assert len(cn.stmt_children) != 0
    assert len(cnc.stmt_children) == 0
    assert len(cn.expr_children) == 0
    assert len(cnc.expr_children) == 1
    hxf2 = HxCFunc.from_addr(0x0180002524)
    assert isinstance(hxf2.get_cnode_label(6), CNode)
    assert hxf2.get_cnode_label(42) is None
    cnl = hxf2.cnodes_with_label
    assert isinstance(cnl, list)
    for cn in cnl:
        assert isinstance(cn, CNode)
        assert cn.has_label == True


def test_biphxcitem00():
    ## fix HxCItem test, just apply generic as most is the same as in the test_bipcnode00
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    hi = hxf.hx_root_stmt
    gentst_hxcstmt(hi)
    hic = hi.stmt_children[0] # first child, this should be a CNodeStmtExpr
    assert isinstance(hic, HxCStmtExpr)
    gentst_hxcstmt(hic)
    hia = hic.value # first asg
    assert isinstance(hia, HxCExprAsg)
    gentst_hxcexpr(hia)
    hxf2 = HxCFunc.from_addr(0x0180002524)
    assert isinstance(hxf2.hx_get_label(6), HxCItem)

def test_biphxvisitor00():
    # test for the HxCItem visitors
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    hxf.hx_visit_expr(genst_all)
    hxf.hx_visit_list_expr([HxCExprCall], genst_all)
    hxf.hx_visit_stmt(genst_all)
    hxf.hx_visit_list_stmt([HxCStmtExpr], genst_all)
    hxf.hx_visit_all(genst_all)
    hxf.hx_visit_list_all([HxCExprCall, HxCStmtExpr], genst_all)

def test_bipcnodevisitor00():
    # Visitor for the cnode, as visitor functions in HxCFunc are wrapper on top
    #   of the CNode functions this is considered enough. Internally those
    #   use the functions in cnode_visitor.py
    hxf = HxCFunc.from_addr(0x01800D2FF0)
    hxf.visit_cnode(genst_all)
    def _intern_testfilter(cn):
        assert isinstance(cn, (CNodeExprCall, CNodeStmtExpr)) 
        genst_all(cn)
    hxf.visit_cnode_filterlist(_intern_testfilter, [CNodeExprCall, CNodeStmtExpr])
    hxf = HxCFunc.from_addr(0x0180002524)
    hxf.visit_cnode(genst_all)
    ln = hxf.get_cnode_filter_type([CNodeStmtReturn])
    for cnr in ln:
        cn = cnr.value
        assert isinstance(cn, CNodeExpr)
        assert len(cn.get_cnode_filter(lambda x: True)) <= 8 # 8 should be more than sufficient
    hxf = HxCFunc.from_addr(0x0180078F20)
    def _intern_testfilter2(cn): # return the call to an Helper function
        return isinstance(cn, CNodeExprCall) and isinstance(cn.caller, CNodeExprHelper)
    ln = hxf.get_cnode_filter(_intern_testfilter2)
    assert isinstance(ln, list)
    assert len(ln) == 1
    assert isinstance(ln[0], CNodeExprCall) and isinstance(ln[0].caller, CNodeExprHelper)
    ln = hxf.get_cnode_filter_type([CNodeExprHelper])
    assert isinstance(ln, list)
    assert len(ln) == 1
    assert isinstance(ln[0], CNodeExprHelper)
    hxf = HxCFunc.from_addr(0x018009BF50)
    hxf.visit_cnode(genst_all)

def test_hxcexprobj00():
    # Specific test for methods implemented in HxCExprObj/CNodeExprObj
    f = HxCFunc.from_addr(0x01800D2FF0).get_cnode_filter_type(CNodeExprCall)[0].caller.value_as_func
    assert isinstance(f, BipFunction)
    assert f.name == "RtlCommitDebugInfo_0"
    e = HxCFunc.from_addr(0x01800D2FF0).get_cnode_filter_type(CNodeExprCall)[1].get_arg(0).operand.value_as_elt
    assert isinstance(e, BipElt) and isinstance(e, BipData)
    assert e.ea == 0x018015D228
    s = HxCFunc.from_addr(0x0180053BA0).get_cnode_filter_type(CNodeExprCall)[0].get_arg(1).value_as_cstring
    assert s == 'SE_InitializeEngine'



