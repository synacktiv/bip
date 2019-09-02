.. _doc-hexrays-cnode:

CNode & visitors
################

.. module:: bip.hexrays

TODO

GetCNode

CNode API
=========

.. autoclass:: CNode
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

CNodeExpr API
=============

.. autoclass:: CNodeExpr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

CNodeStmt API
=============

.. autoclass:: CNodeStmt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Final Expression API
====================

.. autoclass:: CNodeExprFinal
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprEmpty
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprNum
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprFNum
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprStr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprObj
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprVar
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprHelper
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprInsn
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprType
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

MemAccess Expression API
========================

.. autoclass:: CNodeExprMemAccess
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprIdx
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprMemref
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprMemptr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Unary Operation Expression API
==============================

.. autoclass:: CNodeExprUnaryOperation
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprPtr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprFneg
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprNeg
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprCast
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprLnot
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprBnot
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprRef
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprPostinc
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprPostdec
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprPreinc
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprPredec
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprSizeof
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Double Operation Expression API
===============================

.. autoclass:: CNodeExprDoubleOperation
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprComma
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsg
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgbor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgxor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgband
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgadd
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgsub
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgmul
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgsshr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgushr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgshl
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgsdiv
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgudiv
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgsmod
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAsgumod
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprLor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprLand
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprBor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprXor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprBand
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprEq
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprNe
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprSge
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprUge
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprSle
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprUle
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprSgt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprUgt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprSlt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprUlt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprSshr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprUshr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprShl
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprAdd
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprSub
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprMul
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprSdiv
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprUdiv
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprSmod
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprUmod
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprFadd
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprFsub
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprFmul
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeExprFdiv
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Other leaf Expressions API
==========================

.. autoclass:: CNodeExprTernary
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: CNodeExprCall
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Final Statement API
===================

.. autoclass:: CNodeStmtFinal
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtEmpty
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtExpr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtGoto
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtAsm
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtReturn
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Other leaf Statement API
========================

.. autoclass:: CNodeStmtIf
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtFor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtWhile
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtDoWhile
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtSwitch
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtContinue
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtBreak
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: CNodeStmtBlock
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Internal Hexrays Visitor API
============================

.. automodule:: bip.hexrays.cnode_visitor
   :members:


