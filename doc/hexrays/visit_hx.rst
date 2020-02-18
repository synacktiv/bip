HxCItem
#######

.. module:: bip.hexrays

The :class:`~bip.hexrays.HxCItem` API is one of the way to represent AST nodes
of an Hexrays decompiled function at the level of Bip. This API is the closest
of the one provided by IDAPython, however this is not the prefered way to view
AST nodes in Bip, :ref:`doc-hexrays-cnode` for the prefered way and 
:ref:`doc-hexrays-astnodes` for more general information.

The simplest way to access :class:`~bip.hexrays.HxCItem` elements is through
the usage of the visitorm methods starting with ``hx_visit_`` in
:class:`~bip.hexrays.HxCFunc`

This API is based on the :class:`~bip.hexrays.HxCItem` abstract class, each
AST nodes are represented by a subclass of this object which are determine
by its type. For more information of the different type of nodes see 
:ref:`doc-hexrays-astnodes-nodetype`. The method
:meth:`~bip.hexrays.HxCItem.GetHxCItem` allow to recuperate an object of the
correct class (which inherit from :class:`~bip.hexrays.HxCItem`) for a
particular ``citem_t`` object from IDA.

HxCItem API
===========

.. autoclass:: HxCItem
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

HxCExpr API
===========

.. autoclass:: HxCExpr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

HxCStmt API
===========

.. autoclass:: HxCStmt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Final Expression API
====================

.. autoclass:: HxCExprFinal
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprEmpty
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprNum
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprFNum
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprStr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprObj
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprVar
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprHelper
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprInsn
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprType
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

MemAccess Expression API
========================

.. autoclass:: HxCExprMemAccess
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprIdx
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprMemref
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprMemptr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Unary Operation Expression API
==============================

.. autoclass:: HxCExprUnaryOperation
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprPtr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprFneg
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprNeg
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprCast
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprLnot
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprBnot
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprRef
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprPostinc
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprPostdec
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprPreinc
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprPredec
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprSizeof
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Double Operation Expression API
===============================

.. autoclass:: HxCExprDoubleOperation
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprComma
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsg
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgbor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgxor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgband
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgadd
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgsub
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgmul
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgsshr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgushr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgshl
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgsdiv
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgudiv
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgsmod
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAsgumod
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprLor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprLand
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprBor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprXor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprBand
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprEq
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprNe
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprSge
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprUge
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprSle
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprUle
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprSgt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprUgt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprSlt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprUlt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprSshr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprUshr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprShl
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprAdd
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprSub
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprMul
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprSdiv
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprUdiv
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprSmod
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprUmod
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprFadd
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprFsub
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprFmul
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCExprFdiv
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Other leaf Expressions API
==========================

.. autoclass:: HxCExprTernary
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: HxCExprCall
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Final Statement API
===================

.. autoclass:: HxCStmtFinal
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtEmpty
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtExpr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtGoto
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtAsm
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtReturn
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Other leaf Statement API
========================

.. autoclass:: HxCStmtIf
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtFor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtWhile
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtDoWhile
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtSwitch
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtContinue
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtBreak
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


.. autoclass:: HxCStmtBlock
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. _doc-hexrays-ida-visitor-internal:

Internal Hexrays Visitor API
============================

.. automodule:: bip.hexrays.hx_visitor
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

