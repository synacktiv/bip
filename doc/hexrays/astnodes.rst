.. _doc-hexrays-astnodes:

Ast Nodes & Visitors
####################

.. module:: bip.hexrays

TODO: rewrite this intro

This page explain some Bip internals and contains the API for two top level
classes (:class:`~bip.hexrays.AbstractCItem` and
:class:`~bip.hexrays.HxCType`) used internally. It also contains an array
explaining the link between the classes and the C representation.

Node representation in Bip
==========================

AST nodes of a decompiled hexrays C function are represented in two different
ways in Bip: using :class:`~bip.hexrays.CNode` or
:class:`~bip.hexrays.HxCItem`. In IDA all nodes are represented by the class
``citem_t`` with subclasses for different types of node, the Bip equivalent is
the :class:`~bip.hexrays.HxCItem`. However there is some limitations to what
it is provided by this object, the principal one is the fact that
a :class:`~bip.hexrays.HxCItem` do not provide a link to the function from which
they are derived. This limitation can be quite problematic at time and so the
:class:`~bip.hexrays.CNode` abstraction was created for keeping a single link to
the parent function and to the parent node.

In most cases, there is really few differences to use one or another of those
representation but as :class:`~bip.hexrays.CNode` objects possess more
functionnality there is few reasons not to use them.

Both :class:`~bip.hexrays.HxCItem` and :class:`~bip.hexrays.CNode` classes are
abstract and posess multiple subclasses which represents the actual nodes of
the AST depending on their types. Both those classes have a lot in common and
inherit from the same abstract class :class:`~bip.hexrays.AbstractCItem`. For
determining the correct node to implement it is necessary to check its type
from the ``citem_t`` object, this type internal to IDA are represented in Bip
by :class:`~bip.hexrays.HxCType`. For more information about which nodes
represent what C element see `AST Node types`_.

As subclasses of :class:`~bip.hexrays.HxCItem` and :class:`~bip.hexrays.CNode`
would have a lot in common and for avoiding code duplication the subclasses
for the :class:`~bip.hexrays.CNode` are dynamically generated. This should
have no impact for the user, but when looking at the code of Bip it is normal
to not find anywhere the subclasses of :class:`~bip.hexrays.CNode`.  All nodes
which inherit from :class:`~bip.hexrays.HxCItem` start with the ``HxC`` prefix
while all class which inherit from :class:`~bip.hexrays.CNode` start with the
``CNode`` prefix.

For more information see :ref:`doc-hexrays-cnode-generation-internal`.

.. _doc-hexrays-astnodes-nodetype:

AST Node types
==============

AST nodes are split in two main categories: statements (``Stmt``) and
expressions (``Expr``). Those two categories have basically the same meaning
than in C: statements mainly include execution flow control (``if``, ``for``,
``block``, ``goto``, ``return``, ...) while expressions are basically
everything else from assignment, arithmetic operations to functions calls and
cast.

.. note::

    All the class given there after are the one for the
    :class:`~bip.hexrays.CNode` implementation but it works exactly the same
    for the :class:`~bip.hexrays.HxCItem` implementation.

The AST is a tree representation of the decompiled code, each node of this
tree will be either a statements (object which inherit
from :class:`~bip.hexrays.CNodeStmt`) or an expression (object which inherit
from :class:`~bip.hexrays.CNodeExpr`). A statement node can have children
which are expression or statements, while an expression node may only have
children which are expression. The :meth:`~bip.hexrays.HxCFunc.root_node` of
a function should always be a :class:`~bip.hexrays.CNodeStmtBlock` which
itself should contain the different statements used in the rest of the
function. For a concrete example of an AST
see :ref:`general-archi-hexrays-example-ast`.

Bip provides a class hierarchy for "classifying" the different kind of nodes.
This class hierarchy is composed of numerous abstract classes which represent
different "types" of nodes. At the top of the hierarchy is the
:class:`~bip.hexrays.CNode` class, followed just bello by the
:class:`~bip.hexrays.CNodeStmt` and :class:`~bip.hexrays.CNodeExpr` which
represent the statement and the expressions. Those are follow by other
abastract classes which are detailed in `abstract node types`_, one of the
interest of those abstract class is to be able to use ``isinstance`` when
developing a visitor or recuperating nodes of a particular types for treating
several nodes the same way (see :ref:`general-archi-common-patterns`). The
leaf of the class hierarchy are the concrete class which have a particular
meaning in C, those node types are detailed in `concrete node types`_.

Abstract node types
-------------------

This table describes the abstract node type which represent the class
hierarchy of the node.

=================================== =================================== ======== =================================================================================================================================== =======================================================================================================================================================================================================
Class name                          Parent class name                   Type     Description                                                                                                                         Childrens
=================================== =================================== ======== =================================================================================================================================== =======================================================================================================================================================================================================
:class:`CNodeStmt`                  :class:`CNode`                      Stmt     Base class for all concrete and abstract statement nodes.                                                                           Depends, childrens can be statement or expressions.
:class:`CNodeStmtFinal`             :class:`CNodeStmt`                  Stmt     All statement class which do not have other statements as childrens but have values.                                                Depends, childrens can not be statement.
:class:`CNodeStmtLoop`              :class:`CNodeStmt`                  Stmt     All statement representing a loop (for, while, dowhile).                                                                            Depends, at least one expression :meth:`CNodeStmtLoop.cond` for the loop condition and a statement :meth:`CNodeStmtLoop.st_body` for the content of the loop.
:class:`CNodeExpr`                  :class:`CNode`                      Expr     Base class for all concrete and abstract expression nodes.                                                                          Depends, childrens can not be statement.
:class:`CNodeExprFinal`             :class:`CNodeExpr`                  Expr     Expression which do not have any other node as children, but have values. Those nodes are always leaf of the AST.                   No childrens, :meth:`CNodeExprFinal.value` for getting the content of the expression.
:class:`CNodeExprDoubleOperation`   :class:`CNodeExpr`                  Expr     Expression which posess two operands, this includes assignment, most logical and mathematical operations and things like comma.     Two expressions: :meth:`CNodeExprDoubleOperation.first_op` and :meth:`CNodeExprDoubleOperation.second_op`.
:class:`CNodeExprAssignment`        :class:`CNodeExprDoubleOperation`   Expr     Expression which represent an assignment, this include simple assignment but also assignment with operations (such as ``+=``).      Two expressions: :meth:`CNodeExprAssignment.dst` (equivalent to :meth:`CNodeExprDoubleOperation.first_op`) and :meth:`CNodeExprAssignment.src` (equivalent to :meth:`CNodeExprDoubleOperation.second_op`).
:class:`CNodeExprUnaryOperation`    :class:`CNodeExpr`                  Expr     Expression for unary operation such as ``++``, negation, pointer, cast and so on.                                                   One expression child :meth:`CNodeExprUnaryOperation.operand`.
:class:`CNodeExprMemAccess`         :class:`CNodeExpr`                  Expr     Expression which represent a memory access in an array or structure, this do not include simple pointers.                           One or two children: :meth:`CNodeExprMemAccess.obj` as an expression and :meth:`CNodeExprMemAccess.off` which can be an expression or an integer.
=================================== =================================== ======== =================================================================================================================================== =======================================================================================================================================================================================================

Those classes are represented on the schematic of the hexrays architecture:

.. figure:: /_static/img/bip_hexrays_cnode.png

Concrete node types
-------------------

This tables describe the concrete nodes with actual meaning in C. For more
clarity this table has been separated between the statements and the
expressions.

Statements concrete node types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============================= ======================= ================================================================================================== ====================================================================================================================================================================================================================================================================================================================================================================================================================
Class name                    Parent class name       Description                                                                                        Childrens
============================= ======================= ================================================================================================== ====================================================================================================================================================================================================================================================================================================================================================================================================================
:class:`CNodeStmtEmpty`       :class:`CNodeStmt`      Empty statement, should not be present in final AST but this happens.                              None.
:class:`CNodeStmtExpr`        :class:`CNodeStmtFinal` Statement containing an expression.                                                                :meth:`CNodeStmtExpr.value` contains an expression.
:class:`CNodeStmtGoto`        :class:`CNodeStmtFinal` Statement representing a ``goto`` in C, it contains a label number.                                No statement or expression, :meth:`CNodeStmtGoto.value` return the label number.
:class:`CNodeStmtAsm`         :class:`CNodeStmtFinal` Statement containing an asm value (``__asm``), correspond to inline ASM in C.                      No statements or expression, :meth:`CNodeStmtAsm.value` return the list of :class:`~bip.base.Instr` contain in the statement.
:class:`CNodeStmtReturn`      :class:`CNodeStmtFinal` Statement representing a ``return``.                                                               :meth:`CNodeStmtReturn.value` contain the expression the function return.
:class:`CNodeStmtIf`          :class:`CNodeStmt`      Statement representing a ``if``.                                                                   :meth:`CNodeStmtIf.cond` is an expression representing the condition; :meth:`CNodeStmtIf.st_then` is a statement representing the block taken if the condition is true; :meth:`CNodeStmtIf.st_else` is a statement representing the block taken if the condition is false, if there is no ``else`` this will be ``None`` (test with :meth:`CNodeStmtIf.has_else`): ``if (cond) { st_then } else { st_else };``.
:class:`CNodeStmtFor`         :class:`CNodeStmtLoop`  Statement representing a ``for``.                                                                  Three expressions for the :meth:`CNodeStmtFor.init`, :meth:`CNodeStmtFor.cond`, :meth:`CNodeStmtFor.step` (``for (init; cond; step)``) and one statement for the content of the loop: :meth:`CNodeStmtFor.st_body`
:class:`CNodeStmtWhile`       :class:`CNodeStmtLoop`  Statement representing a ``while``.                                                                One expression for the :meth:`CNodeStmtWhile.cond` and one statement for the :meth:`CNodeStmtWhile.st_body` (``while (cond) { st_body };``).
:class:`CNodeStmtDoWhile`     :class:`CNodeStmtLoop`  Statement representing a ``do ... while`` loop.                                                    One expression for the :meth:`CNodeStmtWhile.cond` and one statement for the :meth:`CNodeStmtWhile.st_body` (``do { st_body } while (cond);``).
:class:`CNodeStmtSwitch`      :class:`CNodeStmt`      Statement representing a ``switch`` statement.                                                     One expression for the value tested (:meth:`CNodeStmtSwitch.expr`) and one statement per cases in the switch. The number of statements is variable.
:class:`CNodeStmtContinue`    :class:`CNodeStmt`      Statement representing a ``continue``.                                                             None.
:class:`CNodeStmtBreak`       :class:`CNodeStmt`      Statement representing a ``break``.                                                                None.
:class:`CNodeStmtBlock`       :class:`CNodeStmt`      Statement representing a C block statement.                                                        Contains a list of statements :meth:`CNodeStmtBlock.elts` representing all the statements included in this block. This is used as the root node for all functions.
============================= ======================= ================================================================================================== ====================================================================================================================================================================================================================================================================================================================================================================================================================

Expressions concrete node types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============================= =================================== ============================================================================================================== ================================================================================================================================================================================================
Class name                    Parent class name                   Description                                                                                                    Childrens
============================= =================================== ============================================================================================================== ================================================================================================================================================================================================
:class:`CNodeExprEmpty`       :class:`CNodeExpr`                  Empty node, should never be used but happens sometimes.                                                        None.
:class:`CNodeExprNum`         :class:`CNodeExprFinal`             An immediate number.                                                                                           None.
:class:`CNodeExprFNum`        :class:`CNodeExprFinal`             A floating point number.                                                                                       None.
:class:`CNodeExprStr`         :class:`CNodeExprFinal`             A string in the AST (constant str as integer, str referenced by their address use :class:`CNodeExprObj`).      None.
:class:`CNodeExprObj`         :class:`CNodeExprFinal`             An object representing by its address, this include: globals, functions, strings, ...                          None.
:class:`CNodeExprVar`         :class:`CNodeExprFinal`             An object representing a local variable (:class:`HxLvar`).                                                     None.
:class:`CNodeExprHelper`      :class:`CNodeExprFinal`             An "helper" function: not real functions but created by hexrays. In particular use for intrinsic.              None.
:class:`CNodeExprInsn`        :class:`CNodeExprFinal`             An expression which contains a statements. This should never happend and is **not** implemented.               None.
:class:`CNodeExprType`        :class:`CNodeExprFinal`             An expression which contains a type. This is **not** implemented.                                              None.
:class:`CNodeExprTernary`     :class:`CNodeExpr`                  A C ternary operation.                                                                                         Three expressions: :meth:`~CNodeExprTernary.cond`, :meth:`~CNodeExprTernary.expr1`, :meth:`~CNodeExprTernary.expr2`. C representation is ``cond ? expr1 : expr2``.
:class:`CNodeExprCall`        :class:`CNodeExpr`                  A call to a function, this include call to function pointer.                                                   One expression representing the caller (:meth:`~CNodeExprCall.caller`) and several expressions corresponding to the arguments (:meth:`~CNodeExprCall.args` as a list).
:class:`CNodeExprAsg`         :class:`CNodeExprAssignment`        C assignment operation: ``dst = src``                                                                          Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgbor`      :class:`CNodeExprAssignment`        C assignment operation: ``dst |= src``                                                                         Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgxor`      :class:`CNodeExprAssignment`        C assignment operation: ``dst ^= src``                                                                         Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgband`     :class:`CNodeExprAssignment`        C assignment operation: ``dst &= src``                                                                         Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgadd`      :class:`CNodeExprAssignment`        C assignment operation: ``dst += src``                                                                         Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgsub`      :class:`CNodeExprAssignment`        C assignment operation: ``dst -= src``                                                                         Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgmul`      :class:`CNodeExprAssignment`        C assignment operation: ``dst *= src``                                                                         Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgsshr`     :class:`CNodeExprAssignment`        C assignment operation: ``dst >>= src`` (signed)                                                               Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgushr`     :class:`CNodeExprAssignment`        C assignment operation: ``dst >>= src`` (unsigned)                                                             Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgshl`      :class:`CNodeExprAssignment`        C assignment operation: ``dst <<= src``                                                                        Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgsdiv`     :class:`CNodeExprAssignment`        C assignment operation: ``dst /= src`` (signed)                                                                Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgudiv`     :class:`CNodeExprAssignment`        C assignment operation: ``dst /= src`` (unsigned)                                                              Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgsmod`     :class:`CNodeExprAssignment`        C assignment operation: ``dst %= src`` (signed)                                                                Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprAsgumod`     :class:`CNodeExprAssignment`        C assignment operation: ``dst %= src`` (unsigned)                                                              Two children expressions: :meth:`~CNodeExprAssignment.dst` and :meth:`~CNodeExprAssignment.src`
:class:`CNodeExprComma`       :class:`CNodeExprDoubleOperation`   C comma operator with deux expressions: ``first_op, second_op``. Often used in conditions.                     Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprLor`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op || second_op``                                                                      Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprLand`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op && second_op``                                                                      Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprBor`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op | second_op``                                                                       Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprXor`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op ^ second_op``                                                                       Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprBand`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op & second_op``                                                                       Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprEq`          :class:`CNodeExprDoubleOperation`   C operation for ``first_op == second_op`` (int or float)                                                       Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprNe`          :class:`CNodeExprDoubleOperation`   C operation for ``first_op != second_op`` (int or float)                                                       Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprSge`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op >= second_op`` (signed or float)                                                    Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprUge`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op >= second_op`` (unsigned)                                                           Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprSle`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op <= second_op`` (signed or float)                                                    Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprUle`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op <= second_op`` (unsigned)                                                           Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprSgt`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op > second_op`` (signed or float)                                                     Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprUgt`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op > second_op`` (unsigned)                                                            Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprSlt`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op < second_op`` (signed or float)                                                     Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprUlt`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op < second_op`` (unsigned)                                                            Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprSshr`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op >> second_op`` (signed)                                                             Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprUshr`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op >> second_op`` (unsigned)                                                           Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprShl`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op << second_op``                                                                      Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprAdd`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op + second_op``                                                                       Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprSub`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op - second_op``                                                                       Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprMul`         :class:`CNodeExprDoubleOperation`   C operation for ``first_op * second_op``                                                                       Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprSdiv`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op / second_op`` (signed)                                                              Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprUdiv`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op / second_op`` (unsigned)                                                            Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprSmod`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op % second_op`` (signed)                                                              Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprUmod`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op % second_op`` (unsigned)                                                            Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprFadd`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op + second_op`` (float)                                                               Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprFsub`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op - second_op`` (float)                                                               Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprFmul`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op * second_op`` (float)                                                               Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprFdiv`        :class:`CNodeExprDoubleOperation`   C operation for ``first_op / second_op`` (float)                                                               Two children expressions: :meth:`~CNodeExprDoubleOperation.first_op` and :meth:`~CNodeExprDoubleOperation.second_op`
:class:`CNodeExprPtr`         :class:`CNodeExprUnaryOperation`    Dereferencing a pointer ``*operand``                                                                           One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprFneg`        :class:`CNodeExprUnaryOperation`    C operation for ``-operand`` (float)                                                                           One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprNeg`         :class:`CNodeExprUnaryOperation`    C operation for ``-operand``                                                                                   One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprCast`        :class:`CNodeExprUnaryOperation`    Casting of an expression ``(type)operand``                                                                     One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprLnot`        :class:`CNodeExprUnaryOperation`    C operation for ``!operand``                                                                                   One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprBnot`        :class:`CNodeExprUnaryOperation`    C operation for ``~operand``                                                                                   One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprRef`         :class:`CNodeExprUnaryOperation`    Get the reference of an expression ``&operand``                                                                One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprPostinc`     :class:`CNodeExprUnaryOperation`    C operation for ``operand++``                                                                                  One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprPostdec`     :class:`CNodeExprUnaryOperation`    C operation for ``operand--``                                                                                  One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprPreinc`      :class:`CNodeExprUnaryOperation`    C operation for ``++operand``                                                                                  One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprPredec`      :class:`CNodeExprUnaryOperation`    C operation for ``--operand``                                                                                  One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprSizeof`      :class:`CNodeExprUnaryOperation`    Sizeof of an expression ``sizeof(operand)``                                                                    One child expression: :meth:`~CNodeExprUnaryOperation.operand`
:class:`CNodeExprIdx`         :class:`CNodeExprMemAccess`         Access to an index into an array ``obj[off]``                                                                  Two children expressions: :meth:`~CNodeExprMemAccess.obj` and :meth:`~CNodeExprMemAccess.off`.
:class:`CNodeExprMemref`      :class:`CNodeExprMemAccess`         Access to an element of a structure which is not a pointer ``obj.off``                                         One child expression: :meth:`~CNodeExprMemAccess.obj`. :meth:`~CNodeExprMemref.off` is a integer value.
:class:`CNodeExprMemptr`      :class:`CNodeExprMemAccess`         Access to an element of a structure which is a pointer ``obj->off``                                            One child expression: :meth:`~CNodeExprMemAccess.obj`. :meth:`~CNodeExprMemref.off` is a integer value.
============================= =================================== ============================================================================================================== ================================================================================================================================================================================================

.. _doc-hexrays-astnodes-visitors:

Visitors in Bip
===============

Two types of visitors are implemented in Bip. One use the
``ctree_visitor_t`` provided by IDA and allow to iterate on subclasses of
:class:`~bip.hexrays.HxCItem`. The second one (and the one usually advise
to use) is implemented directly in Bip and iterate on sublcasses of
:class:`~bip.hexrays.CNode`. As a general rule, it should be expected to get
improvement only on the Bip implementation of the visitors.

The Bip implementation of the visitor use a Deep-First Search (DFS) algorithm
with preorder-traversal (the current node is visited before the childs), when
a statement is visited all the childs expression will be visited before the
childs statements. The functions actually implementing this visitor are
documented in :ref:`doc-hexrays-cnode-visitor-api`. The main methods allowing
to use this visitor are :meth:`~bip.hexrays.HxCFunc.visit_cnode` and
:meth:`~bip.hexrays.HxCFunc.visit_cnode_filterlist`.

The IDA implementation can be access through the methods starting
with ``hx_visit_`` methods of :class:`~bip.hexrays.HxCFunc`. See
:ref:`doc-hexrays-ida-visitor-internal` for more information on those.

AbstractCItem API
=================

.. autoclass:: AbstractCItem
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


HxCtype Enum
============

.. autoclass:: HxCType
    :members:
    :member-order: bysource



