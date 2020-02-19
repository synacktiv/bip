.. _doc-hexrays-cnode:

CNode
#####

.. module:: bip.hexrays

The :class:`~bip.hexrays.CNode` API is one of the representation in Bip for
the AST nodes of an Hexrays decompiled function. Of the two representations,
it is the one which is prefered. The class :class:`~bip.hexrays.CNode` is an
abstract class which is used as parent for the actual classes representing the
nodes. For more informations about AST nodes and their different types see
:ref:`doc-hexrays-astnodes`.

For recuperating the :class:`~bip.hexrays.CNode` objects for a particular
function several methods of :class:`~bip.hexrays.HxCFunc` can be used:

* the :meth:`~bip.hexrays.HxCFunc.root_node` property for getting the root of
  the AST for a particular function;
* the :meth:`~bip.hexrays.HxCFunc.get_cnode_filter` and
  :meth:`~bip.hexrays.HxCFunc.get_cnode_filter_type` methods provide list of
  the nodes in the functions (those are based on the visitors);
* the :meth:`~bip.hexrays.HxCFunc.visit_cnode` 
  and :meth:`~bip.hexrays.HxCFunc.visit_cnode_filterlist` methods which allow
  to visit the AST using a Deep-First Search (DFS) algorithm
  with preorder-traversal.

For a list of possible node type see :ref:`doc-hexrays-astnodes-nodetype`.

Two internal mechanisms are important to understand
the :class:`~bip.hexrays.CNode` implementation:

* all :class:`~bip.hexrays.CNode` are generated from a ``citem_t`` object in
  IDA, the correct classes is determine depending of the type of
  the ``citem_t`` (:class:`~bip.hexrays.HxCType`). The
  :meth:`~bip.hexrays.CNode.GetCNode` static method exist for finding the
  correct child class of :class:`~bip.hexrays.CNode` corresponding to the
  ``citem_t`` and creating it, as a general rule the constructors should not
  be called directly.
* most of the :class:`~bip.hexrays.CNode` subclasses are created dynamically
  from their equivalent :class:`~bip.hexrays.HxCItem`, this is for avoiding
  code duplication. For more information
  see :ref:`doc-hexrays-cnode-generation-internal`.

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

Assignment
----------

.. autoclass:: CNodeExprAssignment
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

Methods specific to CNode implementation
========================================

This list the methods which exist only in the implementation of
the :class:`~bip.hexrays.CNode` and not in the :class:`~bip.hexrays.HxCItem`.
Those methods are documented correctly in their respective class, they are
listed here only as an easy way to see functionnality which are
:class:`~bip.hexrays.CNode` specific. Access to parent
:class:`~bip.hexrays.HxCFunc` and parent node are not listed here.

========================   ===============================================
Classes                    Methods
========================   ===============================================
:class:`CNodeExprVar`      :meth:`~bip.hexrays.CNodeExprVar.lvar`
:class:`CNodeExprVar`      :meth:`~bip.hexrays.CNodeExprVar.lvar_name`
========================   ===============================================


.. _doc-hexrays-cnode-visitor-api:

Internal Hexrays Visitor API
============================

.. automodule:: bip.hexrays.cnode_visitor
   :members:

.. _doc-hexrays-cnode-generation-internal:

CNode generation and internals
==============================

This description explains how the :class:`~bip.hexrays.CNode` subclasses are
created and is mainly destined to developers and maintainers of Bip.

For avoiding code duplication most classes which inherit
from :class:`~bip.hexrays.CNode` are created dynamically from their equivalent
:class:`~bip.hexrays.HxCItem` (the direct wrapper on the IDA implementation).
The classes for both representation will have mainly the same attributes and
the same method. When generating the :class:`~bip.hexrays.CNode` subclasses
the names for the classes are generated by replacing the ``HxC`` prefix by
the ``CNode`` prefix, for example :class:`~bip.hexrays.HxCExprAdd` will become
:class:`~bip.hexrays.CNodeExprAdd`.

Three classes are not generated dynamically. The :class:`~bip.hexrays.CNode`
class (equivalent to :class:`~bip.hexrays.HxCItem`) which contains the added
method and attributes which are specific to this implementation, this is the
main based abstract class for all of this implementation. Both
:class:`~bip.hexrays.CNode` and :class:`~bip.hexrays.HxCItem` inherit from 
the :class:`~bip.hexrays.AbstractCItem` abstract class which contains most
of the code common to those two classes. The :class:`~bip.hexrays.CNodeExpr`
(equivalent to :class:`~bip.hexrays.HxCExpr`) and
:class:`~bip.hexrays.CNodeStmt` (equivalent to :class:`~bip.hexrays.HxCStmt`)
classes are not generated dynamically mainly because their constructors must
be changed.

.. note::

    It is possible that the :class:`~bip.hexrays.CNodeExpr` and 
    :class:`~bip.hexrays.CNodeStmt` will be generated dynamically in the
    future.

All other subclasses of :class:`~bip.hexrays.CNode` are created dynamically
using the :func:`~bip.hexrays.cnode.buildCNode` class decorator. This
decorator is used on all the :class:`~bip.hexrays.HxCItem` subclasses and
for each class it is used on it will create the equivalent
:class:`~bip.hexrays.CNode` subclasses. For doing that the following steps are
taken:

* recreating the architecture of inheritance for the new class,
* performing a copy of the attributes of the base class and modifying the
  ``__doc__`` and ``__module__``,
* creating the name for the new class (replace ``HxC`` by ``CNode`` prefix),
* adding methods which are specific to the CNode version of the implementation
  if any,
* creating the actual new class,
* registering the new class in the corresponding module globals
  (``bip.hexrays.cnode`` accessible for a user directly from ``bip.hexrays``
  or from ``bip``) for being able to access it later on,
* registering the new class for being able to create the equivalent when
  rebuilding the inheritance.

For being able to rebuild the inheritance of the class it is necessary to
keep an equivalence between the :class:`~bip.hexrays.HxCItem` subclasses and
the :class:`~bip.hexrays.CNode` ones. This equivalence is stored in the
:data:`~bip.hexrays.cnode._citem2cnode` global dictionary and updated each
time a new class is created by the :func:`bip.hexrays.cnode.buildCNode`
decorator (first and last step of the previous algorithm).

.. note::

    The system of using :func:`bip.hexrays.cnode.buildCNode` as a
    decorator may be changed in the future as a metaclass is probably more
    appropriate for this.

For being able to add new methods to a :class:`~bip.hexrays.CNode` subclass,
another decorator exists: :func:`~bip.hexrays.cnode.addCNodeMethod`. This
decorator take in argument a string representing the name of the CNode
subclasses the method should be added and an optional second argument
which allow to specify a different name for the class method than the one
the function decorated has. This decorator will simply add the
method in the :data:`~bip.hexrays.cnode._cnodeMethods` global array which 
will then be used by the :func:`~bip.hexrays.cnode.buildCNode` decorator for
adding the methods and properties at the class creation. Because of the way
this work it is necessary for all specific methods to be created **before**
the actual class creation. Presently, because the number of specific methods
is quite small, those methods are directly at the end of the ``cnode.py``
file.

Internal generation API
-----------------------

Those functions are not currently exported by Bip, and are documented for
internal use only:

.. autofunction:: bip.hexrays.cnode.buildCNode

.. autofunction:: bip.hexrays.cnode.addCNodeMethod

.. autodata:: bip.hexrays.cnode._cnodeMethods
    :annotation:

.. autodata:: bip.hexrays.cnode._citem2cnode
    :annotation:


