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
to not find anywhere the subclasses of :class:`~bip.hexrays.CNode`.  For more
information see :ref:`doc-hexrays-cnode-generation-internal`.

.. _doc-hexrays-astnodes-nodetype:

AST Node types
==============

TODO: 
Two types of node: expr and statement
TODO:
name class | parent class (type ?) | description

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



