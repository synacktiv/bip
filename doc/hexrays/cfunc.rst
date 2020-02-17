Hexrays Functions
#################

.. module:: bip.hexrays

Hexrays function are implemented in Bip by the class :class:`~bip.hexrays.HxCFunc`.
They represent a C function as decompiled by hexrays and are the main
interface for using the features from hexrays in C.

There are two ways to get a :class:`~bip.hexrays.HxCFunc` object using the Bip
API, the first one is by using the :meth:`~bip.base.BipFunction.hxfunc`
property method from a :class:`~bip.base.BipFunction`, this property returns
the equivalent :class:`~bip.hexrays.HxCFunc` for
the :class:`~bip.base.BipFunction`. The second way is to use the class method
:meth:`~bip.hexrays.HxCFunc.from_addr` which take an address in argument and try
to create the corresponding :class:`~bip.hexrays.HxCFunc`. Both of those
methods may fail if Hexrays is not able to decompile the function or if the
address given is not part of a function, in that case an exception
:class:`~bip.base.BipDecompileError` is raised by Bip.

The :class:`~bip.hexrays.HxCFunc` allows to recuperate the C string
of the decompiled function (:meth:`~bip.hexrays.HxCFunc.cstr`), to get the
"normal" :class:`~bip.base.BipFunction` (:meth:`~bip.hexrays.HxCFunc.bfunc`)
and provide to two main features: local variables (lvar) and AST nodes.

Local variables (lvar) are represented by :class:`~bip.hexrays.HxLvar` objects
and are accessible through several methods. The simplest way is to use the
:meth:`~bip.hexrays.HxCFunc.lvars` property which return an array of the
variable. As those variables also include the arguments of the functions the
:meth:`~bip.hexrays.HxCFunc.args` property allows to get only the
:class:`~bip.hexrays.HxLvar`  which are arguments.

The AST nodes of the :class:`~bip.hexrays.HxCFunc` can be accessed in
different ways. Bip provides :class:`~bip.hexrays.CNode` classes
(:class:`~bip.hexrays.CNode` is the parent class for all nodes) which
represents a node of the AST, those are already a second level of abstraction
on top of the hexrays AST node. There are three main ways to access
the :class:`~bip.hexrays.CNode` for a particular function:

* by accessing the :meth:`~bip.hexrays.HxCFunc.root_node` of the AST and then
  making the visit or the treatment as the user which;
* by using visitors already implemented: :meth:`~bip.hexrays.HxCFunc.visit_cnode` 
  or :meth:`~bip.hexrays.HxCFunc.visit_cnode_filterlist` and providing a
  callback, those visitors use a Deep-First Search (DFS) algorithm;
* by using helper methods :meth:`~bip.hexrays.HxCFunc.get_cnode_filter` or
  :meth:`~bip.hexrays.HxCFunc.get_cnode_filter_type` which provides list of
  the resulting nodes, those helpers are based on the visitors.

It is also possible to use the visitor on the first level of abstraction
on top of the hexrays node, those methods start with the prefix
``hx_visit_``.

HxCFunc API
===========

.. autoclass:: HxCFunc
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


