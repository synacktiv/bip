.. _general-archi:

Bip Project architecture
########################

This part describe the main architecture of Bip. It is a good read for
understanding the global design of Bip, however for starting reading the
:ref:`general-overview` is probably simpler.

The `Module architecture`_ part describes how the different modules and
classes are interfaced together, the `common code patterns`_ part explains how
Bip was developped for being used, finally the `interfacing with IDA`_ part
explains how the interface with IDA is made and problems link to that design.

Module architecture
===================

Bip is decomposed in three main modules: ``bip.base``, ``bip.hexrays`` and
``bip.gui``.

Base
----

.. module:: bip.base

The module ``bip.base`` is in charge of all the basic interfaces with IDA for
manipulating and modifying the IDB. The following schematic represent the
main classes and their link together:

.. figure:: /_static/img/bip_base2.png

Those classes represent the main elements which can be accessed and
manipulated using Bip. Several *building blocks* exist inside this module:

* The **elements** (:class:`BipBaseElt`, :class:`BipRefElt` and :class:`BipElt`)
  are abstract classes which allow to provide common interfaces for their
  child classes. The :func:`GetElt` and :func:`GetEltByName` allow to
  recuperate directly the correct child class from their ID or their name.
  This allow to provide an easy to use way to get the correct object from
  just an address or an ID, this is in particular used for xref. For more
  information see :ref:`ref-base-elt`.
* The **xrefs** allow to make link with all childs objects of :class:`BipRefElt`
  (:class:`Instr`, :class:`BipData`, :class:`BipStruct`,
  :class:`BStructMember`) and with :class:`BipFunction`. Xref are represented
  by the :class:`BipXref` classes but in most case methods are provided
  for recuperating directly the correct object or address without using
  directly those objects. Xref can be of several types depending if they
  are link because of data or code, they also include the control flow links.
* The **structure** are represented by two different but linked classes:
  :class:`BipStruct` and :class:`BStructMember`. A :class:`BipStruct` will
  keep references to its members and a member will keep a reference to its
  struct. Both of those class can use xref through the API they inherit
  from :class:`BipRefElt`.
* The **type** are represented by the abstract class :class:`BipType` and
  several child classes starting by the prefix ``BType``. Types are used in
  numerous occasions and impact both the analysis and the comportement of IDA.
  For more information on how they work in Bip see :ref:`doc-bip-base-type`.
* The **instructions** and **data** inherit from :class:`BipElt` and so
  possess access to xref api provided by :class:`BipRefElt` but also numerous
  API link to the fact of having an address and potentially data ("bytes").
  :class:`BipData` are also linked to the :class:`BipType` which directly
  impact the behavior of some methods. :class:`Instr` possess references to
  the :class:`BipFunction` and :class:`BipBlock` when they exist and can also
  allow to manipulate :class:`BipOperand`.
* The **functions** (:class:`BipFunction`) are a critical link to the API: they possess
  :class:`BipXref`, allow link to their basic block (:class:`BipBlock`) and
  the :class:`Instr`. They provide also methods for accessing their callers
  and callees. Finally they make the link between the ``bip.base`` module and
  the ``bip.hexrays`` module.

Hexrays
-------

.. module:: bip.hexrays

The module ``bip.hexrays`` contains the interfaces for manipulating the
hexrays decompiler from IDA. This module will not provide anything if an
hexrays decompiler for the current architecture is not set. The following
schematic represent the architecture of this module:

.. figure:: /_static/img/bip_hexrays_cnode.png

The central part of the ``bip.hexrays`` module is the :class:`HxCFunc`
which is used for representing a C function as decompiled by HexRays.
A :class:`HxCFunc` allows to access local storage of the function *lvar*
represented by :class:`HxLvar` which have a name, a type and may or not be
arguments of the function. The second interesting part about :class:`HxCFunc`
is they allow access to the AST created by HexRays, this AST represent a
subset of C and it is possible to use visitors for inspecting the nodes from
which it is composed.

:class:`CNode` is an abstract class (all class are abstract for the CNode
except the leaf of the inheritance tree) which represent a node of the AST,
two main types of node exist: :class:`CNodeStmt` which represent a C
statement (*if*, *for*, *while*, *block*, *goto*, *continue*, *return*, ...)
and :class:`CNodeExpr` which represent C expressions (arithmetic and logic
operations, function calls, cast, memory access, ...). As an AST is a tree
most nodes will have children: :class:`CNodeStmt` can have :class:`CNodeExpr`
or :class:`CNodeStmt` as children, while :class:`CNodeExpr` can only have
other :class:`CNodeExpr` as children. For helping to manipulate those objects
some intermediate abstract class are define such as :class:`CNodeExprFinal`
which represent all expressions without child.

For more information about the usage and implementation of hexrays see
:ref:`index-hexrays`.

.. note:: **CNode and HxCItem**

    It is expected of a Bip user to use :class:`CNode` for manipulating
    AST nodes but in practice two different implementations of the hexrays AST
    nodes exist in Bip: the :class:`CNode` and the :class:`HxCItem`. Those two
    implementations are in fact exactly the same with the only difference
    that the :class:`CNode` objects have a link to their :class:`HxCFunc`
    and there parent :class:`CNode` object in the AST (at the exception of
    the root node which does not have a parent).
    
    This difference in implementation allow to travel more easilly the AST and
    to make efficient link with other components, the simplest exemple is the
    possibility to create a link between the :class:`CNodeExprVar` object
    and the corresponding :class:`HxLvar` object, while it is not possible
    using the :class:`HxCExprVar` object (this may have change since IDA 7.3
    with the access to the microcode API in IdaPython).

    For avoiding code duplication all the :class:`CNode` classes are
    automatically generated from their equivalent :class:`HxCItem` classes at
    the exception of :class:`CNode` (equivalent to :class:`HxCItem`),
    :class:`CNodeExpr` (:class:`HxCExpr`) and :class:`CNodeStmt`
    (:class:`HxCStmt`). Every change in the :class:`HxCItem` classes will
    also change the comportement of the equivalent :class:`CNode` classes. The
    methods unique to the :class:`CNode` classes are present in the
    ``cnode.py`` file and use the ``@addCNodeMethod`` decorator.

    For more information about the internal implementation of :class:`CNode`
    see TODO.

Gui
---

.. module:: bip.gui

Finally the ``bip.gui`` module is the smallest module, it contains the
interfaces for the user interfaces and the plugins. Its architecture is
represented by this schematic:

.. figure:: /_static/img/bip_gui.png

The most important part define in this module for a user is the
:class:`BipPlugin` system. Bip defines its own plugin system which is
separated from the one of IDA, each plugin should inherit from the class
:class:`BipPlugin` (directly or indirectly) and will be loaded by the
:class:`~bip.gui.pluginmanager.BipPluginManager` . Each Bip plugin should
be a singleton and can be recuperated using the
:class:`~bip.gui.pluginmanager.BipPluginManager`, which is itself a singleton
and a *real* IDA Plugin (recuperated using :func:`get_plugin_manager`).

Activities are objects made for interfacing with different part of
IDA, and in particular for being able to be used as decorator of methods of a
:class:`BipPlugin`. The :class:`BipActivity` is an abstract class which is a
callable and expect a handler and a way to register with the IDA interface.
The simplest exemple of Activity are the :class:`BipAction` which allow to
define menu entry or shortcut (*hot-key*) in IDA, as a general rule their
are made to being used as decorator which are made for working the same way
than the ``property`` decorator of Python.

.. note:: **BipActivityContainer**

    The :class:`BipActivityContainer` is a particular activity containing
    several activities and which does not do any action by it-self. It is made
    for allowing to chain decorators on the same method.

For more information about writting plugins and there internals
see :ref:`gui-plugins`.

Common code patterns
====================

Bip provide an abstraction in top of the 

TODO: functions which return the correct element and usage of isinstance

Interfacing with IDA
====================

TODO: problem of the fact we keep ref. on the IDA C++ object.



