.. _general-archi:

Bip Project architecture
########################

This part describe the main architecture of Bip. It is a good read for
understanding the global design of Bip, however for starting reading the
:ref:`general-overview` is probably simpler.

The `Module architecture`_ part describes how the different modules and
classes are interfaced together, the `common code patterns`_ part explains how
Bip was developped for being used, finally the `interfacing with IDA & limitations`_ part
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

.. warning::

    When asking the hexrays decompiler to decompile again a function (``F5``)
    a new object representing the decompiled function will be created, if a
    :class:`HxCFunc` was recuperated before that it will not use the
    correct object which can lead to wierd behavior.

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
    to make efficient link with other components, the simplest example is the
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
    see :ref:`doc-hexrays-cnode-generation-internal`.

Example of AST
~~~~~~~~~~~~~~

As an illustration of the AST view, lets look at a really simple function with
the following code decompiled:

.. code-block:: C

    // this is a simple example written by hand for explaining how this works,
    //   hexrays may optimize this equivalent code differently.
    int f(int a1, int *a2) {
        int v1;

        v1 = a1 + 2; // (1)
        if (a2) // (2)
            return v1 + 3; // (3)
        return v1; // (4)
    }

.. note::

    All the class given there after are the one for the
    :class:`~bip.hexrays.CNode` implementation but it works exactly the same
    for the :class:`~bip.hexrays.HxCItem` implementation.

.. note::

    Depending on the IDA version, the tree structure may change however the
    idea how the AST works should stay the same.

A :class:`~bip.hexrays.HxCFunc` :meth:`~bip.hexrays.HxCFunc.root_node` should
always be a :class:`~bip.hexrays.CNodeStmtBlock`. This node will contain a
list of other statments representing the content of the function.

The first statement (1) contained in the :meth:`~bip.hexrays.HxCFunc.root_node`
will be a :class:`~bip.hexrays.CNodeStmtExpr` which is just a statement
containing an expression. This expression will be
a :class:`~bip.hexrays.CNodeExprAsg` which represent an assignment, this
expression contains two operands and inherit from the
:class:`~bip.hexrays.CNodeExprDoubleOperation` abstract class. The first
operand (:meth:`~bip.hexrays.CNodeExprDoubleOperation.first_op`) will be the
left part of the assignment: a local variable (``v1``) which is represented by
the :class:`~bip.hexrays.CNodeExprVar` with a value of ``2``, this value
correspond to the index in the local variable array and arguments of the
function counts also (so ``a1`` will be at index ``0``), its possible to
directly get the :class:`~bip.hexrays.HxLvar` object corresponding using the
:meth:`~bip.hexrays.CNodeExprVar.lvar` property. The right part of the
assignment will be a :class:`~bip.hexrays.CNodeExprAdd` node with 2 childs
himself: a :class:`~bip.hexrays.CNodeExprVar` again for ``a1`` and a
:class:`~bip.hexrays.CNodeExprNum` for the number ``2``.

The second statement (2) contained in the
:meth:`~bip.hexrays.HxCFunc.root_node` will be
a :class:`~bip.hexrays.CNodeStmtIf` which contains 2 childs: an expression
for the condition and a statement for the content of the ``if``, if
an ``else`` was present a third child will be present (a statement again).
The expression for the condition will once again be a
:class:`~bip.hexrays.CNodeExprVar`.

The content of the ``if`` (3) will be a
:class:`~bip.hexrays.CNodeStmtBlock` with only one statement in it a
:class:`~bip.hexrays.CNodeStmtReturn` representing the ``return``, itself
containing a :class:`~bip.hexrays.CNodeExprAdd` once again for the ``v1 + 3``.

The last statement will be :class:`~bip.hexrays.CNodeStmtReturn` statement
containing a :class:`~bip.hexrays.CNodeExprVar`.

As can be seen in this simple example this is a pretty straight forward AST
structures, however for being able to use it well a good understanding of 
the node types is better. For a complete list of the different types of
:class:`~bip.hexrays.CNode` see :ref:`doc-hexrays-astnodes-nodetype`.

Gui
---

.. module:: bip.gui

Finally the ``bip.gui`` module is the smallest module, it contains the
interfaces for the user interfaces and the plugins. Its architecture is
represented by this schematic:

.. figure:: /_static/img/bip_gui.png

The most important part of this module for a user is the
:class:`BipPlugin` system. Bip defines its own plugin system which is
separated from the one of IDA, each plugin should inherit from the class
:class:`BipPlugin` (directly or indirectly) and will be loaded by the
:class:`~bip.gui.pluginmanager.BipPluginManager` . Each Bip plugin should
be a singleton and can be recuperated using the
:class:`~bip.gui.pluginmanager.BipPluginManager`, which is itself a singleton
and a *real* IDA Plugin (recuperated using :func:`get_plugin_manager`).

Activities are objects made for interfacing with different parts of
IDA, and in particular for being able to be used as decorator of methods of a
:class:`BipPlugin`. The :class:`BipActivity` is an abstract class which is a
callable and expect a handler and a way to register with the IDA interface.
The simplest example of Activity is the :class:`BipAction` which allows to
define menu entry or shortcuts (*hot-key*) in IDA, as a general rule they
are made to being used as decorator in a similar way as the ``property``
decorator of Python.

.. note:: **BipActivityContainer**

    The :class:`BipActivityContainer` is a particular activity containing
    several activities and which does not do any action by it-self. It is made
    for allowing to chain decorators on the same method.

For more information about writing plugins and their internal
see :ref:`gui-plugins`.

Common code patterns
====================

Bip class identification
------------------------

Bip provide an abstraction in top of several objects in IDA, several different
classes in Bip can be used for representing the same IDA objects (ex.:
:class:`~bip.hexrays.CNode`, :class:`~bip.base.BipType`, ...). Each different
class will provide different functionalities depending on attribute(s) of the
underlying IDA object, this allows to avoid trying to use features which are
not set or invalid in the IDA object and to clarify the usage of those
objects.

In most cases Bip will provide one static function or one static method which
allows to get the object of the correct class (ex: :func:`~bip.base.GetElt`,
:func:`~bip.base.GetEltByName`, :meth:`~bip.hexrays.CNode.GetCNode`, ...).
Most parent classes of the objects provide ways to test which kind of object
will be produced. However, the intended way to check for the object type is
to use the ``isinstance`` function with the object type being tested.

Here are a few examples of how it was intended to be used. In this first
example the first instruction of a function is recuperated using
:func:`~bip.base.GetEltByName`, in this case we know it is an instruction
(:class:`~bip.base.Instr`) but the function can return other subclasses
of :class:`~bip.base.BipElt`. We then look at the :class:`~bip.base.BipElt`
which reference this address, some are :class:`~bip.base.Instr` and some
are :class:`~bip.base.BipData`, for knowing which is which we
use ``isinstance``.

.. code-block:: pycon

    >>> from bip import *
    >>> elt = GetEltByName("RtlQueryProcessLockInformation")
    >>> elt # first instruction of RtlQueryProcessLockInformation
    Instr: 0x1800D2FF0 (mov     rax, rsp)
    >>> elt.is_code # this are common property to BipElt which are used to get the correct object
    True
    >>> elt.is_data
    False
    >>> for e in elt.xEltTo: # here we get the Elt xref, elements can be Instr or BipData
    ...   if isinstance(e, Instr): # in case of instr we want to print the mnemonic
    ...     print("Found instr at 0x{:X} which ref function, with mnemonic: {}".format(e.ea, e.mnem))
    ...   elif isinstance(e, BipData): # for BipData there is no mnemonic available and so we just want the address
    ...     print("Found data ref at 0x{:x}".format(e.ea))
    ...   else:
    ...     print("Something else ?? {}".format(e))
    Found instr at 0x1800C12A2 which ref function, with mnemonic: call
    Found data ref at 0x1801136d7
    Found data ref at 0x1801434a8
    Found data ref at 0x18016c7fc

This next example show how to check for types. All types in Bip inherit from 
:class:`~bip.base.BipType`, the :meth:`~bip.base.BipType.GetBipType` method
allow to get the correct Bip object from the ``tinfo_t`` object used by
IDA (which is used for all different types). In most cases there is no need
to go through this method, Bip objects which are typed should have a ``type``
property which should allow to get their type and
the methods :meth:`~bip.base.BipType.FromC` and
:meth:`~bip.base.BipType.get_at` should allow to get the correct value easily.
However when scripting it is often interesting to look at the type of an
object, more information about types and the different classes which represent
them can be found in the :ref:`doc-bip-base-type` documentation. Here is a
small example of how to look at the types, we start with a
:class:`~bip.base.BTypeStruct` and look at the members, if a member is a
pointer (:class:`~bip.base.BTypePtr`) we look at the subtype pointed.

.. code-block:: pycon

    >>> from bip import *
    >>> tst = BipType.FromC("struct {char a; int b; void *c; __int64 d; char *e; void *(*f)(int i);}")
    >>> tst.members_info
    {'a': <bip.base.biptype.BTypeInt object at 0x0000029B22C24160>, 'c': <bip.base.biptype.BTypePtr object at 0x0000029B22C24128>, 'b': <bip.base.biptype.BTypeInt object at 0x0000029B22C24390>, 'e': <bip.base.biptype.BTypePtr object at 0x0000029B22C244A8>, 'd': <bip.base.biptype.BTypeInt object at 0x0000029B22C24438>, 'f': <bip.base.biptype.BTypePtr object at 0x0000029B22C24048>}
    >>> for i in range(tst.nb_members):
    ...     if isinstance(tst.get_member_type(i), BTypePtr):
    ...        print("We have a ptr for member {}! Type pointed is: {}".format(tst.get_member_name(i), tst.get_member_type(i).pointed.str))
    ...     else:
    ...        print("Not a pointer for member {}, type is: {}".format(tst.get_member_name(i), tst.get_member_type(i).str))
    Not a pointer for member a, type is: char
    Not a pointer for member b, type is: int
    We have a ptr for member c! Type pointed is: void
    Not a pointer for member d, type is: __int64
    We have a ptr for member e! Type pointed is: char
    We have a ptr for member f! Type pointed is: void *__stdcall(int i)

This is also the case when using visitors in hexrays. The Bip visitors return
objects which inherit from the :class:`~bip.hexrays.CNode` class. As
in the other example, the easiest way to determine which types of node is to
use ``isinstance``. An example of this can simply be found in the overview in
the part :ref:`general-overview-cnode-visit` in the ``visit_call`` functions,
it is also shown indirectly through the usage of the method
:meth:`~bip.hexrays.HxCFunc.visit_cnode_filterlist` which takes a list of
class in argument, under the hood this function will visit all nodes and call
the callback only for the one being instance of one of the class passed in the
second argument.

It is worth noticing that in most cases the underlying object or identifier
used by IDA will be kept in reference in one of the private attributes of the
object.

Interfacing with IDA & limitations
==================================

This part of the documentation describe some limitations of Bip and some
problems and limitations which can occur because of the interface with IDA.
Basic usage of the API for recuperating should not create many of those
problems, one noticeable exception is when modifying the database using the
GUI and reusing objects which have been kept from before the modification,
this, of course, include the *undo* feature of IDA. More "advanced" usage and
developers should consider being careful about those. 

In a lot of case IDA provides API which allows to recuperate the information
necessary, however, in some cases the IDAPython API do not offer such
useful wrappers and for being able to get the full benefits of the available
API it is necessary to recuperate reference to the underlying objects. Those
objects are available in Python through the swig interface (part of IDAPython)
build by IDA on top of their C++ API. As a general rule, people from hexrays
encourage avoiding keeping references on those objects, but as said earlier
there is not always a choice. Because of this several problems exist.

The first is a really simple problem but hard to solve: when keeping an object
of a type in Bip the underlying IDB can be changed (using the API or the GUI).
This can make the current object of Bip invalid. A simple example of this
will be to recuperate an :class:`~bip.base.Instr` object
using :func:`~bip.base.GetElt` and then to undefine this element using the GUI.
If :func:`~bip.base.GetElt` is called again a  :class:`~bip.base.BipData`
object will be returned, which is the object expected. However, if the previous
object is used, it can lead to unexpected behavior because this address is
not an instruction anymore, for example the
property :class:`~bip.base.Instr.mnem` will return an empty string. 

For avoiding this problem as much as possible, Bip tries to avoid keeping
references to the IDA objects or to memoize information, but often this is not
possible and it has an overall cost in performance. As a general rule when
doing modifications to the IDB the user should be careful to fetch again the
object instead of re-using them. Sadly there is actually no solution
implemented in Bip for solving this problem. In theory it could be implemented
using the event API of hexrays but this may create several other complex
problems if it is even possible.

Another common problem of using the IDA objects is that
`wrappers are only wrappers <https://www.hex-rays.com/blog/idapython-wrappers-are-only-wrappers/>`_ .
What this basically said is that we have to handle the management of our
objects in python as they are in C++, with SWIG in the middle. This include
the example in the blogpost but also several others, such as for example
the ones link to the :ref:`doc-bip-base-type` API (look for the warning). As
a rule, having problem with the memory management when using the Bip
standard (not private) API is not considered normal and can be
reported as a bug. However this can force development to make some
particular choice for enforcing this.

Finally, the *undo* feature provided in IDA may invalidate any or all of the
internal object use by IDA ("The simplest approach is to assume that the
database has completely changed and to re-read information from the database
to the memory." and "Plugins in general should not cache and reuse pointers to
kernel objects (like func_t, segment_t). These pointers may change between
plugins invocations."
from `Undo: IDA can do it <https://www.hex-rays.com/products/ida/7_3/undo/>`_).
As there is nothing really possible to do at that point for supporting such
a thing and trying to actualize all possible objects when an *undo* or *redo*
is simply not acceptable it is advice to simply disable this feature.



