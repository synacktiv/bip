Xref
####

.. module:: bip.base

XRef are a really important feature of IDA which allow to find the links
between different objects. In Bip they are represented by the :class:`BipXref`
objects. All objects which inherit from :class:`BipRefElt` (including those
which inherit from :class:`BipElt`) posess an API for xref.

An xref is an oriented link between two different element of the IDB. The
object *creating* the xref can be access by using the :meth:`~BipXref.src`
property while the destination can be access using :meth:`~BipXref.dst`,
both of those property return object which inherit from :class:`BipBaseElt`;
it is possible to get their ID using :meth:`~BipXref.src_ea` and
:meth:`~BipXref.dst_ea`.

Some flags are available allowing to check the type of xref and most object
allowing to access them provide properties allowing to access directly more
specific objects.

Here is a list of objects which can access xref through the interface
provided by :class:`BipRefElt` :

* :class:`BipRefElt`
* :class:`BipElt`
* :class:`Instr`
* :class:`BipData`
* :class:`BipStruct`
* :class:`BStructMember`

The :class:`BipFunction` also possess an interface with xrefs.

BipXref API
===========

.. autoclass:: BipXref
    :members:
    :member-order: bysource
    :special-members:
    :private-members:



