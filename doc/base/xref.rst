Xref
####

.. module:: bip.base

XRef are a really important feature of IDA which allow to find the links
between different objects. In Bip they are represented by the :class:`BipXref`
objects. All objects which inherit from :class:`BipRefElt` (including those
which inherit from :class:`BipElt`) posess an API for xref.

Here is a list of objects which can access xref:

* :class:`BipRefElt`
* :class:`BipElt`
* :class:`Instr`
* :class:`BipData`
* :class:`BipStruct`
* :class:`BStructMember`

BipXref API
===========

.. autoclass:: BipXref
    :members:
    :member-order: bysource
    :special-members:
    :private-members:



