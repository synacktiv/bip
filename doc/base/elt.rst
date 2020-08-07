.. _ref-base-elt:

Elements
########

.. module:: bip.base

Basic elements in IDA are all refered by an ID. This can be the address of the
element in the database or a particular ID. For allowing to access easily the
correct element from its ID Bip defines a tree of classes with each leaf
classes in charge of a particular element.

Three abstract classes are defined in Bip:

* :class:`BipBaseElt` : is the parent class of all element in Bip, in
  particular it is in charge of making the interface with :func:`GetElt` and
  :func:`GetEltByName`.
* :class:`BipRefElt` : is the parent class of all elements which can be
  referenced by xref in IDA. This include :class:`BipInstr`, :class:`BipData`,
  :class:`BipStruct` and :class:`BStructMember`.
* :class:`BipElt` : is the parent class of all elements with an actual address
  as ID and provide a lot of common API for thoses elements, this is the
  parent class of :class:`BipInstr` and :class:`BipData`.

For getting a correct element from an ID it is enough to call the
:func:`GetElt` and :func:`GetEltByName` function. As those functions can
return diferent types of objects it can be convenient to use ``isinstance``
for checking the return type of the object.

Internals
=========

Recuperation of the correct element
-----------------------------------

For being able to return an object :func:`GetElt`
(:func:`GetEltByName` is simply a wrapper in top of :func:`GetElt`) must
be able to tell which class should be used. This is done by recursivelly
checking the child classes of :class:`BipBaseElt`, each child classes should
implement the class method :meth:`BipBaseElt._is_this_elt` which take an ID
in argument. If this method return True iteration will continue on child
classes of this class, if it return False it will stop. When all child classes
return False or a leaf as been reach an object of this element is created and
returned.

If two subclasses return True at one level of the recursion, one of them will
be ignored.

All classes which inherit from :class:`BipBaseElt` are expected to take only
their ID in argument for being able to be instantiated by :func:`GetElt` .

Element Functions API
=====================


.. autofunction:: GetElt
.. autofunction:: GetEltByName
.. autofunction:: Here

BipBaseElt API
==============

.. autoclass:: BipBaseElt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

BipRefElt API
=============

.. autoclass:: BipRefElt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

BipElt API
==========

.. autoclass:: BipElt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


