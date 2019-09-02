.. _general-archi:

Bip Project architecture
########################

This part describe the main architecture of Bip. It is a good read for
understanding the global design of Bip, however for starting reading the
:ref:`general-overview` is probably simpler.

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

The module ``bip.hexrays`` contains the interfaces for manipulating the
hexrays decompiler from IDA. This module will not provide anything if an
hexrays decompiler for the current architecture is not set. The following
schematic represent the architecture of this module:

.. figure:: /_static/img/bip_hexrays_cnode.png

TODO: doc, auto generated, other schematic ?

Gui
---

Finally the ``bip.gui`` module is the smallest module, it contains the
interfaces for the user interfaces and the plugins. Its architecture is
represented by this schematic:

.. figure:: /_static/img/bip_gui.png

TODO: classes and interactions

Common code patterns
====================

Bip provide an abstraction in top of the 

TODO: functions which return the correct element and usage of isinstance

Interfacing with IDA
====================

TODO: problem of the fact we keep ref. on the IDA C++ object.



