Enum
####

.. module:: bip.base

This part describe the enum (:class:`BipEnum`) and enum members
(:class:`BEnumMember`). The :class:`BEnumMember` class inherit from
:class:`BipRefElt` which allow to get access to the enum members through xref
and possible to recuperate using the :func:`GetElt` function.

Those classes represent
the element view in the ``Enum`` tab. of IDA and are different from the
:class:`BipType` which is used for referencing the type of some elements in
IDA, however they are obviously linked.

Except xrefs the most common way to get an enum is using the
:meth:`BipEnum.get` class method which expect its name. For creating one
the :meth:`BipEnum.create` class method is available. Once an enum has
been recuperated it is possible to access the members as a dict by using
their name or to iterate on all the members. It is also possible to use
the :meth:`BEnumMember.get` class method for directly recuperating an enum
member.

BipEnum API
===========

.. autoclass:: BipEnum
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

BEnumMember API
===============

.. autoclass:: BEnumMember
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


