Structures
##########

.. module:: bip.base

This part describe the structures (:class:`BipStruct`) and structure members
(:class:`BStructMember`). This two objects inherit from :class:`BipRefElt`
which make them able to be referenced by xref and possible to recuperate using
the :func:`GetElt` function.

Those classes represent
the element view in the ``Struct`` tab. of IDA and are different from the
:class:`BipType` which is used for referencing the type of some elements in
IDA, however they are obviously linked.

Except xrefs the most common way to get a structure is using the
:meth:`~BipStruct.get` class method which expect its name. For creating one
the :meth:`~BipStruct.create` class method is available. Once a struct has
been recuperated it is possible to access the members as a dict by using
their name or their offset (this is not a list and so it is the offset of
the member which is expected not its index).

BipStruct API
=============

.. autoclass:: BipStruct
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

    .. automethod:: __init__

BStructMember API
=================

.. autoclass:: BStructMember
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

    .. automethod:: __init__


