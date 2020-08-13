Data
####

.. module:: bip.base

The :class:`BipData` objects inherit from :class:`BipElt` and are used for
representing data which means everything which is not code.

:class:`BipData` object can be created by calling the constructor with the
data address but in a more generic way it is possible to use the
:func:`GetElt` or :func:`GetEltByName` for recuperating them.
:class:`BipData` will be create by :func:`GetElt` if IDA considered the
address as data or unknown. As they are inheriting from :class:`BipRefElt` it
is possible to use the xref API through them (for access to and from them).

The most basic usage will be to recuperate or set a value using the property
:meth:`~BipData.value`. This property depends of the type
which can be access and modify through the :meth:`~BipData.type` property,
this property return and expect a :class:`BipType` object. It is also possible
to access directly the :meth:`BipElt.bytes` of the object.

:class:`BipData` provides some static methods for accessing and
modifying data of the IDB without creating an object, in particular the
:meth:`~BipData.get_cstring` which allow to get a C string from an address.
Finally it is possible to iterate on all defined :class:`BipData` using the 
class method :class:`BipData.iter_heads`.

BipData API
===========

.. autoclass:: BipData
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


