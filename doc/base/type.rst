.. _doc-bip-base-type:

Type
####

.. module:: bip.base

Types are used every where in IDA: data (:class:`BipData`),
functions (:class:`BipFunction`), local variable
(:class:`~bip.hexrays.HxLvar`) ... In Bip all types are reprensented as
an object which inherit from :class:`BipType`. :class:`BipType` objects can
be recursive: a pointer will be represented by the :class:`BTypePtr` which
will contain a reference on the pointed type, a :class:`BTypeFunc` in the
case of a function pointer for example. All subclasses of :class:`BipType`
start with the prefix ``BType*``.

For creating a new :class:`BipType` the easiest way is to use the
:meth:`BipType.FromC` static method: it will create an object which inherit
from :class:`BipType` of the correct class from a string representing the C
declaration of the type.

When recuperating a type from IDA (``tinfo_t``) Bip will try to determine the
correct object much the same way it is done for the :class:`BipBaseElt` when
using :func:`GetElt`. This is made using the static method
:func:`BipType.GetBipType` and the class method for determining the correct
class is :meth:`BipType.is_handling_type`.

Here is a quick descriptions of the different types implemented in Bip:

======================= =======================================================================================================================================
Type name               Description
======================= =======================================================================================================================================
:class:`BTypeEmpty`     An empty type, should never happen but...
:class:`BTypePartial`   A type where the size is known but without any other information.
:class:`BTypeVoid`      The ``void`` type (not ``void*`` just ``void``).
:class:`BTypeInt`       An ``int``, can have different size, be signed or unsigned.
:class:`BTypeBool`      A boolean, can have different size.
:class:`BTypeFloat`     A float or double.
:class:`BTypePtr`       A pointer, recursive type, :meth:`~BTypePtr.pointed` for getting the subtype.
:class:`BTypeArray`     An array, recursive type (:meth:`BTypeArray.elt_type`), have a number of element.
:class:`BTypeFunc`      A function, recursive type for arguments and return value. Also access to the arguments name and their numbers.
:class:`BTypeStruct`    A structure, rescursive type for the members. This is different from :class:`BipStruct`.
:class:`BTypeUnion`     A union, rescursive type for the members.
:class:`BTypeEnum`      An enum, bugged before IDA 7.3, implementation is not finished.
======================= =======================================================================================================================================


BipType API
===========

.. autoclass:: BipType
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BTypeEmpty
    :members:
    :member-order: bysource

.. autoclass:: BTypePartial
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BTypeVoid
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BTypeInt
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BTypeBool
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BTypeFloat
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BTypePtr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BTypeArray
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BTypeFunc
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BTypeStruct
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BTypeUnion
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BTypeEnum
    :members:
    :member-order: bysource
    :special-members:
    :private-members:



