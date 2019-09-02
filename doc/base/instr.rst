Instructions & Operands
#######################

.. module:: bip.base

Instructions are represented by :class:`Instr` objects. They inherit from
:class:`BipElt` and as such have access to xrefs and common methods for
objects with an address. They are also link to their function
(:meth:`~Instr.func`) and basic block (:meth:`~Instr.block`) if any. Finally
an instruction can have :class:`Operand` which can be access using the
:meth:`~Instr.ops` property.

The :class:`Operand` class represent all types of operand. As this is not the
common design for Bip this will probably be changed soon. For getting the
type of an operand the :meth:`~Operand.type` property can be used and
compare with the value of :class:`OpType`. The :meth:`~Operand.value` allow
to recuperate the value of an operand, the meaning of this value is depending
of its :meth:`~Operand.type` and can be architectures dependant. This is
not implemented yet and so is still link to information provided by IDA.

Instr API
=========

.. autoclass:: Instr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Operand API
===========

.. warning:: This API will probably change in the near future.

.. autoclass:: Operand
    :members:
    :member-order: bysource

.. autoclass:: OpType
    :members:
    :member-order: bysource


