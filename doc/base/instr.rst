Instructions & Operands
#######################

.. module:: bip.base

Instructions are represented by :class:`BipInstr` objects. They inherit from
:class:`BipElt` and as such have access to xrefs and common methods for
objects with an address. They are also link to their function
(:meth:`~BipInstr.func`) and basic block (:meth:`~BipInstr.block`) if any. Finally
an instruction can have :class:`BipOperand` which can be access using the
:meth:`~BipInstr.ops` property.

The :class:`BipOperand` class represent all types of operand. As this is not the
common design for Bip this will probably be changed soon. For getting the
type of an operand the :meth:`~BipOperand.type` property can be used and
compare with the value of :class:`BipOpType`. The :meth:`~BipOperand.value` allow
to recuperate the value of an operand, the meaning of this value is depending
of its :meth:`~BipOperand.type` and can be architectures dependant. This is
not implemented yet and so is still link to information provided by IDA.

BipInstr API
============

.. autoclass:: BipInstr
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

BipOperand API
==============

.. warning:: This API will probably change in the near future.

.. autoclass:: BipOperand
    :members:
    :member-order: bysource

.. autoclass:: BipOpType
    :members:
    :member-order: bysource

.. autoclass:: BipDestOpType
    :members:
    :member-order: bysource

