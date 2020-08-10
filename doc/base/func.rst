Functions & Basic blocks
########################

.. module:: bip.base

:class:`BipFunction` are created by passing them an address. They are
container for basic block (:class:`BipBlock` accessible using
the :meth:`~BipFunction.blocks` property) and instruction (:class:`BipInstr`
accessible using the :meth:`~BipFunction.instr` property). :class:`BipBlock`
them self contain instructions, a link back to the function
(property :meth:`~BipBlock.func`) and a way to navigate them using the
property :meth:`~BipBlock.succ` and :meth:`BipBlock.pred` .

:class:`BipFunction` can also allow to recuperate the hexrays decompile
version of their code when available, this is done using the
:meth:`~BipFunction.hxcfunc` property which return a
:class:`~bip.hexrays.HxCFunc` object when available.

For example of how to use functions and blocks see the
:ref:`general-overview` .

BipFunction API
===============

.. autoclass:: BipFunction
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

BipBlock API
============

.. autoclass:: BipBlock
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BipBlockType
    :members:
    :member-order: bysource





