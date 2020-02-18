Local variables
###############

.. module:: bip.hexrays

Local variables (lvar) are implemented in Bip by the class
:class:`~bip.hexrays.HxLvar`. They represent a local variable (including
arguments) such as view by the decompiler. 

The main way to access the :class:`~bip.hexrays.HxLvar` is through
a :class:`~bip.hexrays.HxCFunc` object using, for exemple the
:meth:`~bip.hexrays.HxCFunc.lvars` property.

As of now there is no way to get the equivalent storage for a lvar.

HxLvar API
==========

.. autoclass:: HxLvar
    :members:
    :member-order: bysource

    .. automethod:: __init__


