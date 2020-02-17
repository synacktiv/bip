List of BipPlugin
#################

======================================= =================== ================================================================================================================================
Name                                    File                Description
======================================= =================== ================================================================================================================================
:class:`~plugins.printk_com.PrintkComs` printk_com.py       Add the format string used by a called to ``printk`` in comment at the level of the call.
:class:`~plugins.colorcall.ColorCall`   colorcall.py        Allow to color call instruction and jump outside a function.
:class:`~plugins.unklibfix.UnkLibFix`   unklibfix.py        Allow to remove the ``unknown_libname_*`` functions named when applying FLIRT signature.
======================================= =================== ================================================================================================================================

PrintkComs API
==============

.. autoclass:: plugins.printk_com.PrintkComs
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

    .. autoattribute:: printk_current
    .. autoattribute:: printk_all


ColorCall API
=============

.. autoclass:: plugins.colorcall.ColorCall
    :members:
    :member-order: bysource

    .. autoattribute:: color_call
    .. autoattribute:: color_calljmp
    .. autoattribute:: colorcalljmp_in_func

UnkLibFix API
=============

.. autoclass:: plugins.unklibfix.UnkLibFix
    :members:
    :member-order: bysource

    .. autoattribute:: rm_unk_func
    .. autoattribute:: rm_unk_func_comm



