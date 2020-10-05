Changelog
#########

This page has the goal to record breaking change in the API between versions.
New features may be listed but probably not always.

Change from v1.0 to Current
===========================

New features:

* added methods 
  :meth:`~bip.gui.pluginmanager.BipPluginManager.reload_plugin`,
  :meth:`~bip.gui.pluginmanager.BipPluginManager.reload_all`,
  :meth:`~bip.gui.pluginmanager.BipPluginManager.unload_plugin` and
  :meth:`~bip.gui.pluginmanager.BipPluginManager.unload_all` in the
  :class:`~bip.gui.pluginmanager.BipPluginManager` for managing
  :class:`~bip.gui.BipPlugin`.
* added method :meth:`~bip.gui.BipAction.detach_from_menu`.
* added property :meth:`~bip.base.BipFunction.type` for interfacing with
  :class:`~bip.base.BipType`.

Bug Fix:

* Correctly detach :class:`~bip.gui.BipAction` from menu when calling
  :meth:`~bip.gui.BipAction.unregister`.

Deprecated (will be removed on next major version) object & functions:

* Properties :meth:`bip.base.BipFunction.str_type` and
  :meth:`bip.base.BipFunction.guess_strtype`,
  should used :meth:`bip.base.BipFunction.type` instead.

Change from v0.3 to v1.0
========================

New features:

* new class :class:`bip.base.BipIdb`
* new class :class:`bip.base.BipIda`
* new class :class:`bip.gui.BipUserSelect`

Breaking changes:

* renaming of ``bip.base.XrefTypes`` to ``bip.base._XrefTypes``
* renaming of ``bip.base.DestOpType`` to ``bip.base.BipDestOpType``
* renaming of ``bip.base.OpType`` to ``bip.base.BipOpType``
* renaming of ``bip.base.Operand`` to ``bip.base.BipOperand``
* renaming of ``bip.hexrays.HexRaysEvent`` to ``bip.base.HxEvent``
* renaming of ``bip.base.Instr`` to ``bip.base.BipInstr``
* renaming of ``bip.base.BipFuncFlags`` to ``bip.base._BipFuncFlags``
* renaming of ``bip.base.BipFlowChartFlag`` to ``bip.base._BipFlowChartFlag``
* renaming of ``bip.base.BipType._GetClassBipType`` to ``bip.base.BipType._get_class_bip_type``
* renaming of ``bip.base.BipType.GetBipTypeNoCopy`` to ``bip.base.BipType.from_tinfo_no_copy``
* renaming of ``bip.base.BipType.GetBipType`` to ``bip.base.BipType.from_tinfo``
* renaming of ``bip.base.BipType.FromC`` to ``bip.base.BipType.from_c``
* renaming of ``bip.base.BipType.ImportCHeader`` to ``bip.base.BipType.import_c_header``
* renaming of ``bip.base.BipInstr.Make`` to ``bip.base.BipInstr.make``
* renaming of ``bip.base.BipFunction.ByOrdinal`` to ``bip.base.BipFunction.by_ordinal``
* renaming of ``bip.base.BipFunction.Entries`` to ``bip.base.BipFunction.entries``
* renaming of ``bip.base.BipFunction.Entries_iter`` to ``bip.base.BipFunction.entries_iter``
* renaming of ``bip.base.BipFunction.Count`` to ``bip.base.BipFunction.count``
* renaming of ``bip.hexrays.HxCItem.GetHxCItem`` to ``bip.hexrays.HxCItem.from_citem``
* renaming of ``bip.hexrays.HxCItem._createChild`` to ``bip.hexrays.HxCItem._create_child``
* renaming of ``bip.hexrays.CNode._createChild`` to ``bip.hexrays.CNode._create_child``
* renaming of ``bip.hexrays.HxCStmt.st_childs`` to ``bip.hexrays.HxCStmt.stmt_children``
* renaming of ``bip.hexrays.CNodeStmt.st_childs`` to ``bip.hexrays.CNodeStmt.stmt_children``
* renaming of ``bip.hexrays.CNodeStmt.expr_childs`` to ``bip.hexrays.CNodeStmt.expr_children``
* renaming of ``bip.hexrays.CNode.GetCNode`` to ``bip.hexrays.CNode.from_citem``
* renaming of ``bip.hexrays.CNode.cfunc`` to ``bip.hexrays.CNode.hxcfunc``
* renaming of ``bip.base.BipFunction.hxfunc`` to ``bip.base.BipFunction.hxcfunc``
* renaming of ``bip.hexrays.HxLvar.hxfunc`` to ``bip.hexrays.HxLvar.hxcfunc``
* function ``bip.base.utils.get_ptr_size`` became static method ``bip.base.BipIdb.ptr_size``
* function ``bip.base.utils.absea`` became a static method of ``bip.base.BipIdb``
* function ``bip.base.utils.relea`` became a static method of ``bip.base.BipIdb``
* ``min_ea``, ``max_ea`` and ``Here``, functions are now in ``bip.base.bipidb``
* function ``bip.base.utils.get_addr_by_name`` has been removed.
* function ``bip.base.utils.get_name_by_addr`` has been removed.
* function ``bip.base.utils.get_struct_from_lvar`` has been removed.
* function ``bip.base.utils.Ptr`` became static method of ``bip.base.BipData.get_ptr``
* function ``bip.base.utils.bip_exec_sync`` became static method ``bip.base.BipIda.exec_sync``
* function ``bip.base.utils.get_highlighted_identifier_as_int`` became static method ``BipUserSelect.get_curr_highlighted_int``
* removed classes ``BaseGuiAction`` and ``ContextMenuHooks``
* renamed method ``bip.base.BipType.childs`` to ``bip.base.BiType.children``


Sed script for automatic update of plugins (no garantee to be perfect or to
avoid colisions) (use with ``sed -f RULEFILE INPUTFILE``):

.. code-block:: none

    s/XrefTypes/_XrefTypes/g
    s/DestOpType/BipDestOpType/g
    s/OpType/BipOpType/g
    s/Operand/BipOperand/g
    s/countBipOperand/countOperand/g
    s/HexRaysEvent/HxEvent/g
    s/Instr/BipInstr/g
    s/BipFuncFlags/_BipFuncFlags/g
    s/BipFlowChartFlag/_BipFlowChartFlag/g
    s/_GetClassBipType/_get_class_bip_type/g
    s/GetBipTypeNoCopy/from_tinfo_no_copy/g
    s/GetBipType/from_tinfo/g
    s/FromC/from_c/g
    s/ImportCHeader/import_c_header/g
    s/ByOrdinal/by_ordinal/g
    s/Entries/entries/g
    s/GetHxCItem/from_citem/g
    s/_createChild/_create_child/g
    s/st_childs/stmt_children/g
    s/expr_childs/expr_children/g
    s/GetCNode/from_citem/g
    s/get_ptr_size/BipIdb.ptr_size/g
    s/bip_exec_sync/BipIda.exec_sync/g
    s/get_highlighted_identifier_as_int/BipUserSelect.get_curr_highlighted_int/g
    s/childs/children/g

Are not included in this sed file the change to ``BipInstr.Make``,
``BipFunction.Count``, ``Cnode.cfunc``, ``Ptr`` which can easilly create
problems.

This update removed also the ``example``, ``scripts`` and ``plugins``
directory which will not be maintain as part of Bip (and where probably
already not working since some times).


