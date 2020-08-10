Changelog
#########

This page has for goal to record breaking change in the API between versions.
New features may be listed but probably not always.


Change from v0.3 to v1.0
========================

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
* renaming of ``bip.hexrays.HxCStmt.st_childs`` to ``bip.hexrays.HxCStmt.stmt_childs``
* renaming of ``bip.hexrays.CNodeStmt.st_childs`` to ``bip.hexrays.CNodeStmt.stmt_childs``
* renaming of ``bip.hexrays.CNode.GetCNode`` to ``bip.hexrays.CNode.from_citem``
* renaming of ``bip.hexrays.CNode.cfunc`` to ``bip.hexrays.CNode.hxcfunc``
* renaming of ``bip.base.BipFunction.hxfunc`` to ``bip.base.BipFunction.hxcfunc``
* renaming of ``bip.hexrays.HxLvar.hxfunc`` to ``bip.hexrays.HxLvar.hxcfunc``


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
    s/st_childs/stmt_childs/g
    s/GetCNode/from_citem/g

Are not included in this sed file the change to ``BipInstr.Make``,
``BipFunction.Count``, ``Cnode.cfunc`` which can easilly create problems.



