Changelog
#########

This page has for goal to record breaking change in the API between versions.
New features may be listed but probably not always.


Change from v0.3 to TODO
========================

* renaming of ``bip.base.XrefTypes`` to ``bip.base._XrefTypes``
* renaming of ``bip.base.DestOpType`` to ``bip.base.BipDestOpType``
* renaming of ``bip.base.OpType`` to ``bip.base.BipOpType``
* renaming of ``bip.base.Operand`` to ``bip.base.BipOperand``
* renaming of ``bip.hexrays.HexRaysEvent`` to ``bip.base.HxEvent``
* renaming of ``bip.base.Instr`` to ``bip.base.BipInstr``
* renaming of ``bip.base.BipFuncFlags`` to ``bip.base._BipFuncFlags``
* renaming of ``bip.base.BipFlowChartFlag`` to ``bip.base._BipFlowChartFlag``



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

