import idaapi
import idc

class OpType(object):
    """
        Static class allowing to get the type of the operands as define in the
        ``ua.hpp`` file from hexrays. This is equivalent to the ``idc.o_*``
        values.
    """
    VOID        =  0 #: No Operand.
    REG         =  1 #: General Register (al,ax,es,ds...).
    MEM         =  2 #: Direct Memory Reference  (DATA).
    PHRASE      =  3 #: Memory Ref [Base Reg + Index Reg].
    DISPL       =  4 #: Memory Reg [Base Reg + Index Reg + Displacement].
    IMM         =  5 #: Immediate Value.
    FAR         =  6 #: Immediate Far Address  (CODE).
    NEAR        =  7 #: Immediate Near Address (CODE).
    IDPSPEC0    =  8 #: processor specific type.
    IDPSPEC1    =  9 #: processor specific type.
    IDPSPEC2    = 10 #: processor specific type.
    IDPSPEC3    = 11 #: processor specific type.
    IDPSPEC4    = 12 #: processor specific type.
    IDPSPEC5    = 13 #: processor specific type.

class Operand(object):
    """
        Class representing an operand of an instruction. This class
        should be used through :class:`Instr` .

        .. todo:: make test property depending of type

        .. todo:: make subclass by type of operand ?
    """

    def __init__(self, ins, num):
        """
            Constructor for an operand object. Should not directly use this
            constructor but should be access by using the :meth:`~Instr.op`
            method from :class:`Instr` .
            
            :param ins: The instruction in which this operand ins present
            :type ins: :class:`Instr`
            :param int num: The position of the operand in the instruction.
        """
        self.instr = ins #: Instruction containing the operand
        self.opnum = num #: The position of the operand in the instruction


    @property
    def ea(self):
        """
            Property allowing to get the address of the instruction
            containing this operand.

            :return: The address of the instruction.
            :rtype: int or long
        """
        return self.instr.ea
    
    @property
    def str(self):
        """
            Property allowing to get the representation of the operand as a
            string.
            Wrapper on ``idc.GetOpnd`` .

            :return: The representation of the operand.
            :rtype: str
        """
        return idc.GetOpnd(self.ea, self.opnum)

    @property
    def _op_t(self):
        """
            Return the IDA object ``op_t`` correponding to this operand.

            :return: A swig proxy on an ``op_t`` type.
        """
        return self.instr._insn.ops[self.opnum]

    @property
    def type(self):
        """
            Property allowing to get the type of the operand. This type
            correspond to the :class:`OpType` value .
            Wrapper on ``idc.GetOpType`` .

            :return: The type of the operand as defined in :class:`OpType` .
            :rtype: int
        """
        return idc.GetOpType(self.ea, self.opnum)

    @property
    def value(self):
        """
            Property allowing to get the value of an operand. Depending of the
            type of the operand this value can means different things.
            Wrapper on ``idc.GetOperandValue`` .

            :return: The value of the operand.
            :rtype: int
        """
        return idc.GetOperandValue(self.ea, self.opnum)

    ######################## TEST TYPE ##########################
    # TODO: test those

    @property
    def is_void(self):
        """
            Test if this object represent the fact that there is no operand.
            (OpType.VOID)
        """
        return self.type == OpType.VOID

    @property
    def is_reg(self):
        """
            Test if the operand represent a register. (OpType.REG)
        """
        return self.type == OpType.REG

    @property
    def is_memref(self):
        """
            Test if the operand is a memory reference (one of MEM, PHRASE or
            DISPL in OpType)
        """
        t = self.type 
        return t == OpType.MEM or t == OpType.PHRASE or t == OpType.PHRASE

    @property
    def is_imm(self):
        """
            Test if the operand is an immediate value which is **not** an
            address (OpType.IMM).
        """
        return self.type == OpType.IMM

    @property
    def is_addr(self):
        """
            Test if the operand represent an address, far or near.
            (one of FAR or NEAR in OpType).
        """
        t = self.type 
        return t == OpType.FAR or t == OpType.NEAR

    @property
    def is_proc_specific(self):
        """
            Test if this operand is processor specific.
        """
        return t >= OpType.IDPSPEC0


