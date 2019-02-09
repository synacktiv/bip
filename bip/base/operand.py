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
## TODO:
## x86
#o_trreg  =       ida_ua.o_idpspec0      # trace register
#o_dbreg  =       ida_ua.o_idpspec1      # debug register
#o_crreg  =       ida_ua.o_idpspec2      # control register
#o_fpreg  =       ida_ua.o_idpspec3      # floating point register
#o_mmxreg  =      ida_ua.o_idpspec4      # mmx register
#o_xmmreg  =      ida_ua.o_idpspec5      # xmm register
#
## arm
#o_reglist  =     ida_ua.o_idpspec1      # Register list (for LDM/STM)
#o_creglist  =    ida_ua.o_idpspec2      # Coprocessor register list (for CDP)
#o_creg  =        ida_ua.o_idpspec3      # Coprocessor register (for LDC/STC)
#o_fpreglist  =   ida_ua.o_idpspec4      # Floating point register list
#o_text  =        ida_ua.o_idpspec5      # Arbitrary text stored in the operand
#o_cond  =        (ida_ua.o_idpspec5+1)  # ARM condition as an operand
#
## ppc
#o_spr  =         ida_ua.o_idpspec0      # Special purpose register
#o_twofpr  =      ida_ua.o_idpspec1      # Two FPRs
#o_shmbme  =      ida_ua.o_idpspec2      # SH & MB & ME
#o_crf  =         ida_ua.o_idpspec3      # crfield      x.reg
#o_crb  =         ida_ua.o_idpspec4      # crbit        x.reg
#o_dcr  =         ida_ua.o_idpspec5      # Device control register

class DestOpType(object):
    """
        Static class representing an enum of the ``dt_*`` macro from IDA
        indicating the type of the operand value.

        Defined in ``ua.hpp`` in IDA.
    """
    DT_BYTE         = 0     #: 8 bit
    DT_WORD         = 1     #: 16 bit
    DT_DWORD        = 2     #: 32 bit
    DT_FLOAT        = 3     #: 4 byte
    DT_DOUBLE       = 4     #: 8 byte
    DT_TBYTE        = 5     #: variable size
    DT_PACKREAL     = 6     #: packed real format for mc68040
    DT_QWORD        = 7     #: 64 bit
    DT_BYTE16       = 8     #: 128 bit
    DT_CODE         = 9     #: ptr to code (not used?)
    DT_VOID         = 10    #: none
    DT_FWORD        = 11    #: 48 bit
    DT_BITFILD      = 12    #: bit field (mc680x0)
    DT_STRING       = 13    #: pointer to asciiz string
    DT_UNICODE      = 14    #: pointer to unicode string
    DT_LDBL         = 15    #: long double (which may be different from tbyte)
    DT_BYTE32       = 16    #: 256 bit
    DT_BYTE64       = 17    #: 512 bit


class Operand(object):
    """
        Class representing an operand of an instruction. This class
        should be used through :class:`Instr` .

        .. todo:: make test property depending of type

        .. todo:: make subclass by type of operand ?

        .. todo:: support .reg and other stuff like that

        .. todo:: hex((i.Op2.specval >> 0x10) & 0xFF) give the segment

        .. todo:: make pretty printing function if possible
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
            :rtype: :class:`str`
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
    def dtype(self):
        """
            Property which allow to get the type of the operand value. Those
            can be access through the :class:`DestOpType` enum.
            This is is equivalent to accessing the ``op_t.dtype`` from IDA.

            .. todo: Test

            :return int: The type of the destination of the operand as defined
                in :class:`DestOpType`.
        """
        return self._op_t.dtype

    @property
    def _value(self):
        """
            Property allowing to get the value of an operand. Depending of the
            type of the operand this value can means different things.
            Wrapper on ``idc.GetOperandValue`` .

            .. todo::

                Look at idc.get_operand_value, somethings may need
                change here.

            :return: The value of the operand.
            :rtype: int
        """
        return idc.GetOperandValue(self.ea, self.opnum)

    @property
    def value(self):
        """
            Property allowing to get the value of an operand. Depending of the
            type of the operand this value can means different things.
            For an immediate the value return as a mask apply for getting only
            the number of bytes of the asm value and not the signed extended
            returned by IDA.

            .. todo::

                Look at idc.get_operand_value, somethings may need
                change here.

            .. todo::

                Support the dtype for other things than immediate (such as
                float).
                
            .. todo::
                
                Support all of the dtype for immediate

            .. todo: Test

            :return: The value of the operand.
            :rtype: int
        """
        if self.is_imm:
            dt = self.dtype
            if dt == DestOpType.DT_BYTE:
                return self._value & 0xFF
            elif dt == DestOpType.DT_WORD:
                return self._value & 0xFFFF
            elif dt == DestOpType.DT_DWORD:
                return self._value & 0xFFFFFFFF
            elif dt == DestOpType.DT_FLOAT: # TODO
                return self._value & 0xFFFFFFFF
            elif dt == DestOpType.DT_DOUBLE: # TODO
                return self._value & 0xFFFFFFFFFFFFFFFF
            elif dt == DestOpType.DT_QWORD:
                return self._value & 0xFFFFFFFFFFFFFFFF
            else: # TODO
                return self._value
        return self._value


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


