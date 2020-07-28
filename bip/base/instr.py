import idc
import ida_bytes
import ida_ua
import idautils
import idaapi

from .bipelt import BipElt
from .operand import Operand, OpType
from .biperror import BipError
import bip.base.block
import bip.base.func

class Instr(BipElt):
    """
        Class for representing and manipulating a assembleur instruction in
        IDA.
    """
    #UA_MAXOP = idaapi.UA_MAXOP #: Maximum number of operands for one instruction
    UA_MAXOP = 8 #: Maximum number of operands for one instruction

    def __init__(self, ea=None):
        """
            Constructor for an instruction in IDA.

            :param int ea: The address of the instruction in IDA. If
                ``None`` the screen address is taken.
        """
        super(Instr, self).__init__(ea)
        if not self.is_code:
            raise BipError("No an instr at 0x{:X}".format(ea))


    ####################### BASE ######################

    @property
    def str(self):
        """
            Property returning a string representing the complete instruction.

            :return: A representation of the complete instruction.
            :rtype: :class:`str`
        """
        return idc.GetDisasm(self.ea)

    @property
    def mnem(self):
        """
            Property which allow to get the mnemonic of the instruction.

            :return: The mnemonic of the instruction
            :rtype: :class:`str`
        """
        #return idc.GetMnem(self.ea) # old version
        # idc.print_insn_mnem does not print but return the str, because why not ?
        return idc.print_insn_mnem(self.ea)

    @property
    def _insn(self):
        """
            Property which return an ``insn_t`` representing the instruction
            as provided by IDA.
            
            There is no reason to use this except for interfacing directly
            with IDA functions.

            This is use internally by other functions.
        """
        i = ida_ua.insn_t()
        ida_ua.decode_insn(i, self.ea) # decode and not create for not changing the db
        return i

    def __str__(self):
        return "Instr: 0x{:X} ({})".format(self.ea, self.str)

    #################### OPERANDS ####################

    @property
    def countOperand(self):
        """
            Property which return the number of operand for the instruction.
        """
        i = 0
        ins = self._insn
        while i < self.UA_MAXOP and ins.ops[i].type != OpType.VOID:
            i += 1
        return i

    def op(self, num):
        """
            Method for recuperating an :class:`Operand` object.

            :param int num: The position of the operand.
            :raise ValueError: If the position is not valid.
        """
        o = Operand(self, num)
        if o.type == OpType.VOID:
            raise ValueError("Instruction does not have {} operand".format(num))
        else:
            return o

    @property
    def ops(self):
        """
            Property returning a list of the operands of the instruction.

            :return: A list of :class:`Operand` .
        """
        return [self.op(i) for i in range(self.countOperand)]

    #################### FLAGS ####################

    @property
    def has_prev_instr(self):
        """
            Property indicating if this instruction follow an other normal
            instruction (part of its flow). Wrapper on ``idc.is_flow`` .
        """
        return idc.is_flow(self.flags)

    @property
    def is_call(self):
        """
            Property indicating if this instruction is a call.

            :return bool: True if this instruction is a call, False otherwise.
        """
        return idaapi.is_call_insn(self.ea)

    @property
    def is_ret(self):
        """
            Property indicating if this instruction is a ret.

            :return bool: True if this instruction is a ret, False otherwise.
        """
        return idaapi.is_ret_insn(self.ea)

    @property
    def is_indirect_jmp(self):
        """
            Property indicating if this instruction is an indirect jump (such
            as on a register or from the value of memory).

            :return bool: True if this instruction is a indirect jmp, False
                otherwise.
        """
        return idaapi.is_indirect_jump_insn(self.ea)

    @property
    def is_end_block(self):
        """
            Property indicating if this instruction is the end of a basic block.
            This property will return False if the instruction is a call which
            does not end a block such as display by IDA, see
            :meth:`is_end_block_call` for returning True on call.

            :return bool: True if this instruction is the last one for a
                block.
        """
        return idaapi.is_basic_block_end(self.ea, False)

    @property
    def is_end_block_call(self):
        """
            Property indicating if this instruction is the end of a basic
            block. This property will return True if the instruction is a
            call, see :meth:`is_end_block` for returning False on call which
            are not at the end of a block.

            :return bool: True if this instruction is the last one for a
                block, including the case when it is a call.
        """
        return idaapi.is_basic_block_end(self.ea, True)

    @property
    def is_in_func(self):
        """
            Property which return True if this instruction is inside a
            function.
        """
        try:
            self.func
            return True
        except ValueError:
            return False


    #################### UTILS #####################

    @property
    def prev(self):
        """
            Property returning the instruction which preceed in the normal
            flow of execution the current instruction (no handle of jmp,
            call, ...). It is possible for an instruction to not have a
            previous instruction typically at the start of a function but in
            other cases too. This can be tested with
            :meth:`~Instr.has_prev_instr` .

            :return: The previous instruction if any.
            :rtype: :class:`Instr` or None
        """
        if self.has_prev_instr:
            return Instr(idc.prev_head(self.ea))
        return None

    @property
    def next(self):
        """
            The instruction following the current one. It is important to
            notice it will not always be the next instruction in the control
            flow.
            
            If the next element is not an instruction (for exemple at the end
            of a function followed by data) ``None`` will be returned.

            :return: The next :class:`Instr` or None in case of error.
        """
        try:
            return Instr(idc.next_head(self.ea))
        except BipError:
            return None


    @classmethod
    def _is_this_elt(cls, ea):
        return idc.is_code(ida_bytes.get_full_flags(ea))

    ####################### BASIC BLOCK & FUNCTION ##########################

    @property
    def block(self):
        """
            Return the :class:`BipBlock` in which this instruction is
            included.
            
            This instruction will raise an exception if the instruction is
            not included an IDA basic block. See :class:`BipBlock` for more
            information.

            :return: An :class:`BipBlock` object containing this instruction.
        """
        return bip.base.block.BipBlock(self.ea)

    @property
    def func(self):
        """
            Return the :class:`BipFunction` in which this instruction is
            included.

            This will raise a ``ValueError`` if the instruction is not in a
            defined function.

            :return: An :class:`BipFunction` object containing this
                instruction.
        """
        return bip.base.func.BipFunction(self.ea)

    ########################## XREFS ##############################

    @property
    def xOrdinaryCfNext(self):
        """
            Property returning the next instruction in the control flow. This
            may return None in several case such as ``ret`` or a
            non-conditional ``jmp`` .

            .. note:: This can be simply handle because of things like a
                switch/jmp table.

            :return: :class:`Instr` for the next instruction in the control
                flow or ``None`` .
        """
        xs = [x.dst for x in self.xFrom if x.is_ordinaryflow] 
        if len(xs) > 1:
            raise BipError("Should not be possible to have more than one ordinary flow")
        elif len(xs) == 0:
            return None
        return xs[0]

    @property
    def xCfNext(self):
        """
            Property allowing access to instructions which can follow in the
            control flow. This will take call, jmp and ordinary flow into
            account.

            :return: A list of :class:`Instr` for the next possible
                intructions.
        """
        return [x.dst for x in self.xFrom if x.is_codepath] 

    @property
    def xCfPrev(self):
        """
            Property allowing access to instructions which can lead to the
            current instructions. This will take call, jmp and ordinary flow
            into account.
        """
        return [x.src for x in self.xTo if x.is_codepath] 

    ######################### STATIC/CLASS METHODS ###########################

    @classmethod
    def Make(cls, ea=None):
        """
            Class method for defining an instruction. If auto-analysis is
            enable in IDA this may define also the following instructions.
            If the instruction is already define, this instruction just
            returns it.

            :param ea: The address at which to define the instruction, if None
                the current screen address is used.
            :return: The :class:`Instr` for this address.
            :raise RuntimeError: If it was not possible to define the address
                as code.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        if idc.is_code(ida_bytes.get_full_flags(ea)): # if we already have code
            return cls(ea)
        if ida_ua.create_insn(ea) == 0:
            raise RuntimeError("Unable to create instruction at 0x{:X}".format(ea))
        return cls(ea)



