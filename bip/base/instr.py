#from idaapi import *
#from idc import *
#from idautils import *
import idc
import ida_ua
import idautils
from idaelt import IdaElt
from operand import Operand, OpType
from biperror import BipError

class Instr(IdaElt):
    """
        Class for representing and manipulating an instruction in IDA.

        .. todo:: make test
    """
    #UA_MAXOP = idaapi.UA_MAXOP #: Maximum number of operands for one instruction
    UA_MAXOP = 8 #: Maximum number of operands for one instruction

    def __init__(self, ea):
        """
            Constructor for an instruction in IDA, take the address of the instruction in parameter.
        """
        super(Instr, self).__init__(ea)
        if not self.is_code:
            raise BipError("No an instr at 0x{:X}".format(ea))

    #@property
    #def size(self):
    #    """
    #        Property which return the size of the instruction.

    #        :return: The size in bytes of the instruction.
    #        :rtype: int
    #    """
    #    return self._insn.size


    ####################### BASE ######################

    @property
    def str(self):
        """
            Property returning a string representing the complete instruction.

            :return: A representation of the complete instruction.
            :rtype: str
        """
        return idc.GetDisasm(self.ea)

    @property
    def mnem(self):
        """
            Property which allow to get the mnemonic of the instruction.

            :return: The mnemonic of the instruction
            :rtype: str
        """
        return idc.GetMnem(self.ea)

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
            instruction (part of its flow). Wrapper on ``idc.isFlow`` .
        """
        return idc.isFlow(self.flags)


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
            return Instr(idc.PrevHead(self.ea))
        return None

    @property
    def next(self):
        """
            The instruction following the current one. It is important to
            notice it will not always be the next instruction in the control
            flow.

            .. todo:: Make this the next instruction in the control flow ?

            .. todo:: add check and failure case.

            :return: The next instruction.
            :rtype: class:`Instr`
        """
        return Instr(idc.NextHead(self.ea))

    @classmethod
    def _is_this_elt(cls, ea):
        if idc.isCode(idc.GetFlags(ea)):
            return True
        return False

    # TODO:
    # * flags: different type of flag and property for knowing if the instruction is 
    #   a jmp/ret/call/...
    # * link to basic block and functions

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

    ###################### CLASS METHODS #############################

    @classmethod
    def iter_all(cls):
        """
            Class method allowing to iter on all the instructions define in
            the IDB.

            .. note::
                Internally this function iterate on all the ``Heads`` and
                create the object if the ``idc.is_code`` function return True.

            :return: A generator of :class:`Instr` allowing to iter on all the
                instruction define in the idb.
        """
        for h in idautils.Heads():
            if idc.is_code(idc.GetFlags(h)):
                yield cls(h)


