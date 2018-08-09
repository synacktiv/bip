#from idaapi import *
#from idc import *
#from idautils import *
import idc
import ida_ua
from idaelt import IdaElt
from operand import Operand, OpType

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

	#@property
	#def size(self):
	#	"""
	#		Property which return the size of the instruction.

	#		:return: The size in bytes of the instruction.
	#		:rtype: int
	#	"""
	#	return self._insn.size


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
		decode_insn(i, self.ea) # decode and not create for not changing the db
		return i

	#################### OPERANDS ####################

	@property
	def countOperand(self):
		"""
			Property which return the number of operand for the instruction.
		"""
		i = 0
		ins = self._insn
		while i < self.UA_MAXOP and ins.ops[i].type != 0:
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

	# TODO:
	# * operands: access to operands
	# * flags: different type of flag and property for knowing if the instruction is 
	#   a jmp/ret/call/...
	# * link to basic block and functions
	# * xref



