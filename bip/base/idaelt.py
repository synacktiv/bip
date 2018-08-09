import idc


class IdaElt(object):
	"""
		Base class for representing an element in IDA which have an address.
		This is the basic element on top of which access to instruction and
		data is built.

		.. todo:: make test

		.. todo:: make xref directly at this level

		.. todo:: Make an exception system
	"""

	def __init__(self, ea):
		"""
			Consctructor for an IdaElt.

			:param int ea: The address of the element in IDA.
		"""
		if not isinstance(ea, (int, long)):
			raise TypeError("IdaElt.__init__ : ea should be an integer")
		self.ea = ea #: The address of the instruction in the IDA database

	################### BASE ##################

	@property
	def flags(self):
		"""
			Property for getting the flags of the element. Those flags are the
			one from ida such as returned by ``idc.GetFlags``.

			:return: The flags for the element
			:rtype: int
		"""
		return idc.GetFlags(self.ea)

	@property
	def size(self):
		"""
			Property which return the size of the elt.

			:return: The size in bytes of the element.
			:rtype: int
		"""
		return idc.ItemEnd(self.ea) - self.ea


	@property
	def bytes(self):
		"""
			Property returning the value of the bytes contain in the
			element.

			:return: A list of the bytes forming the element.
			:rtype: list(int)
		"""
		return [idc.Byte(i) for i in range(self.ea, idc.ItemEnd(self.ea))]

	################### NAME ##################
	# All element do not 

	@property
	def name(self):
		"""
			Property which allow to get the name of this element. An element
			do not always have a name.

			:return: The name of an element or an empty string if no name.
			:rtype: str
		"""
		return idc.Name(self.ea)

	@name.setter
	def name(self, value):
		"""
			Setter which allow to set the name of this element.

			This setter will fail if the element is not an head, see
			:meth:`IdaElt.is_head` for testing it.

			.. todo:: maybe raise in case of failure

			.. todo::
			
				idc.set_name support flags so maybe make more advanced
				functions ? (see include/name.hpp) And what about mangling.

			:param str value: The name to give to this element.
		"""
		if not idc.MakeName(self.ea, value):
			pass # Failure case TODO handle this


	################### COLOR ##################

	@property
	def color(self):
		"""
			Property which return the color of the item.

			:return: The coloration of the element in IDA.
			:rtype: int
		"""
		return idc.GetColor(self.ea, idc.CIC_ITEM)

	@color.setter
	def color(self, value):
		"""
			Setter which allow to set the color of the current element.

			:param int value: the color to which set the item.
		"""
		idc.SetColor(self.ea, idc.CIC_ITEM, value)

	################### COMMENT ##################

	@property
	def comment(self):
		"""
			Property which return the comment of the item.
			
			:return: The value of the comment
			:rtype: str
		"""
		return idc.GetCommentEx(self.ea, 0)

	@comment.setter
	def comment(self, value):
		"""
			Setter which allow to set the value of the comment.

			:param str value: The comment to set
		"""
		idc.MakeComm(self.ea, value)

	@property
	def rcomment(self):
		"""
			Property which return the repeatable comment of the item.
			
			:return: The value of the comment
			:rtype: str
		"""
		return idc.GetCommentEx(self.ea, 1)

	@rcomment.setter
	def rcomment(self, value):
		"""
			Setter which allow to set the value of the repeatable comment.

			:param str value: The comment to set.
		"""
		idc.MakeRptCmt(self.ea, value)

	@property
	def has_comment(self):
		"""
			Property which allow to check if the item as a comment (normal or
			repeatable.

			:return: True if the item as a comment, False otherwise
		"""
		return self.comment != "" or self.rcomment != ""

	####################### FLAGS #########################

	@property
	def is_code(self):
		"""
			Property indicating if this element is some code.
			Wrapper on ``idc.isCode`` .
			
			:return: True if current element is code, False otherwise.
			:rtype: bool
		"""
		return idc.isCode(self.flags)

	@property
	def is_data(self):
		"""
			Property indicating if this element is considered as data.
			Wrapper on ``idc.isData`` .
			
			:return: True if current element is data, False otherwise.
			:rtype: bool
		"""
		return idc.isData(self.flags)

	@property
	def is_unknow(self):
		"""
			Property indicating if this element is considered as unknwon.
			Wrapper on ``idc.isUnknown`` .
			
			:return: True if current element is unknwon, False otherwise.
			:rtype: bool
		"""
		return idc.isUnknown(self.flags)

	@property
	def is_head(self):
		"""
			Property indicating if the element is an *head* in IDA. An *head*
			element is the beggining of an elmeent in IDA (such as the
			beginning of an instruction) and can be named.
			Wrapper on ``idc.isHead`` .

			:return: True if the current element is an head, Flase otherwise.
			:rtype: bool
		"""
		return idc.isHead(self.flags)

	# no is_tail because counter intuitive as it is only a ``not is_head`` 

	
	######################## STUFF ############################


	def goto(self):
		"""
			Method which allow to move the screen to the position of this
			element. Wrapper on ``idc.Jump`` .
		"""
		idc.Jump(self.ea)


