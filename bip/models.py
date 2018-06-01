from idaapi import *
from idc import *
from idautils import *

from bip.utils import get_ptr_size

E_NOTFOUND = 0xFFFFFFFFFFFFFFFF

class Struct:
	def __init__(self, sid, name):
		self.sid = sid
		self.name = name

	@property
	def size(self):
		return int(GetStrucSize(self.sid))

	def add_ptr_field(self, name, comment=None):
		ptr_sz = get_ptr_size()/8
		flag = ({8:FF_QWRD, 4:FF_DWRD, 2:FF_WORD}[ptr_sz])|FF_DATA
		
		AddStrucMember(self.sid, name, -1, flag, -1, ptr_sz)

		if comment:
			SetMemberComment(self.sid, GetStrucSize(self.sid)-1, comment, True)
	
	def fill(self, size, prefix='field_'):
		offset = self.size
		ptr_sz = get_ptr_size()/8

		flag = ({8:FF_QWRD, 4:FF_DWRD, 2:FF_WORD}[ptr_sz])|FF_DATA
		
		while offset < size:
			AddStrucMember(self.sid, prefix+hex(offset), -1, flag, -1, ptr_sz)
			offset += ptr_sz

	@property
	def members(self):
		for f in StructMembers(self.sid):
			yield StructField.from_struct(self, f[0])
			
	@staticmethod
	def create(name):
		sid = GetStrucIdByName(name)
		if sid != E_NOTFOUND:
			raise ValueError('struct already exists')
		
		sid = AddStrucEx(-1, name, 0)
		return Struct(sid, name)
				
	@staticmethod
	def get(name):
		sid = GetStrucIdByName(name)
		if sid == E_NOTFOUND:
			raise ValueError('struct doesnt exists')

		return Struct(sid, name)

class StructField:
	def __init__(self, m_id, name, offset, size, struct, flags, comment=""):
		self.name = name
		self.offset = offset
		self.size = size
		self.struct = struct
		self.flags = flags
		self.comment = comment
		self.m_id = m_id

	@property
	def type(self):
		t = GetType(self.m_id)
		common_types = {
			8: "_QWORD",
			4: "_DWORD",
			2: "_WORD",
			1: "_BYTE"
		}

		if t is None and self.size in common_types:
			t = common_types[self.size]
		return t

	def to_dict(self):
		return {
			'name':self.name,
			'offset':self.offset,
			'size':self.size,
			'comment':self.comment,
			'type':self.type
		}
	
	@staticmethod
	def from_struct(struct, offset):
		name = GetMemberName(struct.sid, offset)
		# assume rpt comment
		comment = GetMemberComment(struct.sid, offset, 1)
		flags = GetMemberFlag(struct.sid, offset)
		size = GetMemberSize(struct.sid, offset)
		m_id = GetMemberId(struct.sid, offset)
		return StructField(m_id, name, offset, size, struct, flags, comment)

	
