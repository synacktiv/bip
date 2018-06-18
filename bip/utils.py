from re import match
from idaapi import *
from idc import *
from idautils import *
from ida_hexrays import *

def get_highlighted_identifier_as_int():
	s = get_highlighted_identifier()
	h = match('(0x[0-9a-fA-F]+).*', s)
	o = match('(0[0-7]+).*', s)
	n = match('([0-9]+).*', s)
	
	if h:
		return int(h.group(1), 16)
	elif o:
		return int(o.group(1), 8)
	elif n:
		return int(n.group(1))
	
	return None

def Ptr(ea):
	info = get_inf_structure()

	if info.is_64bit():
		return Qword(ea)
	elif info.is_32bit():
		return Dword(ea)
	else:
		return Word(ea)

def get_ptr_size():
	info = get_inf_structure()

	if info.is_64bit():
		bits = 64
	elif info.is_32bit():
		bits = 32
	else:
		bits = 16

	return bits


def relea(addr):
	return addr-get_imagebase()

def absea(offset):
	return offset+get_imagebase()

def get_addr_by_name(name):
	ea = LocByName(name)
	if ea == 0xffffffffffffffff:
		return 0
	return relea(ea)		

def get_funcs_by_name(name):
	res = []
	for ea in Functions():
		n = GetFunctionName(ea)
		if n.startswith(name):
			res.append(n)

	return res

def get_name_by_addr(offset):
	s = GetFuncOffset(absea(offset))
	if not s:
		nn = NearestName({k:v for k,v in Names()})
		if nn is None:
			return '', 0
		
		ea, name, _ = nn.find(absea(offset))
		offset = absea(offset)-ea
		if offset < 0x100:
			return name, offset
		return '', 0

	print s
	name, _, offset = s.partition('+')
	if offset:
		offset = int(offset, 16)
	else:
		offset = 0
		
	# FFS IDA
	name = name.replace('__', '::')	
	if not get_addr_by_name(name):
		print "[!] WUT WUT WUT '%s' returned by GetFuncOffset doesnt exist" % name

	print name, offset
	return name, offset


def get_struct_from_lvar(lvar):
	"""
	Get a struct from a hexrays local variable type
	Returns a bip Struct or None on error
	"""
	
	t = lvar.type()
	
	if t.is_ptr():
		s = t.get_pointed_object()
		if s.is_struct():
			try:
				struct = Struct.get(s.get_type_name())
				return struct
			except ValueError:
				return None
	return None
