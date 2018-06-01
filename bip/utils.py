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
	if ea>>31:
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


def parse_vtable_rtti():
	vtables = {}
	
	for e in Strings():
		demangled = Demangle('_Z'+str(e), 0)
		ea = e.ea
		
		if not demangled:
			continue
		
		for x in XrefsTo(ea):			
			if not Ptr(x.frm - get_ptr_size()/8):
				continue
			
			for x2 in XrefsTo(x.frm - get_ptr_size()/8):
				if Ptr(x2.frm -get_ptr_size()/8):
					continue
				
				vtables[demangled] = x2.frm - get_ptr_size()/8
				print "Found possible VTable of %s at 0x%x" % (demangled, x2.frm - get_ptr_size()/8)

	return vtables


def vtable2comment(struc_name, addr=None):
	if addr is None:
		addr = ScreenEA()
	
	sid = GetStrucIdByName(struc_name)
	struc = get_struc(sid)
	
	for offset, member_name, size in StructMembers(sid):
		# get member
		mid = get_member(struc, offset)

		# get func name (assume qword)
		func_name = Name(Qword(addr+offset))
		print "setting comment %s at offset %s" % (func_name, hex(offset))
		set_member_cmt(mid, func_name, True)


# http://journals.ecs.soton.ac.uk/java/tutorial/native1.1/implementing/types.html
DALVIK_TYPES_TO_NATIVE = {
	'Z': "jboolean",
	'B': "jbyte",
	'S': "jshort",
	'C': "jchar",
	'I': "jint",
	'J': "jlong",
	'F': "jfloat",
	'D': "jdouble",
	'V': "void"
}

def parse_dalvik_type(t):
	i = 0
	indir_level = 0
	if t[i] == '[':
		while t[i+indir_level] == '[':
			indir_level += 1

	i += indir_level
	c = t[i]
	i += 1
	native_type = DALVIK_TYPES_TO_NATIVE.get(c, None)
	if c == 'L':
		classpath = ""
		for j in range(i, len(t)):
			classpath += t[j]
			i += 1
			if t[j] == ';':
				break
		if classpath == "java/lang/String;":
			native_type = "jstring"
		elif classpath == "java/lang/Class;":
			native_type = "jclass"
		else:
			native_type = "jobject"

	if native_type is None:
		print "UNKNOWN TYPE: ", c

	if indir_level > 0:
		native_type += "Array" + "*" * (indir_level - 1)
	
	return i, native_type

def parse_smali_prototype(p):
	types = []
	m = match(".*\((?P<params>.*)\)(?P<rt>.*)", p)
	d = m.groupdict()
	rt = d['rt']
	t = d['params']
	i = 0
	while i < len(t):
		j, nt = parse_dalvik_type(t[i:])
		i = i + j
		types.append(nt)

	_, rt = parse_dalvik_type(rt)
	return types, rt


