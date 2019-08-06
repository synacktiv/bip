from bip.base import *
import idaapi

def rename_vtables(vtables=None):
	if not vtables:
		vtables = parse_vtable_rtti()
		
	for name, ea in vtables.iteritems():
		MakeName(ea, "%s_VTable" % name.replace("<", "_").replace(">", "").replace(',', '').replace(' ', '_').replace('*', ''))

def define_vtables_struct(vtables=None):
	if not vtables:
		vtables = parse_vtable_rtti()

	for name, ea in vtables.iteritems():
		# walk
		i = 1
		ea += get_ptr_size()/4

		classname = name.replace("<", "_").replace(">", "").replace(',', '').replace(' ', '_').replace('*', '')
		
		s = BipStruct.create("%sVTable" % classname)
					
		while Ptr(ea):
			# if i in (1,2) and GetFunctionName(Ptr(ea)):
			# 	MakeName(Ptr(ea), classname+"::Destructor%d" % i)
			# 	name = "Destructor%d" % i

			name = "Method_%d" % i
			

			s.add(name, get_ptr_size()/8, "0x%x" % Ptr(ea))
			ea += get_ptr_size()/8
			i+=1

def analyse_rtti():
	vtables = parse_vtable_rtti()
	rename_vtables(vtables)
	define_vtables_struct(vtables)


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
