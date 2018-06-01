from bip.models import Struct
from bip.utils import *
from idaapi import *
from idc import *
import idaapi
import idc
import idautils
		
def create_struct_with_size(n):
	s = """Create struct with size

<Name:T:32:16::>
<Size:N:32:16::>
"""
	
	name = Form.StringArgument(200, value='bla')
	num = Form.NumericArgument('N', value=n)

	while True:
		ok = idaapi.AskUsingForm(s, name.arg, num.arg)
		print ok
		if not ok:
			return

		try:
			print repr(name.value)
			print repr(num.value)
			s = Struct.create(name.value)
			s.fill(num.value)
			break
		except ValueError as e:
			Warning(str(e))
		
	
	
def copy_struct_with_size(n):
	s = """Create struct with size

<Name:T:32:16::>
<Size:N:32:16::>
"""
	
	name = Form.StringArgument(200, value='bla')
	num = Form.NumericArgument('N', value=n)

	while True:
		ok = idaapi.AskUsingForm(s, name.arg, num.arg)
		print ok
		if not ok:
			return

		try:
			print repr(name.value)
			print repr(num.value)
			s = Struct.create(name.value)
			s.fill(num.value)
			break
		except ValueError as e:
			Warning(str(e))
		
	
	
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
		
		s = Struct.create("%sVTable" % classname)
					
		while Ptr(ea):
			# if i in (1,2) and GetFunctionName(Ptr(ea)):
			# 	MakeName(Ptr(ea), classname+"::Destructor%d" % i)
			# 	name = "Destructor%d" % i

			name = "Method_%d" % i
			

			s.add_ptr_field(name, "0x%x" % Ptr(ea))
			ea += get_ptr_size()/8
			i+=1


def analyse_rtti():
	vtables = parse_vtable_rtti()
	rename_vtables(vtables)
	define_vtables_struct(vtables)


def fill_jni_prototype(name):
	s = """Fill the function parameters types from smali prototype

	<Prototype:T:200:200::>
	"""
		
	prototype = Form.StringArgument(200, value='bla(II[B)')

	while True:
		ok = idaapi.AskUsingForm(s, prototype.arg)
		print ok
		if not ok:
			return

		try:
			func_ea = idaapi.get_screen_ea()
			if len(prototype.value) == 0:
				return
			java_types, return_type = parse_smali_prototype(prototype.value)

			prototypes = []
			for jp in java_types:
				prototypes.append("%s a%d" % (jp, java_types.index(jp)))

			idc.SetType(func_ea,
					"%s __fastcall %s(JNIEnv *env, jobject o, %s)" % (return_type, name, ", ".join(prototypes)))
			break
		except ValueError as e:
			Warning(str(e))
