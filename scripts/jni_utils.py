from bip.actions import BaseGuiAction
from bip.utils import *
import adaapi

class FillJNIPrototype(BaseGuiAction):
	action_name = "bip:filljniprototype"
	action_label = "Fill JNI Prototype..."
	action_shortcut = "Shift+Alt+J"

	def __init__(self):
		super(FillJNIPrototype, self).__init__()
		self.attach_to_menu("Edit")
		
	def should_attach_to_popup(self, form, popup):
		idaapi.get_tform_title(form).startswith('Pseudocode')
		
	def activate(self, ctx):
		ide = get_highlighted_identifier()
		fill_jni_prototype(ide)

	def update(self, ctx):
		return idaapi.AST_ENABLE_FOR_FORM


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
