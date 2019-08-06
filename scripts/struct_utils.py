from bip.gui import *
from bip.base import *
import idaapi

# Actions

class CreateStructAction(BaseGuiAction):
	action_name = "bip:createstructsize"
	action_label = "Create struct with size..."
	action_shortcut = "Shift+Alt+D"

	def __init__(self):
		super(CreateStructAction, self).__init__()
		self.attach_to_menu("Edit")

	def should_attach_to_popup(self, form, popup):
		return idaapi.get_tform_title(form).startswith('Pseudocode')

	def activate(self, ctx):
		size = get_highlighted_identifier_as_int()
		create_struct_with_size(size)

	def update(self, ctx):
		#return idaapi.AST_ENABLE_FOR_FORM if ctx.form_title.startswith('Pseudocode') else idaapi.AST_DISABLE_FOR_FORM
		# lets always enable it
		return idaapi.AST_ENABLE_FOR_FORM

class CopyStructAndFill(BaseGuiAction):
	action_name = "bip:copystructandfill"
	action_label = "Copy struct..."
	action_shortcut = "Shift+Alt+E"

	def __init__(self):
		super(CopyStructAndFill, self).__init__()
		self.attach_to_menu("Edit")

	def should_attach_to_popup(self, form, popup):
		return True

	def activate(self, ctx):
		size = get_highlighted_identifier_as_int()
		copy_struct_with_size(size)

	def update(self, ctx):
		return idaapi.AST_ENABLE_FOR_FORM



# Forms

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
			s = BipStruct.create(name.value)
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
			s = BipStruct.create(name.value)
			s.fill(num.value)
			break
		except ValueError as e:
			Warning(str(e))


class myplugin_t(idaapi.plugin_t):
	flags = 0
	comment = "Provides helpers actions to deal with structs"
	wanted_name = "Bip Struct Helpers"
	wanted_hotkey = "Alt-F8"
	help = "lol"

	def init(self):
		actions = [CreateStructAction()]
		hook = ContextMenuHooks(actions)
		hook.hook()
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		pass

	def term(self):
		pass

def PLUGIN_ENTRY():
	return myplugin_t()

