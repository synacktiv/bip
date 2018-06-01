from bip.utils import *
from bip.controllers import *

class BaseGuiAction(idaapi.action_handler_t, object):
	action_name = None
	action_label = None
	action_shortcut = None
	action_tooltip = None
	action_icon = None
	
	def __init__(self):
		idaapi.action_handler_t.__init__(self)
		self.register()
		print "registered"

	def activate(self, ctx):
		raise NotImplementedError("activate method should be overrided")

	def register(self):
		idaapi.register_action(idaapi.action_desc_t(
			self.action_name, self.action_label, self, self.action_shortcut,
			self.action_tooltip, self.action_icon if self.action_icon else -1
		))

	def attach_to_menu(self, path, flags=idaapi.SETMENU_APP):
		# by default, add menu item after the specified path (can also be SETMENU_INS)
		idaapi.attach_action_to_menu(path, self.action_name, flags)

	def attach_to_toolbar(self, toolbar_name):
		idaapi.attach_action_to_toolbar(toolbar_name, self.action_name)
		
	def should_attach_to_popup(self, form, popup):
		""" Fired upon ctx menu spawning. Decided weither the action should be added """
		# popup = ctx menu
		return False

	def update(self, ctx):
		""" Fired upon form focus change
		returns one of :
		AST_DISABLE
		AST_DISABLE_ALWAYS
		AST_DISABLE_FOR_FORM
		AST_DISABLE_FOR_IDB
		AST_ENABLE
		AST_ENABLE_ALWAYS
		AST_ENABLE_FOR_FORM
		AST_ENABLE_FOR_IDB
		"""
		print "[!] update method was not overriden, hardcoded AST_ENABLE_FOR_FORM"
		return idaapi.AST_ENABLE_FOR_FORM

CTX = None

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
	
class ContextMenuHooks(idaapi.UI_Hooks):
	"""
	Hook to enable on-the-fly context menu action registering
	"""
	def __init__(self, actions):
		self.actions = actions
		super(ContextMenuHooks, self).__init__()
	
	def finish_populating_tform_popup(self, form, popup):
		print self.actions
		for action in self.actions:
			if action.should_attach_to_popup(form, popup):
				idaapi.attach_action_to_popup(form, popup, action.action_name, None)
