from bip.models import Struct
from bip.utils import *
from ida_hexrays import *
from idaapi import ctree_visitor_t, CV_FAST
from idc import *
from idc import GetCommentEx

def hexrays_propagate_comments(event, *args):
	if event == 13:		
		f = args[0]
		cmts = f.user_cmts

		for c in cmts:
			ida_cmt = GetCommentEx(c.ea, 0)
			if not ida_cmt or ida_cmt.startswith('HR: '):
				MakeComm(c.ea, 'HR: '+f.get_user_cmt(c, 1))

	return 0




def hexrays_propagate_structs(event, *args):
	class visitor(ctree_visitor_t):
		def __init__(self, lvar):
			self.lvar = lvar
			ctree_visitor_t.__init__(self, CV_FAST)
			return

		def visit_expr(self, i):
			if i.opname == 'memptr' and i.ea != 0xffffffffffffffff:
				lvar = f.lvars[i.x.v.idx]

				if lvar == self.lvar:
					s = get_struct_from_lvar(lvar)
					if s is not None:
						print '0x%x () : ref to %s + 0x%x' % (i.ea, f.lvars[i.x.v.idx].name, i.m)
						# fixme bla
						op_stroff(i.ea, -1, s.sid, 0)


			return 0 # continue enumeration
			
	print event
			
	if event == 112:
		ui = args[0]
		lvar = args[1]
		visitor(lvar).apply_to(ui.cfunc.body, None)

	elif event == 114:
		ui = args[0]
		to = args[2]
		visitor(to).apply_to(ui.cfunc.body, None) 

	return 0

def install():
	install_hexrays_callback(hexrays_propagate_structs)
	install_hexrays_callback(hexrays_propagate_comments)

def uninstall():
	remove_hexrays_callback(hexrays_propagate_structs)
	remove_hexrays_callback(hexrays_propagate_comments)
	
