import sys
sys.path.append(r"E:\bip")


from ida_hexrays import *
from idaapi import ctree_visitor_t, CV_FAST, CV_PARENTS
from bip.hexrays import *
# TODO make this compatible with pytest



class visit(ctree_visitor_t):

    def __init__(self, func):
        ctree_visitor_t.__init__(self, CV_FAST)
        #ctree_visitor_t.__init__(self, CV_PARENTS)
	self.func = func

    def visit_expr(self, i):
        print(GetHxCItem(i))
	return 0

def test_visit00():
    f = decompile(0x01800D2FF0)
    visit(f).apply_to(f.body, None)

