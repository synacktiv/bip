from bip.base.utils import *
from bip.hexrays import HexRaysEvent
from ida_hexrays import *
from idaapi import ctree_visitor_t, CV_FAST
from idc import *
from idc import GetCommentEx

def hexrays_propagate_comments(event, *args):
    if event == HexRaysEvent.hxe_func_printed:
        f = args[0]
        cmts = f.user_cmts

        for c in cmts:
            ida_cmt = GetCommentEx(c.ea, 0)
            if not ida_cmt or ida_cmt.startswith('HR: '):
                MakeComm(c.ea, 'HR: '+f.get_user_cmt(c, 1))

    return 0


def install():
    install_hexrays_callback(hexrays_propagate_comments)

def uninstall():
    remove_hexrays_callback(hexrays_propagate_comments)


