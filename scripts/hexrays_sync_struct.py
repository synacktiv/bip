from bip.base import Struct
from bip.hexrays import HexRaysEvent

from ida_hexrays import *
from idaapi import ctree_visitor_t, CV_FAST, CV_PARENTS
import idc
from idc import *
from idc import GetCommentEx, op_stroff

# TODO: this will be change when a proper hexrays api as been integrated in bip

def get_struct_from_lvar(lvar):
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

def find_addr(expr, parents):
    """
        Try to find the address to which belong the expression. For doing this
        it try to iterate on the parents.
        
        * expr: an ``ida_hexrays.cexpr_t`` as recuperated as argument of the ``ctree_visitor_t.visit_expr`` method
        * parents: an ``ida_hexrays.ctree_items_t`` (a ``qvector< citem_t * > *`` in reality) such as recuperated through the ``ctree_visitor_t.parents`` attribute
        
        return ``idc.BADADDR`` if it could not find the address, else return the address.
    """
    if expr is None: # can't do anything here
        return idc.BADADDR

    if expr.ea != idc.BADADDR: # check if addr is good
        return expr.ea

    if parents is None:
        return idc.BADADDR
    
    cur = expr
    for elt in parents:
        if elt is None:
            continue
        try:
            while cur is not None:
                cur = elt.find_parent_of(cur)
                if cur.ea != idc.BADADDR:
                    return cur.ea
        except Exception:
            continue
    return idc.BADADDR


class visitor_propagator(ctree_visitor_t):
    def __init__(self, func, set_all_operand=False):
        """
            Constructor for the visitor in charge to propagate the information
            on the structure from the decompile version of hexrays into the
            assembler.
            
            * func: a ``ida_hexrays.cfuncptr_t`` function such as return by the function decompile or as first argument of the event 12
            * set_all_operand: a boolean (default False) which allow to not check the type of the operands before setting them as an offset of the structure
        """
        #ctree_visitor_t.__init__(self, CV_FAST)
        # TODO: this should probably be done with super
        # CV_PARENTS for having parent information
        ctree_visitor_t.__init__(self, CV_PARENTS)
        self.set_all_operand = set_all_operand
        self.func = func

    def visit_expr(self, i):
        ea = find_addr(i, self.parents)
        if i.opname == 'memptr' and ea != idc.BADADDR:
            if i.x.v is None:
                return 0
            lvar = self.func.lvars[i.x.v.idx]

            s = get_struct_from_lvar(lvar)
            if s is not None:
                print '0x%x () : ref to %s + 0x%x' % (ea, self.func.lvars[i.x.v.idx].name, i.m)
                if self.set_all_operand:
                    op_stroff(ea, -1, s.sid, 0)
                else:
                    # this convert only the displacement access, this is
                    #   mainly for avoiding to convert the immediate as an
                    #   offset in a structure when assignement
                    #   something smarter should be done for getting which
                    #   operand should be set
                    # TODO: Use bip.base.Instr for doing that
                    if get_operand_type(ea, 0) == o_displ:
                        op_stroff(ea, 0, s.sid, 0)
                    if get_operand_type(ea, 1) == o_displ:
                        op_stroff(ea, 1, s.sid, 0)

        return 0 # continue enumeration


def hexrays_propagate_structs(event, *args):
    if event == HexRaysEvent.hxe_print_func:
        f = args[0]
        visitor_propagator(f).apply_to(f.body, None)
    return 0


def install():
    install_hexrays_callback(hexrays_propagate_structs)

def uninstall():
    remove_hexrays_callback(hexrays_propagate_structs)

# TODO:
#   * make a "real" plugin
#   * provide an api for making it on a precise function
#   * find a better event than the event 12 & stop it from reapplying the type if there as been change or maybe just make something for reapplying it ?
#   * handle the split instruction case
#   * document everything



# import bip.hexrays_callbacks as cb; cb.install()
