from bip.base import *
from bip.hexrays import *
from bip.hexrays.cnode import *

# TODO IMPORTANT: if offset is 0 for propagation that will not be the same node type

#from ida_hexrays import *
#from idaapi import ctree_visitor_t, CV_FAST, CV_PARENTS
import idc
from idc import *
from idc import GetCommentEx, op_stroff
import ida_hexrays

# TODO: integrate in IdaType
def get_struct_from_tinfo(t):
    if t.is_ptr():
        s = t.get_pointed_object()
        if s.is_struct():
            try: # TODO this does not work correctly with typedef for struct
                struct = IdaStruct.get(s.get_type_name())
                return struct
            except ValueError:
                print("could not find struct for {}".format(s.get_type_name()))
                return None
        else:
            print("type does not point on a struct")
    else:
        print("type is not a ptr")


    return None

# TODO: integrate in lvar
def get_struct_from_lvar_local(lvar):
    return get_struct_from_tinfo(lvar.type._tinfo)

# TODO: integrate in bip
def get_struct_from_addr(go):
    return get_struct_from_tinfo(IdaType.get_at(go)._tinfo)

def visit_propag(cn, num_ops=2, set_all_operand=False):
    ea = cn.closest_ea
    if ea is None:
        return
    if isinstance(cn, CNodeExprMemptr):
        ob = cn.ptr
    elif isinstance(cn, CNodeExprMemref):
        ob = cn.mem
    else: # should never happen
        print("Unexpected node type")
        return

    off = cn.off

    ob = ob.find_left_node_notmatching([CNodeExprCast, CNodeExprRef])

    if isinstance(ob, CNodeExprVar):
        lv = ob.lvar

        st = get_struct_from_lvar_local(lv)
        if st is None:
            print("Could not find struct from lvar (ea=0x{:X}, obj={}, lvar={})".format(ea, ob, lv))
            return
    elif isinstance(ob, CNodeExprObj): # global object
        go = ob.value
        if go == idc.BADADDR:
            print("object with bad address (ea=0x{:X}, obj={})".format(ea, ob))
            return
        st = get_struct_from_addr(go)
        if st is None:
            print("Could not find struct from address (ea=0x{:X}, obj={}, addr=0x{:X})".format(ea, ob, go))
            return
    else:
        print("Unexpected object type (ea=0x{:X}, obj={})".format(ea, ob))
        return

    # TODO: fix this:
    #   * use bip.base.Instr
    #   * use map of addr (once implemented)
    #   * fix the struct for when having a Memref (only Memptr will work right now)
    if set_all_operand:
        op_stroff(ea, -1, st._sid, 0)
    else:
        for _ in range(num_ops):
            # TODO: should not be necessary once we have the map we should be
            #   able to do that directly
            i = Instr(ea)
            c = 0
            for o in i.ops:
                # check if operand is a displacement and has the correct value
                if ((o.type == OpType.DISPL and o.value == off)
                    or (off == 0 and o.type == OpType.PHRASE)):
                    op_stroff(ea, c, st._sid, 0) # TODO: change this with bip stuff
                    print("Struct found at 0x{:X}".format(ea))
                    return # we found the operand
                c += 1
            ea += i.size
        print("Struct not found for ea=0x{:X}".format(ea))


def propagate_for_func(ea):
    f = IdaFunction(ea)
    f.hxfunc.visit_cnode_filterlist(visit_propag, [CNodeExprMemref, CNodeExprMemptr])


def propagate_all_func():
    for f in IdaFunction.iter_all():
        try:
            f.hxfunc.visit_cnode_filterlist(visit_propag, [CNodeExprMemref, CNodeExprMemptr])
        except ida_hexrays.DecompilationFailure:
            print("Decompile failure at 0x{:X}".format(f.ea))
            continue


# TODO:
#   * make a "real" plugin
#   * support use with callbacks
#   * handle the split instruction case with ea map
#   * document everything



# import bip.hexrays_callbacks as cb; cb.install()

