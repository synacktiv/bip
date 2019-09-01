from bip.base import *
from bip.hexrays import *
from bip.gui import *
from bip.hexrays.cnode import *

"""
    Search for all call to printk, if possible recuperate the string and add
    it in comments at the level of the call.
"""

def ignore_cast_ref(cn):
    """
        Ignore cast and ref (``&`` operator in C) node and return the
        resulting node.
 
        Ignoring cast is a common problem, ignoring ref can be a really bad
        idea.

        :param cn: An object which inherit from :class:`CNode`.
        :return: An object which inherit from :class:`CNode`, will not be
            a :class:`CNodeExprCast` or :class:`CNodeExprRef` .
    """
    if isinstance(cn, (CNodeExprCast, CNodeExprRef)):
        return ignore_cast_ref(cn.ops[0])
    return cn

def is_call_to_printk(cn):
    """
        Check if the node object represent a call to the function ``printk``.

        :param cn: A :class:`CNodeExprCall` object.
        :return: True if it is a call to printk, False otherwise
    """
    c = ignore_cast_ref(cn.caller) # get the node representing the function
    if not isinstance(c, CNodeExprObj):
        # if it is not an object just ignore it, object are for everything
        # which has an address, including functions. We don't handle lvar and
        # or wierd case.
        return False
    # Check if it calls to printk. For more perf. we would want to use xref
    #   to printk and checks of the address of the node
    try:
        return BipFunction(c.value).name == "printk"
    except Exception: # handle exception in case IDA has not define it as a function.
        return False

def get_ea_arg(cn, argnum):
    """
        Get the address or number of an argument for a call.

        This ignore ref and return number as valid (handling IDA fail).

        :param cn: A :class:`CNodeExprCall` object.
        :param argnum: The position of the argument to get (0 is the first).
        :return: The address or number of the arg or None in case of error.
    """
    if cn.number_args < argnum + 1: # if we don't have the argument ignore
        #print("Call without arg {} at 0x{:X}".format(argnum, cn.ea))
        return None
    
    # lets get the address of the structure in first arg
    karg = ignore_cast_ref(cn.args[argnum])
    if not isinstance(karg, (CNodeExprNum, CNodeExprObj)):
        # we check for Num in case hexrays have failed, do not handle
        #   lvar and so on
        #print("Unhandle argument type ({}) at 0x{:X}".format(karg, cn.ea))
        return None
    return karg.value

def visit_call_printk(cn):
    """
        Visitor for call node which will check if a node is a call to
        ``printk`` and add the string in comment if possible.
        
        :param cn: A :class:`CNodeExprCall` object.
    """
    if not is_call_to_printk(cn): # not a call to printk: ignore
        return
    try:
        ea = get_ea_arg(cn, 0)
        s = BipData.get_cstring(ea + 2) # get the string
        if s is None or s == "":
            #print("Invalid string at 0x{:X}".format(cn.ea))
            return
        s = s.strip() # remove \n
        cn.cfunc.add_cmt(cn.ea, s)
        GetElt(cn.ea).comment = s
    except Exception: 
        #print("Exception at 0x{:X}".format(cn.ea))
        return

class PrintkComs(BipPlugin):

    def printk_handler(self, eafunc):
        """
            Comment all call to printk in a function with the format string
            pass to the printk. Comments are added in both the hexrays and ASM
            view. Works only if the first argument is a global.

            :param eafunc: The addess of the function in which to add the 
                comment.
        """
        try:
            hf = HxCFunc.from_addr(eafunc) # get hexray view of the func
        except Exception:
            print("Fail getting the decompile view for function at 0x{:X}".format(eafunc))
            return
        hf.visit_cnode_filterlist(visit_call_printk, [CNodeExprCall]) # visit only on the call

    @shortcut("Ctrl-H")
    def printk_current(self):
        self.printk_handler(Here())

    @menu("Edit/Plugins/", "Comment all printk")
    def printk_all(self):
        # get the function which call printk
        f = BipFunction.get_by_name("printk")
        if f is None:
            print("No function named printk")
            return
        for fu in f.callers:
            print("Renaming for {}".format(fu))
            self.printk_handler(fu.ea)


