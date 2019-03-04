import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_gdl
import ida_bytes

from idaelt import IdaElt, GetElt
import instr
import block
import xref
from biperror import BipError

try:
    import bip.hexrays as hexrays
except ImportError:
    # TODO change this by a real log system ?
    print("WARNING: unable to import hexrays")
    hexrays = None

class IdaFuncFlags(object):
    """
        Enum for the function flags from IDA. ``FUNC_*`` flags. Documentation
        of the flags is from the IDA documentation

        .. todo:: doc sphinx complient
    """
    FUNC_NORET          = idaapi.FUNC_NORET         # function doesn't return
    FUNC_FAR            = idaapi.FUNC_FAR           # far function
    FUNC_LIB            = idaapi.FUNC_LIB           # library function
    FUNC_STATIC         = idaapi.FUNC_STATICDEF     # static function
    FUNC_FRAME          = idaapi.FUNC_FRAME         # function uses frame pointer (BP)
    FUNC_USERFAR        = idaapi.FUNC_USERFAR       # user has specified far-ness
                                                    # of the function
    FUNC_HIDDEN         = idaapi.FUNC_HIDDEN        # a hidden function
    FUNC_THUNK          = idaapi.FUNC_THUNK         # thunk (jump) function
    FUNC_BOTTOMBP       = idaapi.FUNC_BOTTOMBP      # BP points to the bottom of the stack frame
    FUNC_NORET_PENDING  = idaapi.FUNC_NORET_PENDING # Function 'non-return' analysis
                                                    # must be performed. This flag is
                                                    # verified upon func_does_return()
    FUNC_SP_READY       = idaapi.FUNC_SP_READY      # SP-analysis has been performed
                                                    # If this flag is on, the stack
                                                    # change points should not be not
                                                    # modified anymore. Currently this
                                                    # analysis is performed only for PC
    FUNC_PURGED_OK      = idaapi.FUNC_PURGED_OK     # 'argsize' field has been validated.
                                                    # If this bit is clear and 'argsize'
                                                    # is 0, then we do not known the real
                                                    # number of bytes removed from
                                                    # the stack. This bit is handled
                                                    # by the processor module.
    FUNC_TAIL           = idaapi.FUNC_TAIL          # This is a function tail.
                                                    # Other bits must be clear
                                                    # (except FUNC_HIDDEN)

    FUNCATTR_FLAGS      = idc.FUNCATTR_FLAGS

class IdaFlowChartFlag(object):
    """
        Enum for the flag of the flow chart. ``FC_*`` constant. Documentation
        of the flags is from the IDA documentation.
    """
    #: print names (used only by display_flow_chart())
    FC_PRINT = ida_gdl.FC_PRINT
    #: do not compute external blocks. Use this to prevent jumps leaving the
    #:  function from appearing in the flow chart. Unless specified, the
    #:  targets of those outgoing jumps will be present in the flow chart
    #:  under the form of one-instruction blocks
    FC_NOEXT = ida_gdl.FC_NOEXT
    #: compute predecessor lists
    FC_PREDS = ida_gdl.FC_PREDS
    #: multirange flowchart (set by append_to_flowchart)
    FC_APPND = ida_gdl.FC_APPND
    #: build_qflow_chart() may be aborted by user
    FC_CHKBREAK = ida_gdl.FC_CHKBREAK

class IdaFunction(object):
    """
        Class for representing and manipulating function in IDA.

        .. todo:: test
        .. todo:: provide interface for flowgraph and allow to get all basicblocks and not only the one included in the function (external block: without FC_NOEXT flag)
        .. todo:: equality and inclusion operator
        .. todo:: pretty printer (__str__ func)
        .. todo:: Interface with stack
        .. todo:: color
        .. todo:: hexray interface
        .. todo:: get/set calling convention (hexray)
        .. todo:: get/set arguments/ret type (hexray)
        .. todo:: frame ?
    """

    ################################# BASE #################################

    def __init__(self, ea):
        """
            Constructor for a :class:`IdaFunction` object.

            This function will raise a ``ValueError`` if the address ``ea``
            is not in the function.

            :param ea: An address included in the function, it does not need
                to be the first one.
        """
        #: Internal func_t object from IDA
        self._funct = idaapi.get_func(ea)
        if self._funct is None:
            raise ValueError("Address 0x{:X} is not inside a function".format(ea))


    @property
    def ea(self):
        """
            Property which return the start address of the function.

            :return int: The address of the function.
        """
        return self._funct.start_ea

    # TODO setter of start ea ?

    @property
    def end(self):
        """
            Property which return the address at the end of the function.
            This address is not included in the function.

            :return int: The stop address of the function. This address is 
                not included in the function.
        """
        return self._funct.end_ea

    # TODO setter of end ea ?

    @property
    def size(self):
        """
            Property which allow to get the size of the function in bytes.

            :return int: The number of bytes in the function.
        """
        return self._funct.size()

    @property
    def name(self):
        """
            Property which return the name of the function as display in the
            IDA window.

            .. todo:: this does not handle mangling

            :return str: The name of the function.
        """
        return idc.get_name(self.ea, ida_name.GN_VISIBLE)

    @name.setter
    def name(self, value):
        """
            Setter for changing the name of the function.

            :param str value: The new name of the function, if an empty string
                is provided it will revert to the default name provided by
                IDA (``sub_...``).
        """
        idc.set_name(self.ea, value, idc.SN_CHECK)

    @property
    def truename(self):
        """
            Property which return the true name of the function.

            :return str: The true name of the function.
        """
        return idc.get_name(self.ea)

    @property
    def ordinal(self):
        """
            Property which return the ordinal of this function.

            :return int: The number corresponding to the ordinal of this
                function.
        """
        return idaapi.get_func_num(self.ea)

    def __str__(self):
        return "Func: {} (0x{:X})".format(self.name, self.ea)

    
    def __cmp__(self, other):
        if not isinstance(other, IdaFunction):
            raise TypeError("Not an IdaFunction")
        
        if self.ea < other.ea:
            return -1
        elif self.ea > other.ea:
            return 1
        else:
            return 0
        

    ######################## Hexrays ###############################

    @property
    def hxfunc(self):
        """
            Property which return the hexrays C function (:class:`HxCFunc`)
            for this function.

            If if it not possible to import the hexrays API an NotImplemented
            error will be raised.

            This may raise an ``ida_hexrays.DecompilationFailure`` if the
            decompilation failed.

            :return: A :class:`HxCFunc` object equivalent to this function.
        """
        if hexrays is None:
            raise NotImplemented("It appears the hexrays API is not available")
        return hexrays.HxCFunc.from_addr(self.ea)


    ####################### FLAGS & INFO ############################

    @property
    def flags(self):
        """
            Property which return the function flags as returned by
            ``idc.GetFunctionFlags`` .

            :return int: The flags for this function.
        """
        #idc.GetFunctionFlags(self.ea) # deprecated
        return idc.get_func_attr(self.ea, IdaFuncFlags.FUNCATTR_FLAGS)

    @flags.setter
    def flags(self, value):
        """
            Setter which allow to modify the functions flags.
        """
        idc.set_func_attr(self.ea, IdaFuncFlags.FUNCATTR_FLAGS, flags)

    @property
    def does_return(self):
        """
            Property which indicate if the function is expected to return.

            :return boolean: True if the function is expected to return.
        """
        return self._funct.does_return()

    def is_inside(self, o):
        """
            Allow to check if an address or an :class:`IdaElt` object (or
            inherited) is included in this function. In particular it
            allow to check if an :class:`Instr` is included in a function.

            This function will raise a ``TypeError`` exception if the
            parameter ``o`` is not from a valid type.

            :param o: The address or object to test for inclusion.
            :type o: ``int`` coresponding to an address or an object inherited
                from :class:`IdaElt` .
        """
        if isinstance(o, (long, int)):
            return self._funct.contains(o)
        elif isinstance(o, IdaElt):
            return self._funct.contains(o.ea)
        else:
            raise TypeError("Object {} is not of a valid type".format(o))

    @property
    def is_far(self):
        """
            Check flags of this function for knowing if this is a far
            function.

            .. todo:: Test
        """
        return self.flags & IdaFuncFlags.FUNC_FAR != 0

    @property
    def is_lib(self):
        """
            Check flags of this function for knowing if this is a library
            function.

            .. todo:: Test
        """
        return self.flags & IdaFuncFlags.FUNC_LIB != 0

    @property
    def is_static(self):
        """
            Check flags of this function for knowing if this is a static
            function.

            .. todo:: Test
        """
        return self.flags & IdaFuncFlags.FUNC_STATICDEF != 0

    @property
    def use_frame(self):
        """
            Check flags of this function for knowing if it is using the frame
            pointer.

            .. todo:: Test
        """
        return self.flags & IdaFuncFlags.FUNC_FRAME != 0

    @property
    def is_userfar(self):
        """
            Check flags of this function for knowing if the user as define
            the function as change the marking of the function being far or
            not.

            .. todo:: Test
        """
        return self.flags & IdaFuncFlags.FUNC_USERFAR != 0

    @property
    def is_hidden(self):
        """
            Check flags of this function for knowing if its a hidden function.

            .. todo:: Test
        """
        return self.flags & IdaFuncFlags.FUNC_HIDDEN != 0

    @property
    def is_thunk(self):
        """
            Check flags of this function for knowing if its a thunk function.

            .. todo:: Test
        """
        return self.flags & IdaFuncFlags.FUNC_THUNK != 0


    ############################ COMMENT ##############################

    @property
    def comment(self):
        """
            Property which allow access to the comment.

            .. todo:: Test
        """
        return idc.GetFunctionCmt(self.ea, False)

    @comment.setter
    def comment(self, value):
        """
            Setter which allow to modify the comment.

            .. todo:: Test
        """
        return idc.SetFunctionCmt(self.ea, value, False)

    @property
    def rcomment(self):
        """
            Property which allow access to the repeatable comment.

            .. todo:: Test
        """
        return idc.GetFunctionCmt(self.ea, True)

    @rcomment.setter
    def rcomment(self, value):
        """
            Setter which allow to modify the repeatable comment.

            .. todo:: Test
        """
        return idc.SetFunctionCmt(self.ea, value, True)

    ######################## FLOWCHART & BASICBLOCK #########################

    @property
    def _flowchart(self):
        """
            Return a ``FlowChart`` object as defined by IDA in ``ida_gdl.py``.
            This is used for getting the basic block and should not be used
            directly.

            .. note::
            
                Internally this is compute with the flags
                ``IdaFlowChartFlag.FC_PREDS`` and
                ``IdaFlowChartFlag.FC_NOEXT`` .

            :return: An ``idaapi.FlowChart`` object.
        """
        return idaapi.FlowChart(self._funct,
                flags=(IdaFlowChartFlag.FC_PREDS|IdaFlowChartFlag.FC_NOEXT))

    @property
    def nb_blocks(self):
        """
            Return the number of blocks present in this function.
        """
        return self._flowchart.size

    @property
    def blocks(self):
        """
            Return a list of :class:`IdaBlock` corresponding to the
            BasicBlocks in this function.

            :return: A list of object :class:`IdaBlock`
        """
        fc = self._flowchart
        return [block.IdaBlock(b) for b in fc]

    
    @property
    def blocks_iter(self):
        """
            Return a generator of :class:`IdaBlock` corresponding to the
            BasicBlocks in this function. This implementation will be just
            a little more performant than the :meth:`blocks` property.

            :return: A generator of object :class:`IdaBlock`
        """
        fc = self._flowchart
        for b in fc:
            yield block.IdaBlock(b) 

    ############################# INSTR & ITEMS ############################

    @property
    def items(self):
        """
            Return a list of :class:`IdaElt` corresponding to the items of 
            the functions.

            .. todo:: Test

            .. note::
                
                This should mainly be :class:`Instr` but possible in theory
                to be other kind of data ?

            :return: A list of object :class:`IdaElt`.
        """
        return [GetElt(e) for e in idautils.FuncItems(self.ea)]

    @property
    def instr(self):
        """
            Return a list of :class:`Instr` corresponding to the instructions
            of the functions.

            .. todo:: Test

            :return: A list of object :class:`Instr`
        """
        return [instr.Instr(h) for h in idautils.Heads(self.ea, self.end) if idc.is_code(ida_bytes.get_full_flags(h))]

    @property
    def instr_iter(self):
        """
            Return a generator of :class:`Instr` corresponding to the
            instructions of the functions. This implementation will be just
            a little more performant than the :meth:`instr` property.

            .. todo:: Test

            :return: A generator of object :class:`Instr`
        """
        for h in idautils.Heads(self.ea, self.end):
            if idc.is_code(ida_bytes.get_full_flags(h)):
                yield instr.Instr(h)

    @property
    def bytes(self):
        """
            Property returning the value of the bytes contain in the function.

            .. todo:: Test


            :return: A list of the bytes forming the element.
            :rtype: list(int)
        """
        return [idc.Byte(i) for i in range(self.ea, self.end)]


    ############################ TYPE, ARGS, .... #########################

    @property
    def type(self):
        """
            Property which return the type (prototype) of the function.

            .. todo:: Test


            .. todo::

                Merge with guesstype if no type set ?
                This could create problems...

            :return str: String representing the type of the function.
        """
        return idc.get_type(self.ea)

    @type.setter
    def type(self, value):
        """
            Setter which allow to change the type (prototype) of the function.

            .. todo:: Test

        """
        idc.SetType(self.ea, value)

    @property
    def guesstype(self):
        """
            Property which allow to return the prototype of the function
            guessed by IDA.

            :return str: The guess prototype of the function.
        """
        return idc.guess_type(self.ea)

    ########################## XREFS #########################

    # The basic from makes no sense what so ever

    @property
    def xTo(self):
        """
            Property which allow to get all xrefs pointing to (to) this
            function. This is the equivalent to ``XrefsTo`` from idapython on
            the first instruction.

            .. todo:: Test

            :return: A list of :class:`IdaXref` with the ``dst`` being this
                element.
        """
        return [xref.IdaXref(x) for x in idautils.XrefsTo(self.ea)]

    @property
    def xEaTo(self):
        """
            Property which allow to get all addresses which referenced this
            function (xref to).

            .. todo:: Test

            :return: A list of address.
        """
        return [x.src_ea for x in self.xTo]

    @property
    def xEltTo(self):
        """
            Property which allow to get all elements which referenced this
            element (xref to).

            .. todo:: Test

            :return: A list of :class:`IdaElt` (or subclasses
                of :class:`IdaElt`).
        """
        return [x.src for x in self.xTo]

    @property
    def xCodeTo(self):
        """
            Property which return all instructions which referenced this
            element. This will take into account jmp, call, ordinary flow and
            "data" references.

            .. todo:: Test

            :return: A list of :class:`Instr` referenced by this element.
        """
        return [x.src for x in self.xTo if x.src.is_code]

    @property
    def callers(self):
        """
            Property which return a list of all the functions which call this
            function.

            This function will not take into account jmp or ordinary flow to
            this function.

            .. todo:: Test

            :return: A list of :class:`IdaFunction` which call this function.
        """
        return [IdaFunction(ea) for ea in set([x.src_ea for x in self.xTo if x.is_call])]

    @property
    def callees(self):
        """
            Property which return a list of the functions which are called by
            this one.
            
            Internally this function will iterate on all instruction for
            getting the call xref. This can be quite time consuming.

            .. todo:: Test

            :return: A list of :class:`IdaFunction` which are called by this
                function.
        """
        l = []
        for i in self.instr_iter:
            for x in i.xFrom:
                if x.is_call:
                    l.append(IdaFunction(x.dst_ea))
        return l

    

    ########################## CLASS METHOD ############################


    @classmethod
    def ByOrdinal(cls, ordinal):
        """
            Get an :class:`IdaFunction` from its ordinal, there is between
            ``0`` and ``IdaFunction.Count()`` function in an IDB.

            .. todo:: Test
        """
        return cls(ida_funcs.getn_func(ordinal).start_ea)

    @classmethod
    def iter_all(cls):
        """
            Class method allowing to iter on all the functions define in
            the IDB.

            .. todo:: Test

            :return: A generator of :class:`IdaFunction` allowing to iter on
                all the functions define in the idb.
        """
        for ea in idautils.Functions():
            yield cls(ea)

    @classmethod
    def get_by_name(cls, name):
        """
            .. todo:: doc

            .. todo:: there is something better to do for this
        """
        for f in cls.iter_all():
            if f.name == name:
                return f


    @classmethod
    def get_by_prefix(cls, name):
        """
            Class method allowing to get all the functions which are named
            with a particular prefix.
        """
        return [f for f in cls.iter_all() if f.name.startswith(name)]


    @classmethod
    def create(cls, start, end=None):
        """
            Class method allowing to create a new function.

            .. todo:: test

            :param int start: Start address for the function to create.
            :param int end: Facultative argument which indicate the end
                address of the function. If is is not provided (None, default
                value) it will try to create a function using the
                auto-analysis of IDA.
            :return: A new :class:`IdaFunction` object corresponding to the
                function create. If this function was not able to create the
                new function a ``BipError`` will be raised.
        """
        if end is None:
            end = 0xffffffffffffffff # default IDA value meaning auto analysis
        if not idc.MakeFunction(start, end):
            raise BipError("Unable to create function at 0x{:X}".format(start))
        return cls(start)

    ########################## STATIC METHOD ############################

    @staticmethod
    def Count():
        """
            Return the number of functions which are present in the idb.
        """
        return ida_funcs.get_func_qty()

    


