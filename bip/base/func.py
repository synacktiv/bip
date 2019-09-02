import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_gdl
import ida_bytes
import ida_typeinf
import ida_kernwin

from bipelt import BipElt, GetElt
import instr
import block
import xref
from biperror import BipError

try:
    import bip.hexrays as hexrays
except Exception:
#except ImportError: # fix build of the doc for this and support the correct exception
    # TODO change this by a real log system ?
    print("WARNING: unable to import hexrays")
    hexrays = None

class BipFuncFlags(object):
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

class BipFlowChartFlag(object):
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

class BipFunction(object):
    """
        Class for representing and manipulating function in IDA.

        .. todo:: provide interface for flowgraph and allow to get all basicblocks and not only the one included in the function (external block: without FC_NOEXT flag)
        .. todo:: Interface with stack
        .. todo:: color
        .. todo:: get/set calling convention (hexray)
        .. todo:: get/set arguments/ret type (hexray)
        .. todo:: frame ?
    """

    ################################# BASE #################################

    def __init__(self, ea=None):
        """
            Constructor for a :class:`BipFunction` object.

            This function will raise a ``ValueError`` if the address ``ea``
            is not in the function.

            :param ea: An address included in the function, it does not need
                to be the first one. If ``None`` the screen address is used.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
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

    ############################ CMP FUNCTIONS #############################
    
    def __cmp__(self, other):
        """
            Compare with another BipFunction. Will return 0 if the functions
            have the same address, and -1 or 1 depending on the other function
            position. This will raise a ``TypeError`` exception if the
            argument is not a :class:`BipFunction` .
        """
        if not isinstance(other, BipFunction):
            raise TypeError("Not a BipFunction")
        
        if self.ea < other.ea:
            return -1
        elif self.ea > other.ea:
            return 1
        else:
            return 0

    def __hash__(self):
        """
            Compute a unique hash for this ida function. The produce hash is
            dependant of the type of the object (:class:`BipFunction`) and
            of its address. This allow to create container using the hash
            of the object for matching an object of a defined type and with
            a particular address.

            Calculation made is: ``hash(type(self)) ^ self.ea``, in particular
            it means than child classes will not have the same hash as a
            parrent classes even if the compare works.

            :return: An integer corresponding to the hash for this object.
        """
        return hash(type(self)) ^ self.ea

    def __contains__(self, value):
        """
            Allow to check if an element is included inside this function. It
            accepts the following in arguments:

            * :class:`BipElt` (including :class:`Instr`)
            * :class:`BipBlock`
            * An integer corresponding to an address.

            In all those case the address of the element is used for testing
            if it is present in the function.
        """
        if isinstance(value, (BipElt, block.BipBlock)):
            ea = value.ea
        elif isinstance(value, (int, long)):
            ea = value
        else:
            raise TypeError("Unknown type comparaison for {} with BipFunction.".format(value))
        return ea >= self.ea and ea < self.end

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
            ``idc.GetFunctionFlags`` (old) or
            ``idc.get_func_attr(ea, FUNCATTR_FLAGS)`` (new).

            :return int: The flags for this function.
        """
        return idc.get_func_attr(self.ea, BipFuncFlags.FUNCATTR_FLAGS)

    @flags.setter
    def flags(self, value):
        """
            Setter which allow to modify the functions flags.
        """
        idc.set_func_attr(self.ea, BipFuncFlags.FUNCATTR_FLAGS, flags)

    @property
    def does_return(self):
        """
            Property which indicate if the function is expected to return.

            :return boolean: True if the function is expected to return.
        """
        return self._funct.does_return()

    def is_inside(self, o):
        """
            Allow to check if an address or an :class:`BipElt` object (or
            inherited) is included in this function. In particular it
            allow to check if an :class:`Instr` is included in a function.

            This function will raise a ``TypeError`` exception if the
            parameter ``o`` is not from a valid type.

            :param o: The address or object to test for inclusion.
            :type o: ``int`` coresponding to an address or an object inherited
                from :class:`BipElt` .
        """
        if isinstance(o, (long, int)):
            return self._funct.contains(o)
        elif isinstance(o, BipElt):
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
        return self.flags & BipFuncFlags.FUNC_FAR != 0

    @property
    def is_lib(self):
        """
            Check flags of this function for knowing if this is a library
            function.

            .. todo:: Test
        """
        return self.flags & BipFuncFlags.FUNC_LIB != 0

    @property
    def is_static(self):
        """
            Check flags of this function for knowing if this is a static
            function.

            .. todo:: Test
        """
        return self.flags & BipFuncFlags.FUNC_STATICDEF != 0

    @property
    def use_frame(self):
        """
            Check flags of this function for knowing if it is using the frame
            pointer.

            .. todo:: Test
        """
        return self.flags & BipFuncFlags.FUNC_FRAME != 0

    @property
    def is_userfar(self):
        """
            Check flags of this function for knowing if the user as define
            the function as change the marking of the function being far or
            not.

            .. todo:: Test
        """
        return self.flags & BipFuncFlags.FUNC_USERFAR != 0

    @property
    def is_hidden(self):
        """
            Check flags of this function for knowing if its a hidden function.

            .. todo:: Test
        """
        return self.flags & BipFuncFlags.FUNC_HIDDEN != 0

    @property
    def is_thunk(self):
        """
            Check flags of this function for knowing if its a thunk function.

            .. todo:: Test
        """
        return self.flags & BipFuncFlags.FUNC_THUNK != 0


    ############################ COMMENT ##############################

    @property
    def comment(self):
        """
            Property which allow access to the comment.

            .. todo:: Test
        """
        return idc.get_func_cmt(self.ea, False)

    @comment.setter
    def comment(self, value):
        """
            Setter which allow to modify the comment.

            .. todo:: Test
        """
        return idc.set_func_cmt(self.ea, value, False)

    @property
    def rcomment(self):
        """
            Property which allow access to the repeatable comment.

            .. todo:: Test
        """
        return idc.get_func_cmt(self.ea, True)

    @rcomment.setter
    def rcomment(self, value):
        """
            Setter which allow to modify the repeatable comment.

            .. todo:: Test
        """
        return idc.set_func_cmt(self.ea, value, True)

    ######################## FLOWCHART & BASICBLOCK #########################

    @property
    def _flowchart(self):
        """
            Return a ``FlowChart`` object as defined by IDA in ``ida_gdl.py``.
            This is used for getting the basic block and should not be used
            directly.

            .. note::
            
                Internally this is compute with the flags
                ``BipFlowChartFlag.FC_PREDS`` and
                ``BipFlowChartFlag.FC_NOEXT`` .

            :return: An ``idaapi.FlowChart`` object.
        """
        return idaapi.FlowChart(self._funct,
                flags=(BipFlowChartFlag.FC_PREDS|BipFlowChartFlag.FC_NOEXT))

    @property
    def nb_blocks(self):
        """
            Return the number of blocks present in this function.
        """
        return self._flowchart.size

    @property
    def blocks(self):
        """
            Return a list of :class:`BipBlock` corresponding to the
            BasicBlocks in this function.

            :return: A list of object :class:`BipBlock`
        """
        fc = self._flowchart
        return [block.BipBlock(b) for b in fc]

    
    @property
    def blocks_iter(self):
        """
            Return a generator of :class:`BipBlock` corresponding to the
            BasicBlocks in this function. This implementation will be just
            a little more performant than the :meth:`blocks` property.

            :return: A generator of object :class:`BipBlock`
        """
        fc = self._flowchart
        for b in fc:
            yield block.BipBlock(b) 

    ############################# INSTR & ITEMS ############################

    @property
    def items(self):
        """
            Return a list of :class:`BipElt` corresponding to the items of 
            the functions.

            .. todo:: Test

            .. note::
                
                This should mainly be :class:`Instr` but possible in theory
                to be other kind of data ?

            :return: A list of object :class:`BipElt`.
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
        return [ida_bytes.get_wide_byte(i) for i in range(self.ea, self.end)]


    ############################ TYPE, ARGS, .... #########################

    @property
    def _ida_tinfo(self):
        """
            Internal property which allow to get the ``tinfo_t`` swig proxy
            from IDA associated with this function. Internally this use the
            ``idaapi.get_type`` method with the third argument
            (``type_source_t``) as ``idaapi.GUESSED_FUNC`` .

            This property can raise a :class:`BipError` in case it was not
            possible to determine (guess ?) the type, meaning the
            ``idaapi.get_type`` returned false. It should be possible to try
            with a less agressive type source, but except problem with this
            way it is probably better to be more restrective than less.

            .. note:: When a function is decompiled using hexrays IDA will
                have a usually way better guess on the type of the function so
                it may be a good idea to decompile the function before getting
                the type.

            .. todo:: add test on this

            :return: The ``ida_typeinf.tinfo_t`` object (swig proxy) provided
                by IDA for this function.
        """
        tif = ida_typeinf.tinfo_t()
        if not idaapi.get_type(self.ea, tif, idaapi.GUESSED_FUNC):
            raise BipError("Unable to get the type for the function {}".format(str(self)))
        return tif

    @property
    def str_type(self):
        """
            Property which return the type (prototype) of the function.

            .. todo:: Test


            .. todo::

                Merge with guesstype if no type set ?
                This could create problems...

            :return str: String representing the type of the function.
        """
        return idc.get_type(self.ea)

    @str_type.setter
    def str_type(self, value):
        """
            Setter which allow to change the type (prototype) of the function.

            .. todo:: Test

        """
        idc.SetType(self.ea, value)

    @property
    def guess_strtype(self):
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

            :return: A list of :class:`BipXref` with the ``dst`` being this
                element.
        """
        return [xref.BipXref(x) for x in idautils.XrefsTo(self.ea)]

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

            :return: A list of :class:`BipBaseElt` (or subclasses
                of :class:`BipBaseElt`).
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

            :return: A list of :class:`BipFunction` which call this function.
        """
        return list(set([BipFunction(ea) for ea in [x.src_ea for x in self.xTo if x.is_call]]))

    @property
    def callees(self):
        """
            Property which return a list of the functions which are called by
            this one.
            
            Internally this function will iterate on all instruction for
            getting the call xref. This can be quite time consuming.

            .. todo:: Test

            :return: A list of :class:`BipFunction` which are called by this
                function.
        """
        l = []
        for i in self.instr_iter:
            for x in i.xFrom:
                if x.is_call:
                    l.append(BipFunction(x.dst_ea))
        return l

    

    ########################## CLASS METHOD ############################


    @classmethod
    def ByOrdinal(cls, ordinal):
        """
            Get an :class:`BipFunction` from its ordinal, there is between
            ``0`` and ``BipFunction.Count()`` function in an IDB.

            .. todo:: Test
        """
        return cls(ida_funcs.getn_func(ordinal).start_ea)

    @classmethod
    def iter_all(cls):
        """
            Class method allowing to iter on all the functions define in
            the IDB.

            .. todo:: Test

            :return: A generator of :class:`BipFunction` allowing to iter on
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
            :return: A new :class:`BipFunction` object corresponding to the
                function create. If this function was not able to create the
                new function a ``BipError`` will be raised.
        """
        if end is None:
            end = 0xffffffffffffffff # default IDA value meaning auto analysis
        if not idc.add_func(start, end):
            raise BipError("Unable to create function at 0x{:X}".format(start))
        return cls(start)

    ########################## STATIC METHOD ############################

    @staticmethod
    def Count():
        """
            Return the number of functions which are present in the idb.
        """
        return ida_funcs.get_func_qty()

    @staticmethod
    def Entries():
        """
            Get the functions which are entry points of the binary.

            .. todo:: make unit test

            :return: A list of :class:`BipFunction` which are entry points
                of the binary currently analyzed.
        """
        return [BipFunction(elt[2]) for elt in idautils.Entries()]

    @staticmethod
    def Entries_iter():
        """
            Get an generator on the functions which are entry points of the
            binary. This should be faster than :meth:`~BipFunction.Entries` .

            .. todo:: make unit test

            :return: A generator on :class:`BipFunction` which are entry
                points of the binary currently analyzed.
        """
        for elt in idautils.Entries():
            yield BipFunction(elt[2]) 
    


