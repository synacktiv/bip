import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_gdl
import ida_bytes
import ida_typeinf
import ida_kernwin

import re

from bipelt import BipElt, GetElt
import instr
import block
import xref
from biperror import BipError

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
    FUNC_STATICDEF      = idaapi.FUNC_STATICDEF     # static function
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

        .. todo:: frame ?

        .. todo:: setter for start ea (:meth:`BipFunction.ea`) and end ea
            (:meth:`BipFunction.end`)
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

    @property
    def end(self):
        """
            Property which return the address at the end of the function.
            This address is not included in the function.

            :return int: The stop address of the function. This address is 
                not included in the function.
        """
        return self._funct.end_ea

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

            This function does not handle mangling,
            see :meth:`~BipFunction.demangle_name`.

            :return str: The name of the function.
        """
        return idc.get_name(self.ea, ida_name.GN_VISIBLE)

    @name.setter
    def name(self, value):
        """
            Setter for changing the name of the function.

            :param str value: The new name of the function, if an empty string
                or ``None`` is provided it will revert to the default name
                provided by IDA (``sub_...``).
        """
        if value is None:
            value = ""
        idc.set_name(self.ea, value, idc.SN_CHECK)

    @property
    def demangle_name(self):
        """
            Property which return the demangle name of the function.

            :return str: The demangle name of the function.
        """
        return idc.demangle_name(self.name, idc.get_inf_attr(idc.INF_SHORT_DN))

    @property
    def is_dummy_name(self):
        """
            Property for checking if the current name of this function is a
            "dummy" name (a name set by default by IDA when it does not know
            how to call an element) with a special prefix. This function will
            not recognize the ``aSTRING`` naming,
            see :meth:`~BipFunction.is_auto_name`, and :meth:`~BipFunction.is_ida_name`.
            
            :return: ``True`` if the function has a dummy name, ``False``
                otherwise.
        """
        return ida_bytes.has_dummy_name(ida_bytes.get_full_flags(self.ea))

    @property
    def is_auto_name(self):
        """
            Property for checking if the current name of this function is an
            "auto-generated" name, those are the default name generated by
            IDA but without a special prefix
            (see :meth:`~BipFunction.is_dummy_name`) such as the one for the
            string. See also :meth:`~BipFunction.is_ida_name`.

            :return: ``True`` if the function has an auto-generated name,
                ``False`` otherwise.
        """
        return ida_bytes.has_auto_name(ida_bytes.get_full_flags(self.ea))

    @property
    def is_ida_name(self):
        """
            Property for checking if the current name is a default name as
            generated by IDA. This is an OR condition of
            :meth:`~BipFunction.is_auto_name` and :meth:`~BipFunction.is_dummy_name`.
            
            :return: ``True`` if the function has a name provided by IDA,
                ``False`` otherwise.
        """
        return self.is_auto_name or self.is_dummy_name

    @property
    def is_user_name(self):
        """
            Property for checking if the current name is a "user name". In
            practice this check a flag that the API can avoid setting, so
            there is no garantee it is an actual user name.
            See :meth:`~BipFunction.is_ida_name` for checking if a name was
            generated by IDA.

            :return: ``True`` if the name is marked as set by a user,
                ``False`` otherwise.
        """
        return ida_bytes.has_user_name(ida_bytes.get_full_flags(self.ea))

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
            position.

            Return ``NotImplemented`` if the argument is not a :class:`BipFunction` .
        """
        if not isinstance(other, BipFunction):
            return NotImplemented
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

            If if it not possible to import the hexrays API an NotImplementedError
            error will be raised.

            This may raise a :class:`~bip.base.BipDecompileError` if the
            decompilation failed.

            :return: A :class:`HxCFunc` object equivalent to this function.
        """
        global hexrays
        if hexrays is None:
            try:
                import bip.hexrays as hexrays
            except ImportError:
                hexrays = None
            if hexrays is None:
                raise NotImplementedError("It appears the hexrays API is not available")
        return hexrays.HxCFunc.from_addr(self.ea)

    @property
    def can_decompile(self):
        """
            Property which test if it is possible to get the hexrays
            C function (:class:`HxCFunc`) for this function.

            Internally this will just try to call :meth:`BipFunction.hxfunc`
            and catch the error, this means calling this function will
            actually perform the decompilation.

            :return: True if its possible to get the :class:`HxCFunc` object
                for this :class:`BipFunction`, False otherwise.
        """
        try:
            self.hxfunc
        except Exception:
            return False
        return True

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
        idc.set_func_attr(self.ea, BipFuncFlags.FUNCATTR_FLAGS, value)

    def is_inside(self, o):
        """
            Allow to check if an address or an :class:`BipElt` object (or
            inherited) is included in this function. In particular it
            allow to check if an :class:`Instr` is included in a function.

            This function is based on the ``func_t.contains`` function of
            IDA, this function seems to check only the address compare to the
            start and end address of a function and will return False for
            function chunk.

            :param o: The address or object to test for inclusion.
            :type o: ``int`` coresponding to an address or an object inherited
                from :class:`BipElt` .
            :raise TypeError: if the parameter ``o`` is not from a valid type.
        """
        if isinstance(o, (long, int)):
            return self._funct.contains(o)
        elif isinstance(o, BipElt):
            return self._funct.contains(o.ea)
        else:
            raise TypeError("Object {} is not of a valid type".format(o))

    @property
    def does_return(self):
        """
            Property which indicate if the function is expected to return.

            :return boolean: True if the function is expected to return.
        """
        #return self._funct.does_return()
        return self.flags & BipFuncFlags.FUNC_NORET == 0

    @does_return.setter
    def does_return(self, value):
        """
            Setter for the function flag indicating if this function returns.
            No change are performed if it is already at the correct value.
            This will failed silently if an error occur.
        """
        if value == self.does_return: # already correctly set
            return
        # do not use bitfield op. for setting flags because we don't actually
        #   now its size (and it seems to change if 32 or 64bits)
        if value:
            self.flags = self.flags - BipFuncFlags.FUNC_NORET
        else:
            self.flags = self.flags + BipFuncFlags.FUNC_NORET

    @property
    def is_far(self):
        """
            Check flags of this function for knowing if this is a far
            function.
        """
        return self.flags & BipFuncFlags.FUNC_FAR != 0

    @is_far.setter
    def is_far(self, value):
        """
            Setter for is_far flag. No change are performed if it is already
            at the correct value. This will failed silently if an error occur.

            :param bool value: if ``True`` the flag will be set, otherwise it
                will be removed.
        """
        if value == self.is_far: # already correctly set
            return
        # do not use bitfield op. for setting flags because we don't actually
        #   now its size (and it seems to change if 32 or 64bits)
        if value:
            self.flags = self.flags + BipFuncFlags.FUNC_FAR
        else:
            self.flags = self.flags - BipFuncFlags.FUNC_FAR

    @property
    def is_lib(self):
        """
            Check flags of this function for knowing if this is a library
            function.
        """
        return self.flags & BipFuncFlags.FUNC_LIB != 0

    @is_lib.setter
    def is_lib(self, value):
        """
            Setter for is_lib flag. No change are performed if it is already
            at the correct value. This will failed silently if an error occur.

            :param bool value: if ``True`` the flag will be set, otherwise it
                will be removed.
        """
        if value == self.is_lib: # already correctly set
            return
        # do not use bitfield op. for setting flags because we don't actually
        #   now its size (and it seems to change if 32 or 64bits)
        if value:
            self.flags = self.flags + BipFuncFlags.FUNC_LIB
        else:
            self.flags = self.flags - BipFuncFlags.FUNC_LIB

    @property
    def is_static(self):
        """
            Check flags of this function for knowing if this is a static
            function.
        """
        return self.flags & BipFuncFlags.FUNC_STATICDEF != 0

    @is_static.setter
    def is_static(self, value):
        """
            Setter for is_static flag. No change are performed if it is already
            at the correct value. This will failed silently if an error occur.

            :param bool value: if ``True`` the flag will be set, otherwise it
                will be removed.
        """
        if value == self.is_static: # already correctly set
            return
        # do not use bitfield op. for setting flags because we don't actually
        #   now its size (and it seems to change if 32 or 64bits)
        if value:
            self.flags = self.flags + BipFuncFlags.FUNC_STATICDEF
        else:
            self.flags = self.flags - BipFuncFlags.FUNC_STATICDEF

    @property
    def use_frame(self):
        """
            Check flags of this function for knowing if it is using the frame
            pointer.
        """
        return self.flags & BipFuncFlags.FUNC_FRAME != 0

    @use_frame.setter
    def use_frame(self, value):
        """
            Setter for use_frame flag. No change are performed if it is already
            at the correct value. This will failed silently if an error occur.

            :param bool value: if ``True`` the flag will be set, otherwise it
                will be removed.
        """
        if value == self.use_frame: # already correctly set
            return
        # do not use bitfield op. for setting flags because we don't actually
        #   now its size (and it seems to change if 32 or 64bits)
        if value:
            self.flags = self.flags + BipFuncFlags.FUNC_FRAME
        else:
            self.flags = self.flags - BipFuncFlags.FUNC_FRAME

    @property
    def is_userfar(self):
        """
            Check flags of this function for knowing if the user as define
            the function as change the marking of the function being far or
            not.
        """
        return self.flags & BipFuncFlags.FUNC_USERFAR != 0

    @is_userfar.setter
    def is_userfar(self, value):
        """
            Setter for is_userfar flag. No change are performed if it is
            already at the correct value. This will failed silently if an
            error occur.

            :param bool value: if ``True`` the flag will be set, otherwise it
                will be removed.
        """
        if value == self.is_userfar: # already correctly set
            return
        # do not use bitfield op. for setting flags because we don't actually
        #   now its size (and it seems to change if 32 or 64bits)
        if value:
            self.flags = self.flags + BipFuncFlags.FUNC_USERFAR
        else:
            self.flags = self.flags - BipFuncFlags.FUNC_USERFAR

    @property
    def is_hidden(self):
        """
            Check flags of this function for knowing if its a hidden function.
        """
        return self.flags & BipFuncFlags.FUNC_HIDDEN != 0

    @is_hidden.setter
    def is_hidden(self, value):
        """
            Setter for is_hidden flag. No change are performed if it is
            already at the correct value. This will failed silently if an
            error occur.

            :param bool value: if ``True`` the flag will be set, otherwise it
                will be removed.
        """
        if value == self.is_hidden: # already correctly set
            return
        # do not use bitfield op. for setting flags because we don't actually
        #   now its size (and it seems to change if 32 or 64bits)
        if value:
            self.flags = self.flags + BipFuncFlags.FUNC_HIDDEN
        else:
            self.flags = self.flags - BipFuncFlags.FUNC_HIDDEN

    @property
    def is_thunk(self):
        """
            Check flags of this function for knowing if its a thunk function.
        """
        return self.flags & BipFuncFlags.FUNC_THUNK != 0

    @is_thunk.setter
    def is_thunk(self, value):
        """
            Setter for is_thunk flag. No change are performed if it is
            already at the correct value. This will failed silently if an
            error occur.

            :param bool value: if ``True`` the flag will be set, otherwise it
                will be removed.
        """
        if value == self.is_thunk: # already correctly set
            return
        # do not use bitfield op. for setting flags because we don't actually
        #   now its size (and it seems to change if 32 or 64bits)
        if value:
            self.flags = self.flags + BipFuncFlags.FUNC_THUNK
        else:
            self.flags = self.flags - BipFuncFlags.FUNC_THUNK

    ############################ COMMENT ##############################

    @property
    def comment(self):
        """
            Property which allow access to the comment.
        """
        return idc.get_func_cmt(self.ea, False)

    @comment.setter
    def comment(self, value):
        """
            Setter which allow to modify the comment.
        """
        if value is None:
            value = ""
        return idc.set_func_cmt(self.ea, value, False)

    @property
    def rcomment(self):
        """
            Property which allow access to the repeatable comment.
        """
        return idc.get_func_cmt(self.ea, True)

    @rcomment.setter
    def rcomment(self, value):
        """
            Setter which allow to modify the repeatable comment.
        """
        if value is None:
            value = ""
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

            .. note::
                
                This should mainly be :class:`Instr` but possible in theory
                to be other kind of data.

            :return: A list of object :class:`BipElt`.
        """
        return [GetElt(e) for e in idautils.FuncItems(self.ea)]

    @property
    def instr(self):
        """
            Return a list of :class:`Instr` corresponding to the instructions
            of the functions.

            :return: A list of object :class:`Instr`
        """
        return [instr.Instr(h) for h in idautils.Heads(self.ea, self.end) if idc.is_code(ida_bytes.get_full_flags(h))]

    @property
    def instr_iter(self):
        """
            Return a generator of :class:`Instr` corresponding to the
            instructions of the functions. This implementation will be just
            a little more performant than the :meth:`instr` property.

            :return: A generator of object :class:`Instr`
        """
        for h in idautils.Heads(self.ea, self.end):
            if idc.is_code(ida_bytes.get_full_flags(h)):
                yield instr.Instr(h)

    @property
    def bytes(self):
        """
            Property returning the value of the bytes contain in the function.

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
            this function, see :meth:`~BipFunction.jcallers` property for
            also getting the jmp and ordinary flow.

            .. todo:: Test

            :return: A list of :class:`BipFunction` which call this function.
        """
        s = set()
        for x in self.xTo:
            if not x.is_call:
                continue
            ea = x.src_ea
            try:
                f = BipFunction(ea)
            except ValueError:
                continue
            s.add(f)
        return list(s)

    @property
    def jcallers(self):
        """
            Property which return a list of all the functions which call,
            jump or have an ordinary flow to this function.

            .. todo:: Test

            :return: A list of :class:`BipFunction` which call this function.
        """
        s = set()
        for x in self.xTo:
            if not x.is_codepath:
                continue
            ea = x.src_ea
            try:
                f = BipFunction(ea)
            except ValueError:
                continue
            s.add(f)
        return list(s)

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
                    try:
                        f = BipFunction(x.dst_ea)
                    except ValueError:
                        continue
                    l.append(f)
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
    def Entries(cls):
        """
            Get the functions which are entry points of the binary.

            :return: A list of :class:`BipFunction` which are entry points
                of the binary currently analyzed.
        """
        return [elt for elt in cls.Entries_iter()]

    @classmethod
    def Entries_iter(cls):
        """
            Get an generator on the functions which are entry points of the
            binary. This should be faster than :meth:`~BipFunction.Entries` .

            :return: A generator on :class:`BipFunction` which are entry
                points of the binary currently analyzed.
        """
        for elt in idautils.Entries():
            try:
                yield cls(elt[2]) 
            except ValueError: # case where we are not in a function, but data
                continue # we just ignore that case

    @classmethod
    def get_by_name(cls, name):
        """
            Class method allowing to get a function from its name.

            :return: A :class:`BipFunction` with the correct name or None
                if the function was not found.
        """
        ea = ida_name.get_name_ea(idc.BADADDR, name)
        if ea is None or ea == idc.BADADDR:
            return None
        try:
            return cls(ea)
        except ValueError:
            return None
        return None

    @classmethod
    def get_by_prefix(cls, prefix):
        """
            Class method allowing to get all the functions which are named
            with a particular prefix.

            Internally this iterate on all functions.

            :param str prefix: The prefix for which to get the function.
            :return: A list of :class:`BipFunction` where their names start
                with the prefix.
        """
        return [f for f in cls.iter_all() if f.name.startswith(prefix)]

    @classmethod
    def get_by_regex(cls, regex):
        """
            Class method allowing to get all functions matching a regex.

            Internally this iterate on all functions and use the ``re.match``
            function (it compiles the regex first) and return the function
            if the match did not return None.

            :param str regex: The regex used for finding the function.
            :return: A list of :class:`BipFunction` where their names match
                the regex.
        """
        rc = re.compile(regex)
        return [f for f in cls.iter_all() if rc.match(f.name) is not None]


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
    

