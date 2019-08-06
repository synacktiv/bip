import ida_gdl
import idc
import idautils
import ida_bytes
import ida_kernwin

import idaelt
import func
import instr

class IdaBlockType(object):
    """
        Enum for the type of basic block. This come from the
        ``fc_block_type_t`` enum (``gdl.hpp``) not exposed to the python API.
    """
    FCB_NORMAL  = 0     #: normal block
    FCB_INDJUMP = 1     #: block ends with indirect jump
    FCB_RET     = 2     #: return block
    FCB_CNDRET  = 3     #: conditional return block
    FCB_NORET   = 4     #: noreturn block
    FCB_ENORET  = 5     #: external noreturn block (does not belong to the function)
    FCB_EXTERN  = 6     #: external normal block
    FCB_ERROR   = 7     #: block passes execution past the function end

class IdaBlock(object):
    """
        Class for representing and manipulating basic blocks in IDA.

        .. warning::
        
            This class is an abstraction on top of IDA BadicBlock. In
            particular IDA does **not** create basic block if not in a defined
            function. Change to the flowgraph can be not directly repercuted
            on this object.

        .. todo:: test (nothing as been tested)
        .. todo:: color
        .. todo:: pretty printer (__str__ func)
        .. todo:: equality and inclusion operator
        .. todo:: more functions for testing type (abstraction on .type
            property), property function starting with ``is_``
    """

    ################################# BASE #################################

    def __init__(self, val):
        """
            Constructor for an :class:`IdaBlock` object.

            This function may raise a ``TypeError`` if the argument is not
            of a type supported or a ``ValueError`` if the address pass in
            parameter is not inside a function.

            :param val: A value used for creating a basic block. This can be
                an address (int or long) or a ``ida_gdl.BasicBlock`` object.
                If ``None`` the screen address is used.
        """
        if val is None:
            val = ida_kernwin.get_screen_ea()
        #: Internal ida_gdl.BasicBlock object representing this block in IDA
        self._bb = None
        if isinstance(val, ida_gdl.BasicBlock):
            # in this case no problem just put it in the internal value
            self._bb = val
        elif isinstance(val, (int, long)):
            # if val is an int we consider it to be an address
            # for getting the basic block we need to get the flowchart for the
            # function
            # this may raise a ValueError if val is not a function
            fc = func.IdaFunction(val)._flowchart
            for i in range(fc.size):
                if val >= fc[i].start_ea and val < fc[i].end_ea: # we found it
                    self._bb = fc[i]
                    break

        if self._bb is None:
            raise TypeError("IdaBlock expect a ida_gdl.BasicBlock or the address of an instruction inside a function in input.")


    @property
    def ea(self):
        """
            Property which return the start address of the function.

            :return int: The address of the basicblock.
        """
        return self._bb.start_ea

    @property
    def end(self):
        """
            Property which return the end address of the function. This
            address is not included in the basicblock.

            :return int: The first address at the end of the basicblock.
        """
        return self._bb.end_ea


    ############################ TYPE & INFO #############################

    @property
    def type(self):
        """
            Property which allow access to the type of basic block.

            :return: One of the :class:`IdaBlockType` enum.
        """
        return self._bb.type

    @property
    def is_ret(self):
        """
            Property which return True if the block can return.

            Internally this test the type for ``IdaBlockType.FCB_RET`` and
            ``IdaBlockType.FCB_CNDRET``. It is the equivalent of
            ``ida_gdl.is_ret_block`` in the standard idapython.

            :return: True if the block return, False otherwise.
        """
        return (self.type == IdaBlockType.FCB_RET or 
                self.type == IdaBlockType.FCB_CNDRET)

    @property
    def is_noret(self):
        """
            Property for testing if the block never return. For example this
            will be True if the block terminate by a call to a function which
            will never return (``abort``, ...)

            Internally this test the type for ``IdaBlockType.FCB_NORET``
            and ``IdaBlockType.FCB_ENORET``. It is the equivalent of
            ``ida_gdl.is_noret_block`` in the standard idapython.

            :return: True if the block never return, False otherwise.
        """
        return (self.type == IdaBlockType.FCB_NORET or 
                self.type == IdaBlockType.FCB_ENORET)

    @property
    def is_external(self):
        """
            Property for testing if the block is external to the function from
            which it came.

            Internally this test the type for ``FCB_ENORET`` and
            ``FCB_EXTERN`` .
            
            .. note::
                
                This should never be True if this :class:`IdaBlock` was
                provided by a :class:`IdaFunction`, it can be True if the
                block provided at the initialization was recuperated from an
                other source.

            :return: True if the block is not included in the function from
                which the flowgraph was created, False otherwise.
        """
        return (self.type == IdaBlockType.FCB_EXTERN or 
                self.type == IdaBlockType.FCB_ENORET)

    ########################### Control Flow ###########################

    @property
    def succ(self):
        """
            Return a list of :class:`IdaBlock` which are successor of this
            block. This follow the potential execution pass.

            :return: A list of :class:`IdaBlock` successor of this block.
        """
        return [IdaBlock(bb) for bb in self._bb.succs()]

    @property
    def iter_succ(self):
        """
            Return a generator of the :class:`IdaBlock` following this one.
            This is equivalent to :meth:`succ` and will probably be a little
            faster.

            :return: A generator of :class:`IdaBlock` successor of this block.
        """
        for b in self._bb.succs():
            yield IdaBlock(b)

    @property
    def pred(self):
        """
            Return a list of :class:`IdaBlock` which are predecessor of this
            block. This provide the basicblock which can lead to this block
            followin the execution pass.

            :return: A list of :class:`IdaBlock` predecessor of this block.
        """
        return [IdaBlock(bb) for bb in self._bb.preds()]

    @property
    def iter_pred(self):
        """
            Return a generator of the :class:`IdaBlock` predecessor of this
            one. This is equivalent to :meth:`pred` and will probably be a
            little faster.

            :return: A generator of :class:`IdaBlock` predecessor of this
                block.
        """
        for b in self._bb.preds():
            yield IdaBlock(b)

    ############################### FUNCTION ###############################

    @property
    def func(self):
        """
            Return the :class:`IdaFunction` object corresponding to this
            block.

            .. note::

                Internally this will return the :class:`IdaFunction` which is
                present at the start address of the block. In particular in
                case of external blocks this will return the function in which
                the block are included and not the one from which they came
                from.

            :return: The :class:`IdaFunction` in which this block is included.
        """
        return func.IdaFunction(self.ea)


    ############################# INSTR & ITEMS ############################

    @property
    def items(self):
        """
            Return a list of :class:`IdaElt` corresponding to the items
            included in the basic block (between ``ea`` and ``end``).

            :return: A list of object :class:`IdaElt`.
        """
        return [idaelt.GetElt(h) for h in idautils.Heads(self.ea, self.end)]

    @property
    def instr(self):
        """
            Return a list of :class:`Instr` corresponding to the instructions
            of the basicblock.

            :return: A list of object :class:`Instr` .
        """
        return [instr.Instr(h) for h in idautils.Heads(self.ea, self.end) if idc.is_code(ida_bytes.get_full_flags(h))]

    @property
    def instr_iter(self):
        """
            Return a generator of :class:`Instr` corresponding to the
            instructions of the basicblock. This implementation will be just
            a little more performant than the :meth:`instr` property.

            :return: A generator of object :class:`Instr` .
        """
        for h in idautils.Heads(self.ea, self.end):
            if idc.is_code(ida_bytes.get_full_flags(h)):
                yield instr.Instr(h)

    @property
    def bytes(self):
        """
            Property returning the value of the bytes contain in the
            basicblock.

            :return: A list of the bytes forming the element.
            :rtype: list(int)
        """
        return [idc.Byte(i) for i in range(self.ea, self.end)]

