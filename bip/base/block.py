import ida_gdl
import idc
import idautils
import ida_bytes
import ida_kernwin
import ida_graph

import bipelt
import func
import instr

class BipBlockType(object):
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

class BipBlock(object):
    """
        Class for representing and manipulating basic blocks in IDA.

        .. warning::
        
            This class is an abstraction on top of IDA BadicBlock. In
            particular IDA does **not** create basic block if not in a defined
            function. Change to the flowgraph can be not directly repercuted
            on this object.

        .. todo:: equality and inclusion operator
        .. todo:: more functions for testing type (abstraction on .type
            property), property function starting with ``is_``
    """

    ################################# BASE #################################

    def __init__(self, val=None):
        """
            Constructor for an :class:`BipBlock` object.

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
            fc = func.BipFunction(val)._flowchart
            for i in range(fc.size):
                if val >= fc[i].start_ea and val < fc[i].end_ea: # we found it
                    self._bb = fc[i]
                    break

        if self._bb is None:
            raise TypeError("BipBlock expect a ida_gdl.BasicBlock or the address of an instruction inside a function in input.")


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

    def __str__(self):
        return "BipBlock: 0x{:X} (from {})".format(self.ea, self.func)

    @property
    def _id(self):
        """
            Property returning the ID of the basic block. This is use in
            particular for manipulating the block using the graph functions.

            :return int: The ID of this basic block.
        """
        return self._bb.id

    ############################ TYPE & INFO #############################

    @property
    def type(self):
        """
            Property which allow access to the type of basic block.

            :return: One of the :class:`BipBlockType` enum.
        """
        return self._bb.type

    @property
    def is_ret(self):
        """
            Property which return True if the block can return.

            Internally this test the type for ``BipBlockType.FCB_RET`` and
            ``BipBlockType.FCB_CNDRET``. It is the equivalent of
            ``ida_gdl.is_ret_block`` in the standard idapython.

            :return: True if the block return, False otherwise.
        """
        return (self.type == BipBlockType.FCB_RET or 
                self.type == BipBlockType.FCB_CNDRET)

    @property
    def is_noret(self):
        """
            Property for testing if the block never return. For example this
            will be True if the block terminate by a call to a function which
            will never return (``abort``, ...)

            Internally this test the type for ``BipBlockType.FCB_NORET``
            and ``BipBlockType.FCB_ENORET``. It is the equivalent of
            ``ida_gdl.is_noret_block`` in the standard idapython.

            :return: True if the block never return, False otherwise.
        """
        return (self.type == BipBlockType.FCB_NORET or 
                self.type == BipBlockType.FCB_ENORET)

    @property
    def is_external(self):
        """
            Property for testing if the block is external to the function from
            which it came.

            Internally this test the type for ``FCB_ENORET`` and
            ``FCB_EXTERN`` .
            
            .. note::
                
                This should never be True if this :class:`BipBlock` was
                provided by a :class:`BipFunction`, it can be True if the
                block provided at the initialization was recuperated from an
                other source.

            :return: True if the block is not included in the function from
                which the flowgraph was created, False otherwise.
        """
        return (self.type == BipBlockType.FCB_EXTERN or 
                self.type == BipBlockType.FCB_ENORET)

    ########################### Control Flow ###########################

    @property
    def succ(self):
        """
            Return a list of :class:`BipBlock` which are successor of this
            block. This follow the potential execution pass.

            :return: A list of :class:`BipBlock` successor of this block.
        """
        return [BipBlock(bb) for bb in self._bb.succs()]

    @property
    def succ_iter(self):
        """
            Return a generator of the :class:`BipBlock` following this one.
            This is equivalent to :meth:`succ` and will probably be a little
            faster.

            :return: A generator of :class:`BipBlock` successor of this block.
        """
        for b in self._bb.succs():
            yield BipBlock(b)

    @property
    def pred(self):
        """
            Return a list of :class:`BipBlock` which are predecessor of this
            block. This provide the basicblock which can lead to this block
            followin the execution pass.

            :return: A list of :class:`BipBlock` predecessor of this block.
        """
        return [BipBlock(bb) for bb in self._bb.preds()]

    @property
    def pred_iter(self):
        """
            Return a generator of the :class:`BipBlock` predecessor of this
            one. This is equivalent to :meth:`pred` and will probably be a
            little faster.

            :return: A generator of :class:`BipBlock` predecessor of this
                block.
        """
        for b in self._bb.preds():
            yield BipBlock(b)

    ############################### FUNCTION ###############################

    @property
    def func(self):
        """
            Return the :class:`BipFunction` object corresponding to this
            block.

            .. note::

                Internally this will return the :class:`BipFunction` which is
                present at the start address of the block. In particular in
                case of external blocks this will return the function in which
                the block are included and not the one from which they came
                from.

            :return: The :class:`BipFunction` in which this block is included.
        """
        return func.BipFunction(self.ea)


    ############################# INSTR & ITEMS ############################

    @property
    def items(self):
        """
            Return a list of :class:`BipElt` corresponding to the items
            included in the basic block (between ``ea`` and ``end``).

            :return: A list of object :class:`BipElt`.
        """
        return [bipelt.GetElt(h) for h in idautils.Heads(self.ea, self.end)]

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
        return [ida_bytes.get_wide_byte(i) for i in range(self.ea, self.end)]

    ########################### COLOR #####################################

    @property
    def color(self):
        """
            Property for accessing the color of this basic block.

            :raise RuntimeError: If this function was not able to get the
                information about the graph node.
            :return int: The integer representing the color of this block in
                the BGR format.
        """
        ni = ida_graph.node_info_t()
        if not ida_graph.get_node_info(ni, self.func.ea, self._id):
            # In that case information about the node has not been
            #   recuperated, in practice this seems to mean that no
            #   node_info_t have, been defined for this node including the
            #   color, which means it should have the default color
            #   corresponding to the one set by default when creating a
            #   node_info_t. So we just ignore.
            pass
        return ni.bg_color

    @color.setter
    def color(self, value):
        """
            Property setter for changing the color of this basic block.

            .. warning:: This will **not** set correctly the color for a block
                which color has already been change using the GUI. Probably a
                bug in IDA or another item on top of it ?

            :param value: An integer representing the color to set at the BGR
                format. If value is ``None`` delete the color.
        """
        if value is None:
            ida_graph.clr_node_info(self.func.ea, self._id, ida_graph.NIF_BG_COLOR)
            ida_kernwin.refresh_idaview_anyway()
            return
        ni = ida_graph.node_info_t()
        ni.bg_color = value
        ida_graph.set_node_info(self.func.ea, self._id, ni, ida_graph.NIF_BG_COLOR)
        ida_kernwin.refresh_idaview_anyway()

    @color.deleter
    def color(self):
        """
            Property deleter for removing the color of this basicblock.

            .. warning:: This will **not** clear the color set by the GUI.
                Probably a bug in IDA. However this will clear the color set
                using the setter of this property.
        """
        ida_graph.clr_node_info(self.func.ea, self._id, ida_graph.NIF_BG_COLOR)
        ida_kernwin.refresh_idaview_anyway()



