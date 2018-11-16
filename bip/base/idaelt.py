import idc
import idautils
import xref
from biperror import BipError

class IdaElt(object):
    """
        Base class for representing an element in IDA which have an address.
        This is the basic element on top of which access to instruction and
        data is built.

        .. todo:: make test

        .. todo:: Make an exception system

        .. todo:: Make comparaison possible between 2 objections
    """

    def __init__(self, ea):
        """
            Consctructor for an IdaElt.

            .. note:: There is no reason to use this constructor, the
                :func:`GetElt` function should be used.

            :param int ea: The address of the element in IDA.
        """
        if not isinstance(ea, (int, long)):
            raise TypeError("IdaElt.__init__ : ea should be an integer")
        self.ea = ea #: The address of the element in the IDA database

    ################### BASE ##################

    @property
    def flags(self):
        """
            Property for getting the flags of the element. Those flags are the
            one from ida such as returned by ``idc.GetFlags``.

            :return: The flags for the element
            :rtype: int
        """
        return idc.GetFlags(self.ea)

    @property
    def size(self):
        """
            Property which return the size of the elt.

            :return: The size in bytes of the element.
            :rtype: int
        """
        return idc.ItemEnd(self.ea) - self.ea


    @property
    def bytes(self):
        """
            Property returning the value of the bytes contain in the
            element.

            :return: A list of the bytes forming the element.
            :rtype: list(int)
        """
        return [idc.Byte(i) for i in range(self.ea, idc.ItemEnd(self.ea))]

    ################### NAME ##################
    # All element do not have one

    @property
    def name(self):
        """
            Property which allow to get the name of this element. An element
            do not always have a name.

            :return: The name of an element or an empty string if no name.
            :rtype: str
        """
        return idc.Name(self.ea)

    @name.setter
    def name(self, value):
        """
            Setter which allow to set the name of this element.

            This setter will fail if the element is not an head, see
            :meth:`IdaElt.is_head` for testing it. In case of failure a
            BipError will be raised

            .. todo::
            
                idc.set_name support flags so maybe make more advanced
                functions ? (see include/name.hpp) And what about mangling.

            :param str value: The name to give to this element.
        """
        if value is None:
            value = ""
        if not idc.MakeName(self.ea, value):
            raise BipError("Unable to set name")


    ################### COLOR ##################

    @property
    def color(self):
        """
            Property which return the color of the item.

            :return: The coloration of the element in IDA.
            :rtype: int
        """
        return idc.GetColor(self.ea, idc.CIC_ITEM)

    @color.setter
    def color(self, value):
        """
            Setter which allow to set the color of the current element.

            :param int value: the color to which set the item.
        """
        idc.SetColor(self.ea, idc.CIC_ITEM, value)

    ################### COMMENT ##################

    @property
    def comment(self):
        """
            Property which return the comment of the item.
            
            :return: The value of the comment or ``None`` if there is no
                comment.
            :rtype: str
        """
        return idc.GetCommentEx(self.ea, 0)

    @comment.setter
    def comment(self, value):
        """
            Setter which allow to set the value of the comment.

            :param str value: The comment to set
        """
        if value is None:
            value = ""
        idc.MakeComm(self.ea, value)

    @property
    def rcomment(self):
        """
            Property which return the repeatable comment of the item.
            
            :return: The value of the comment or ``None`` if there is no
                repeatable comment.
            :rtype: str
        """
        return idc.GetCommentEx(self.ea, 1)

    @rcomment.setter
    def rcomment(self, value):
        """
            Setter which allow to set the value of the repeatable comment.

            :param str value: The comment to set.
        """
        if value is None:
            value = ""
        idc.MakeRptCmt(self.ea, value)

    @property
    def has_comment(self):
        """
            Property which allow to check if the item as a comment (normal or
            repeatable.

            :return: True if the item as a comment, False otherwise
        """
        return ((self.comment != "" and self.comment is not None)
                or (self.rcomment != "" and self.rcomment is not None))

    ####################### FLAGS #########################

    @property
    def is_code(self):
        """
            Property indicating if this element is some code.
            Wrapper on ``idc.isCode`` .
            
            :return: True if current element is code, False otherwise.
            :rtype: bool
        """
        return idc.isCode(self.flags)

    @property
    def is_data(self):
        """
            Property indicating if this element is considered as data.
            Wrapper on ``idc.isData`` .
            
            :return: True if current element is data, False otherwise.
            :rtype: bool
        """
        return idc.isData(self.flags)

    @property
    def is_unknown(self):
        """
            Property indicating if this element is considered as unknwon.
            Wrapper on ``idc.isUnknown`` .
            
            :return: True if current element is unknwon, False otherwise.
            :rtype: bool
        """
        return idc.isUnknown(self.flags)

    @property
    def is_head(self):
        """
            Property indicating if the element is an *head* in IDA. An *head*
            element is the beggining of an element in IDA (such as the
            beginning of an instruction) and can be named.
            Wrapper on ``idc.isHead`` .

            :return: True if the current element is an head, Flase otherwise.
            :rtype: bool
        """
        return idc.isHead(self.flags)

    # no is_tail because counter intuitive as it is only a ``not is_head`` 

    
    ######################## STUFF ############################


    def goto(self):
        """
            Method which allow to move the screen to the position of this
            element. Wrapper on ``idc.Jump`` .
        """
        idc.Jump(self.ea)

    @classmethod
    def _is_this_elt(cls, ea):
        """
            Class method which allow the function :func:`GetElt` to know if
            this the correct type for an address.

            :param int ea: An address at which to get an element.
            :return: True if this is a valid class for constructing from 
        """
        return True

    ################################# XREFS ############################
    # all those functions start with a ``x``

    @property
    def xFrom(self):
        """
            Property which allow to get all xrefs generated (from) by the
            element. This is the equivalent to ``XrefsFrom`` from idapython.

            :return: A list of :class:`IdaXref` with the ``src`` being this
                element.
        """
        return [xref.IdaXref(x) for x in idautils.XrefsFrom(self.ea)]

    @property
    def xTo(self):
        """
            Property which allow to get all xrefs pointing to (to) this
            element. This is the equivalent to ``XrefsTo`` from idapython.

            :return: A list of :class:`IdaXref` with the ``dst`` being this
                element.
        """
        return [xref.IdaXref(x) for x in idautils.XrefsTo(self.ea)]

    @property
    def xEaFrom(self):
        """
            Property which allow to get all addresses referenced (by a xref) by
            (from) the element.

            :return: A list of address.
        """
        return [x.dst_ea for x in self.xFrom]

    @property
    def xEaTo(self):
        """
            Property which allow to get all addresses which referenced this
            element (xref to).

            :return: A list of address.
        """
        return [x.src_ea for x in self.xTo]

    @property
    def xEltFrom(self):
        """
            Property which allow to get all elements referenced (by a xref)
            by (from) this element.

            :return: A list of :class:`IdaElt` (or subclasses
                of :class:`IdaElt`).
        """
        return [x.dst for x in self.xFrom]

    @property
    def xEltTo(self):
        """
            Property which allow to get all elements which referenced this
            element (xref to).

            :return: A list of :class:`IdaElt` (or subclasses
                of :class:`IdaElt`).
        """
        return [x.src for x in self.xTo]

    @property
    def xCodeFrom(self):
        """
            Property which return all instructions which are referenced by the
            element. This will take into account jmp, call, ordinary flow and
            "data" references.

            :return: A list of :class:`Instr` referenced by this element.
        """
        return [x.dst for x in self.xFrom if x.dst.is_code]

    @property
    def xCodeTo(self):
        """
            Property which return all instructions which referenced this
            element. This will take into account jmp, call, ordinary flow and
            "data" references.

            :return: A list of :class:`Instr` referenced by this element.
        """
        return [x.src for x in self.xTo if x.src.is_code]


def GetElt(ea):
    """
        Return an object inherithed from :class:`IdaElt` which correspond to
        the element at an address.
        
        Internally this function parcours subclasses of :class:`IdaElt` and
        call the :meth:`~IdaElt._is_this_elt` and return the one which match.

        .. warning::
            
            There is a problem if two functions of a sublcass level can
            return True on the same element.

        :param int ea: An address at which to get an element.
        :return: An object representing the element.
        :rtype: Subclass of :class:`IdaElt`.
    """
    cls = IdaElt
    sbcls = cls.__subclasses__()
    while len(sbcls) != 0:
        cl = sbcls.pop()
        if cl._is_this_elt(ea):
            cls = cl
            sbcls = cl.__subclasses__()
    return cls(ea)

