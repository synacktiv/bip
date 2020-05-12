import idc
import ida_kernwin
import idautils
import ida_bytes
import ida_name
import ida_search

import xref
from biperror import BipError
from utils import min_ea, max_ea

class BipBaseElt(object):
    """
        Base class for representing an element in IDA which is identified by
        an id, this should be used as an abstract class and no object of this
        class should be instantiated.

        This is a really generic class which only support the constructor
        taking an id and the :meth:`BipBaseElt._is_this_elt` for used in
        conjonction with :func:`GetElt`. Child classes should reimplement the
        :meth:`BipBaseElt._is_this_elt` and call this constructor.

        .. todo:: make list of subclasses in this doc. Add to doc a descision
            tree for which classes should be return by the GetElt.
    """

    def __init__(self, idelt):
        """
            Consctructor for a :class:`BipBaseElt` object.

            .. note:: There is no reason to use this constructor, the
                :func:`GetElt` or :func:`GetEltByName` functions should be
                used.

            :param int idelt: The id for representing the IDA element. In most
                case this will be the address of the element.
        """
        if not isinstance(idelt, (int, long)):
            raise TypeError("BipBaseElt.__init__ : idelt should be an integer")
        #: The id which represent the element in IDA, this will typically
        #:  be an address.
        self._idelt = idelt


    @classmethod
    def _is_this_elt(cls, idelt):
        """
            Class method which allow the function :func:`GetElt` to know if
            this the correct type for an address. Only subclasses of an
            element which return True will be tested by :func:`GetElt`,
            :class:`BipBaseElt` return always True except if ``idelt`` is not
            of the correct type.

            :param int idelt: An id representing the element, typically an
                address.
            :return: True if this is a valid class for constructing this
                element.
        """
        if not isinstance(idelt, (int, long)):
            return False
        return True

    @classmethod
    def iter_heads(cls, start=None, end=None):
        """
            Class method allowing to iter on all the element **defined** in
            the IDB. This means elements which are not defined (considered to
            not *heads*) will not be returned by this function.

            .. note::

                Internally this function iterate on all the ``Heads`` and
                create the object if the class which is used for it match
                the element. For exemple calling ``BipData.iter_heads()`` will
                return only the heads which are :class:`BipData` object or
                their children.

            .. note:: This function will work only on mapped object, it is not
                possible to use it for getting :class:`BipStruct` for exemple.

            :param start: The address at which to start iterating. If this
                parameter is None (the default) the minimum mapped address
                will be used.
            :param end: The address at which to stop iterating. If this
                parameter is None (the default) the maximum mapped address
                will be used.
            :return: A generator of object child of :class:`BipBaseElt`
                allowing to iter on all the elt define in the idb.
        """
        if start is None:
            start = min_ea()
        if end is None:
            end = max_ea()
        for h in idautils.Heads(start, end):
            if cls._is_this_elt(h):
                yield GetElt(h)

    def __eq__(self, other):
        """
            Compare the id of 2 :class:`BipBaseElt` and return ``True`` if
            they are equal.
        """
        if not isinstance(other, BipBaseElt):
            return NotImplemented
        return self._idelt == other._idelt

    def __ne__(self, other):
        res = self.__eq__(other)
        if res == NotImplemented:
            return res
        else:
            return not res

class BipRefElt(BipBaseElt):
    """
        Class which represent element which can be reference through a xref.
        This include data, instruction and structures. The :class:`BipRefElt`
        class provide methods for accessing the references to and from the
        element represented by the object.
    """

    ################################# XREFS ############################
    # all those functions start with a ``x``

    @property
    def xFrom(self):
        """
            Property which allow to get all xrefs generated (from) by the
            element. This is the equivalent to ``XrefsFrom`` from idapython.

            :return: A list of :class:`BipXref` with the ``src`` being this
                element.
        """
        return [xref.BipXref(x) for x in idautils.XrefsFrom(self._idelt)]

    @property
    def xTo(self):
        """
            Property which allow to get all xrefs pointing to (to) this
            element. This is the equivalent to ``XrefsTo`` from idapython.

            :return: A list of :class:`BipXref` with the ``dst`` being this
                element.
        """
        return [xref.BipXref(x) for x in idautils.XrefsTo(self._idelt)]

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

            :return: A list of :class:`BipBaseElt` (or subclasses
                of :class:`BipBaseElt`).
        """
        return [x.dst for x in self.xFrom]

    @property
    def xEltTo(self):
        """
            Property which allow to get all elements which referenced this
            element (xref to).

            :return: A list of :class:`BipBaseElt` (or subclasses
                of :class:`BipBaseElt`).
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
        return [x.dst for x in self.xFrom if ('is_code' in dir(x.dst) and x.dst.is_code)]

    @property
    def xCodeTo(self):
        """
            Property which return all instructions which referenced this
            element. This will take into account jmp, call, ordinary flow and
            "data" references.

            :return: A list of :class:`Instr` referenced by this element.
        """
        return [x.src for x in self.xTo if ('is_code' in dir(x.src) and x.src.is_code)]


class BipElt(BipRefElt):
    """
        Base class for representing an element in IDA which have an address.
        This is the basic element on top of which access to instruction and
        data is built.
    """

    def __init__(self, ea=None):
        """
            Consctructor for a :class:`BipElt` object.

            .. note:: There is no reason to use this constructor, the
                :func:`GetElt` function should be used.

            :param int ea: The address of the element in IDA. If ``None`` the
                screen address is taken.
            :raise ValueError: If the address given in argument is a bad
                address (idc.BADADDR)
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        super(BipElt, self).__init__(ea)
        if ea == idc.BADADDR:
            raise ValueError("Invalid address pass as arguemnt for element")
        if not isinstance(ea, (int, long)):
            raise TypeError("BipElt.__init__ : ea should be an integer")
        self.ea = ea #: The address of the element in the IDA database

    ################## COMPARE #############################

    def __cmp__(self, other):
        """
            Compare with another BipElt. Will return 0 if the two :class:`BipElt`
            have the same address, and -1 or 1 depending on the other element
            position.

            :raise TypeError: exception if the argument is not a
                :class:`BipElt`.
        """
        if not isinstance(other, BipElt):
            return NotImplemented
        if self.ea < other.ea:
            return -1
        elif self.ea > other.ea:
            return 1
        else:
            return 0

    def __hash__(self):
        """
            Compute a unique hash for this ida element. The produce hash is
            dependant of the type of this object and of its address. This
            allow to create container using the hash
            of the object for matching an object of a defined type and with
            a particular address.

            Calculation made is: ``hash(type(self)) ^ self.ea``, in particular
            it means than child classes will not have the same hash as a
            parrent classes even if the compare works.

            :return: An integer corresponding to the hash for this object.
        """
        return hash(type(self)) ^ self.ea

    ################### BASE ##################

    @property
    def flags(self):
        """
            Property for getting the flags of the element. Those flags are the
            one from ida such as returned by ``ida_bytes.get_full_flags``.

            :return: The flags for the element
            :rtype: int
        """
        return ida_bytes.get_full_flags(self.ea)

    @property
    def size(self):
        """
            Property which return the size of the elt.

            :return: The size in bytes of the element.
            :rtype: int
        """
        return idc.get_item_end(self.ea) - self.ea


    @property
    def bytes(self):
        """
            Property returning the value of the bytes contain in the
            element.

            :return: A list of the bytes forming the element.
            :rtype: list(int)
        """
        return [ida_bytes.get_wide_byte(i) for i in range(self.ea, idc.get_item_end(self.ea))]

    @bytes.setter
    def bytes(self, value):
        """
            Setter allowing to change the bytes value of the element.

            .. warning::

                No check is made on the size of the array of the setter and
                it can rewrite more than the size of the element,

            :param value: A list of int corresponding to the bytes to change.
        """
        if isinstance(value, str):
            ida_bytes.patch_bytes(self.ea, value)
        elif isinstance(value, list):
            i = 0
            for e in value:
                ida_bytes.patch_byte(self.ea + i, e)
                i += 1
        else:
            raise TypeError("Invalid arg {} for BipElt.bytes setter".format(value))

    @property
    def original_bytes(self):
        """
            Property returning the value of the bytes contain in the
            element before their modification. This still use the size of
            the current element definition.

            :return: A list of the original bytes as integer forming the
                element.
        """
        return [ida_bytes.get_original_byte(i) for i in range(self.ea, idc.get_item_end(self.ea))]

    ################### NAME ##################
    # All element do not have one

    @property
    def name(self):
        """
            Property which allow to get the name of this element. An element
            do not always have a name.

            :return: The name of an element or an empty string if no name.
            :rtype: :class:`str`
        """
        return idc.get_name(self.ea, ida_name.GN_VISIBLE)

    @name.setter
    def name(self, value):
        """
            Setter which allow to set the name of this element.

            This setter will fail if the element is not an head, see
            :meth:`BipElt.is_head` for testing it. In case of failure a
            BipError will be raised

            .. todo::

                idc.set_name support flags so maybe make more advanced
                functions ? (see include/name.hpp)

            :param value: The name to give to this element.
            :type value: :class:`str`
        """
        if value is None:
            value = ""
        if not idc.set_name(self.ea, value, idc.SN_CHECK):
            raise BipError("Unable to set name")

    @property
    def demangle_name(self):
        """
            Property which return the demangle name of the element.

            :return str: The demangle name of the element or None if there is
                no demangle version of the name.
        """
        return idc.demangle_name(self.name, idc.get_inf_attr(idc.INF_SHORT_DN))

    @property
    def is_dummy_name(self):
        """
            Property for checking if the current name of this element is a
            "dummy" name (a name set by default by IDA when it does not know
            how to call an element) with a special prefix. This function will
            not recognize the ``aSTRING`` naming,
            see :meth:`~BipElt.is_auto_name`, and :meth:`~BipElt.is_ida_name`.

            :return: ``True`` if the element has a dummy name, ``False``
                otherwise.
        """
        return ida_bytes.has_dummy_name(self.flags)

    @property
    def is_auto_name(self):
        """
            Property for checking if the current name of this element is an
            "auto-generated" name, those are the default name generated by
            IDA but without a special prefix
            (see :meth:`~BipElt.is_dummy_name`) such as the one for the
            string. See also :meth:`~BipElt.is_ida_name`.

            :return: ``True`` if the element has an auto-generated name,
                ``False`` otherwise.
        """
        return ida_bytes.has_auto_name(self.flags)

    @property
    def is_ida_name(self):
        """
            Property for checking if the current name is a default name as
            generated by IDA. This is an OR condition of
            :meth:`~BipElt.is_auto_name` and :meth:`~BipElt.is_dummy_name`.

            This is still not perfect and name put some names put by IDA will
            not be recognize by this function (for exemple the global for the
            CFG and probably others).

            :return: ``True`` if the element has a name provided by IDA,
                ``False`` otherwise.
        """
        return self.is_auto_name or self.is_dummy_name

    @property
    def is_user_name(self):
        """
            Property for checking if the current name is a "user name". In
            practice this check a flag that the API can avoid setting, so
            there is no garantee it is an actual user name.
            See :meth:`~BipElt.is_ida_name` for checking if a name was
            generated by IDA.

            :return: ``True`` if the name is marked as set by a user,
                ``False`` otherwise.
        """
        return ida_bytes.has_user_name(self.flags)


    ################### COLOR ##################

    @property
    def color(self):
        """
            Property which return the color of the item.

            :return: The coloration of the element in IDA.
            :rtype: int
        """
        return idc.get_color(self.ea, idc.CIC_ITEM)

    @color.setter
    def color(self, value):
        """
            Setter which allow to set the color of the current element.

            :param int value: the color to which set the item.
        """
        idc.set_color(self.ea, idc.CIC_ITEM, value)

    ################### COMMENT ##################

    @property
    def comment(self):
        """
            Property which return the comment of the item.

            :return: The value of the comment or ``None`` if there is no
                comment.
            :rtype: :class:`str`
        """
        return ida_bytes.get_cmt(self.ea, 0)

    @comment.setter
    def comment(self, value):
        """
            Setter which allow to set the value of the comment.

            :param value: The comment to set
            :type value: :class:`str`
        """
        if value is None:
            value = ""
        idc.set_cmt(self.ea, value, 0)

    @property
    def rcomment(self):
        """
            Property which return the repeatable comment of the item.

            :return: The value of the comment or ``None`` if there is no
                repeatable comment.
            :rtype: :class:`str`
        """
        return ida_bytes.get_cmt(self.ea, 1)

    @rcomment.setter
    def rcomment(self, value):
        """
            Setter which allow to set the value of the repeatable comment.

            :param value: The comment to set.
            :type value: :class:`str`
        """
        if value is None:
            value = ""
        ida_bytes.set_cmt(self.ea, value, 1)

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
            Wrapper on ``idc.is_code`` .

            :return: True if current element is code, False otherwise.
            :rtype: bool
        """
        return idc.is_code(self.flags)

    @property
    def is_data(self):
        """
            Property indicating if this element is considered as data.
            Wrapper on ``idc.is_data`` .

            :return: True if current element is data, False otherwise.
            :rtype: bool
        """
        return idc.is_data(self.flags)

    @property
    def is_unknown(self):
        """
            Property indicating if this element is considered as unknwon.
            Wrapper on ``idc.is_unknown`` .

            :return: True if current element is unknwon, False otherwise.
            :rtype: bool
        """
        return idc.is_unknown(self.flags)

    @property
    def is_head(self):
        """
            Property indicating if the element is an *head* in IDA. An *head*
            element is the beggining of an element in IDA (such as the
            beginning of an instruction) and can be named.
            Wrapper on ``idc.is_head`` .

            :return: True if the current element is an head, False otherwise.
            :rtype: bool
        """
        return idc.is_head(self.flags)

    # no is_tail because counter intuitive as it is only a ``not is_head``

    @property
    def has_data(self):
        """
            Property which indicate if an element has a value. If an element
            has no value a default value of ``0xFF`` will be returned in
            general. This correspond to element in IDA which are marked with
            a ``?`` in value. Wrapper on ``idc.has_value``.

            :return: True if the current element has a value, False otherwise.
        """
        return idc.has_value(self.flags)

    ######################## GUI ############################

    def goto(self):
        """
            Method which allow to move the screen to the position of this
            element. Wrapper on ``ida_kernwin.jumpto`` (old ``idc.Jump``).
        """
        ida_kernwin.jumpto(self.ea)

    ########################## CLASS METHOD ##########################

    @classmethod
    def iter_all(cls, start=None, end=None):
        """
            Class method allowing to iter on all mapped elements of the IDB.

            This will return only the elements which are handle by the class
            or one of this subclasses. For exemple calling
            ``BipData.iter_heads()`` will return only the heads which are
            :class:`BipData` object or children of that class. This use
            :func:`GetElt` for determining the correct object to return.

            :param start: The address at which to start iterating. If this
                parameter is None (the default) the minimum mapped address
                will be used.
            :param end: The address at which to stop iterating. If this
                parameter is None (the default) the maximum mapped address
                will be used.
            :return: A generator of object child of :class:`BipBaseElt`
                allowing to iter on all the elt in the idb.
        """
        ea = min_ea() if start is None else start
        if end is None:
            end = max_ea()
        while ea < end:
            elt = GetElt(ea)
            sz = elt.size
            if cls._is_this_elt(ea):
                yield elt
            ea += sz

    #################### STATIC METHOD ######################

    @staticmethod
    def is_mapped(ea=None):
        """
            Static method which allow to know if an address is mapped or not.

            :param ea: The address to test for being mapped or not. If
                ``None`` the screen address will be used.
            :return: True if the address is mapped, False otherwise.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        return ida_bytes.is_mapped(ea)

    @staticmethod
    def next_data_addr(ea=None, down=True):
        """
            Static method which allow to find the address of the next data
            element.

            :param ea: The address at which to start the search. If ``None``
                the screen address will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :return: The address of the next data or None if the search did
                not find any match.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        if down:
            fl = ida_search.SEARCH_DOWN
        else:
            fl = ida_search.SEARCH_UP
        r = ida_search.find_data(ea, fl)
        if r == idc.BADADDR: # no data found
            return None
        return r

    @staticmethod
    def next_data(ea=None, down=True):
        """
            Static method which allow to find the next data element.

            :param ea: The address at which to start the search. If ``None``
                the screen address will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :return: An object which ibherit from :class:`BipBaseElt` or
                ``None`` if the search did not find any match.
        """
        r = BipElt.next_data_addr(ea=ea, down=down)
        if r is None:
            return r
        else:
            return GetElt(r)

    @staticmethod
    def next_code_addr(ea=None, down=True):
        """
            Static method which allow to find the address of the next code
            element.

            :param ea: The address at which to start the search. If ``None``
                the screen address will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :return: The address of the next code or None if the search did
                not find any match.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        if down:
            fl = ida_search.SEARCH_DOWN
        else:
            fl = ida_search.SEARCH_UP
        r = ida_search.find_code(ea, fl)
        if r == idc.BADADDR: # no result found
            return None
        return r

    @staticmethod
    def next_code(ea=None, down=True):
        """
            Static method which allow to find the next code element.

            :param ea: The address at which to start the search. If ``None``
                the screen address will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :return: An object which ibherit from :class:`BipBaseElt` or
                ``None`` if the search did not find any match.
        """
        r = BipElt.next_code_addr(ea=ea, down=down)
        if r is None:
            return r
        else:
            return GetElt(r)

    @staticmethod
    def next_unknown_addr(ea=None, down=True):
        """
            Static method which allow to find the address of the next unknown
            element. An unknown element is an element for which IDA does not
            know the type.

            :param ea: The address at which to start the search. If ``None``
                the screen address will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :return: The address of the next unknown element or ``None`` if
                the search did not find any match.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        if down:
            fl = ida_search.SEARCH_DOWN
        else:
            fl = ida_search.SEARCH_UP
        r = ida_search.find_unknown(ea, fl)
        if r == idc.BADADDR: # no result found
            return None
        return r

    @staticmethod
    def next_unknown(ea=None, down=True):
        """
            Static method which allow to find the next unknown element.
            An unknown element is an element for which IDA does not know
            the type.

            :param ea: The address at which to start the search. If ``None``
                the screen address will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :return: An object which ibherit from :class:`BipBaseElt` or
                ``None`` if the search did not find any match.
        """
        r = BipElt.next_unknown_addr(ea=ea, down=down)
        if r is None:
            return r
        else:
            return GetElt(r)

    @staticmethod
    def next_defined_addr(ea=None, down=True):
        """
            Static method which allow to find the address of the next defined
            element. An defined element is the opposite of unknown, meaning
            or a data with a known type or code.

            :param ea: The address at which to start the search. If ``None``
                the screen address will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :return: The address of the next defined element or None if the
                search did not find any match.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        if down:
            fl = ida_search.SEARCH_DOWN
        else:
            fl = ida_search.SEARCH_UP
        r = ida_search.find_defined(ea, fl)
        if r == idc.BADADDR: # no result found
            return None
        return r

    @staticmethod
    def next_defined(ea=None, down=True):
        """
            Static method which allow to find the next defined element.
            An defined element is the opposite of unknown, meaning or a data
            with a known type or code.

            :param ea: The address at which to start the search. If ``None``
                the screen address will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :return: An object which ibherit from :class:`BipBaseElt` or
                ``None`` if the search did not find any match.
        """
        r = BipElt.next_defined_addr(ea=ea, down=down)
        if r is None:
            return r
        else:
            return GetElt(r)

    @staticmethod
    def search_bytes_addr(byt, start_ea=None, end_ea=None, down=True, nxt=True):
        """
            Static method for searching a sequence of bytes. This will search
            for the bytes which ever the data type is.

            This is a wrapper on the ``ida_search.find_binary`` (previously
            ``FindBinary``) function from IDA with a radix of 16.

            The byte should be represented in hexadecimal seperated by space.
            A ``?`` can be put for replacing a byte, for exemple:
            ``41 8B 44 ? 20``.

            :param byt: A string representing a sequence of byte.
            :param start_ea: The address at which to start the search, if
                ``None`` the current address will be used.
            :param end_ea: The address at which to stop the search, if
                ``None`` the maximum or minimum (depending of searching up or
                down) will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :param nxt: If True (the default) the current element will not
                be included in the search.
            :return: The address at which the byte sequence is present or
                ``None`` if no element were found during the search.
        """
        if start_ea is None:
            start_ea = ida_kernwin.get_screen_ea()
        if down:
            fl = ida_search.SEARCH_DOWN
            if end_ea is None:
                end_ea = idc.get_inf_attr(idc.INF_MAX_EA)
        else:
            fl = ida_search.SEARCH_UP
            if end_ea is None:
                end_ea = idc.get_inf_attr(idc.INF_MIN_EA)
        if nxt:
            fl |= ida_search.SEARCH_NEXT
        r = ida_search.find_binary(start_ea, end_ea, byt, 16, fl)
        if r == idc.BADADDR:
            return None
        else:
            return r

    @staticmethod
    def search_bytes(byt, start_ea=None, end_ea=None, down=True, nxt=True):
        """
            Static method for searching a sequence of bytes. This will search
            for the bytes which ever the data type is.

            This is a wrapper on the ``ida_search.find_binary`` (previously
            ``FindBinary``) function from IDA with a radix of 16.

            The byte should be represented in hexadecimal seperated by space.
            A ``?`` can be put for replacing a byte, for exemple:
            ``41 8B 44 ? 20``.

            :param byt: A string representing a sequence of byte.
            :param start_ea: The address at which to start the search, if
                ``None`` the current address will be used.
            :param end_ea: The address at which to stop the search, if
                ``None`` the maximum or minimum (depending of searching up or
                down) will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :param nxt: If True (the default) the current element will not
                be included in the search.
            :return: An object which inherit from :class:`BipBaseElt`
                representing the element at the address at which the byte
                sequence is present or ``None`` if no element were found
                during the search.
        """
        r = BipElt.search_bytes_addr(byt, start_ea=start_ea, end_ea=end_ea, down=down, nxt=nxt)
        if r is None:
            return r
        else:
            return GetElt(r)

    @staticmethod
    def search_str_addr(s, start_ea=None, end_ea=None, down=True, nxt=True):
        """
            Static method for searching a string. In practice this perform
            a search_bytes on the binary by encoding correctly the string
            passed in argument and returning only reference to data elements.

            .. warning::

                This is different from idapython ``FindText`` method as this
                will only search for bytes in the binary (and more precisely
                the data)! It should also be way faster.

            .. todo:: this should allow to handle encoding.

            :param str s: The C string for which to search. If the string
                is NULL terminated the NULL byte must be included.
            :param start_ea: The address at which to start the search, if
                ``None`` the current address will be used.
            :param end_ea: The address at which to stop the search, if
                ``None`` the maximum or minimum (depending of searching up or
                down) will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :param nxt: If True (the default) the current element will not
                be included in the search.
            :return: The address at which the string was found.  It will
                always be data. If no matching element was found None will be
                return.
        """
        # lets encode the string
        byt = " ".join(["{:X}".format(ord(c)) for c in s])
        # we want to skip everything which is not data without making the
        #   search, this should be faster
        curr_addr = BipElt.next_data_addr(start_ea, down=down)
        while curr_addr is not None:
            curr_addr = BipElt.search_bytes_addr(byt, start_ea=curr_addr, end_ea=end_ea,
                    down=down, nxt=nxt)
            if curr_addr is None:
                return None # not found
            if idc.is_data(ida_bytes.get_full_flags(curr_addr)):
                return curr_addr # found!
            # lets continue
            curr_addr = BipElt.next_data_addr(curr_addr, down=down)
        return None # not found


    @staticmethod
    def search_str(s, start_ea=None, end_ea=None, down=True, nxt=True):
        """
            Static method for searching a string. In practice this perform
            a search_bytes on the binary by encoding correctly the string
            passed in argument and returning only reference to data elements.

            .. warning::

                This is different from idapython ``FindText`` method as this
                will only search for bytes in the binary (and more precisely
                the data)! It should also be way faster.

            .. todo:: this should allow to handle encoding.

            :param str s: The C string for which to search. If the string
                is NULL terminated the NULL byte must be included.
            :param start_ea: The address at which to start the search, if
                ``None`` the current address will be used.
            :param end_ea: The address at which to stop the search, if
                ``None`` the maximum or minimum (depending of searching up or
                down) will be used.
            :param down: If True (the default) search bellow the given
                address, if False search above.
            :param nxt: If True (the default) the current element will not
                be included in the search.
            :return: An object which inherit from :class:`BipBaseElt`
                representing the element at the address at which the string
                was found. The element will always have :meth:`BipElt.is_data`
                as True. If no matching element was found None will be return.
        """
        r = BipElt.search_str_addr(s, start_ea=start_ea, end_ea=end_ea,
                down=down, nxt=nxt)
        return r if r is None else GetElt(r)

def GetElt(ea=None):
    """
        Return an object inherithed from :class:`BipBaseElt` which correspond
        to the element at an id.

        Internally this function parcours subclasses of :class:`BipBaseElt`
        and call the :meth:`~BipBaseElt._is_this_elt` and return the one which
        match.

        .. warning::

            There is a problem if two functions of a sublcass level can
            return True on the same element.

        :param int ea: An address at which to get an element. If ``None`` the
            screen address is used.
        :raise RuntimeError: If the address correspond to the error value.
        :return: An object (subclass of :class:`BipBaseElt`) representing the
            element. If the address is not mapped a :class:`BipElt` will be
            returned.
    """
    if ea is None:
        ea = ida_kernwin.get_screen_ea()
    if ea == idc.BADADDR:
        raise RuntimeError("Trying to get element for error address")
    cls = BipBaseElt
    sbcls = cls.__subclasses__()
    while len(sbcls) != 0:
        cl = sbcls.pop()
        if cl._is_this_elt(ea):
            cls = cl
            sbcls = cl.__subclasses__()
    return cls(ea)

def GetEltByName(name):
    """
        Same as :func:`GetElt` but using a name and not an address.

        :param str name: The name of the element to get. If a "dummy" name
            (``byte_xxxx``, ...) is provided the database is not consulted.
        :return: An object representing the element or ``None`` if the name
            was not found.
        :rtype: Subclass of :class:`BipBaseElt`.
    """
    ea = ida_name.get_name_ea(idc.BADADDR, name)
    if ea is None or ea == idc.BADADDR:
        return None
    return GetElt(ea)

def Here():
    """
        Return current screen address.

        :return: The current address.
    """
    return ida_kernwin.get_screen_ea()

