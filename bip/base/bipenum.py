import idc
import ida_enum

from bip.py3compat.py3compat import *

from .bipelt import BipRefElt


class BipEnum(object):
    """
        Class for representing and manipulating an enum in IDA.
        Class method :meth:`~BipEnum.get` and :meth:`~BipEnum.create` allows
        to easily create and recuperate a :class:`BipEnum` object.

        The enum in IDA do not support xref, however the enum members do.

        .. todo:: allow to set an instruction operand as an enum
    """

    ########################## BASE ##########################

    def __init__(self, eid):
        """
            Constructor for a :class:`BipEnum` object. There is few reason
            to directly use this constructor, see functions:
            :meth:`~BipEnum.get` or :meth:`~BipEnum.create`

            :param int eid: The enum id (``enum_t``) representing this enum.
        """
        self._eid = eid

    def __eq__(self, other):
        """
            Compare two BipEnum.
        """
        if isinstance(other, BipEnum):
            return self._eid == other._eid
        elif isinstance(other, (int, long)):
            return self._eid == other
        else:
            return NotImplemented

    def __ne__(self, other):
        res = self.__eq__(other)
        if res == NotImplemented:
            return res
        else:
            return not res

    @classmethod
    def _is_this_elt(cls, idelt):
        """
            Return true if ``idelt`` correspond to an enum_t.
        """
        return ida_enum.get_enum_name(idelt) is not None

    @property
    def name(self):
        """
            Property for getting the name of this enum. A setter exist for
            this property.

            :return str: The name of this enum.
        """
        return ida_enum.get_enum_name(self._eid)

    @name.setter
    def name(self, value):
        """
            Setter for setting the name of this enum.

            :param str value: The new name to set for the enum.
            :raise ValueError: If setting the name failed.
        """
        if not ida_enum.set_enum_name(self._eid, value):
            raise ValueError("Impossible to set new name {} for the enum".format(value))

    @property
    def width(self):
        """
            Property for getting the width in bytes of an enum. The width of
            an enum can be: 0 (unspecified),1,2,4,8,16,32,64.

            :return int: The width of the enum.
        """
        return ida_enum.get_enum_width(self._eid)

    @width.setter
    def width(self, value):
        """
            Setter for the width of an enum. The width in bytes of an enum
            can be: 0 (unspecified),1,2,4,8,16,32,64.

            :param int value: The width of the enum.
            :raise ValueError: If the value is not supported.
            :raise RuntimeError: If it was unable to change the width of an
                enum.
        """
        if value not in (0,1,2,4,8,16,32,64):
            raise ValueError("Unsuported width {} for enum".format(value))
        if not ida_enum.set_enum_width(self._eid, value):
            raise RuntimeError("Unable to change width of the enum")

    @property
    def is_bitfield(self):
        """
            Property for getting or setting if an enum is a bitfield.

            :return bool: True if this enum is a bitfield, false otherwise.
        """
        return ida_enum.is_bf(self._eid)

    @is_bitfield.setter
    def is_bitfield(self, value):
        """
            Setter for setting an enum has being a bitfield.

            :param bool value: True for setting this enum has a bitfield,
                False for setting it has not a bitfield.
            :raise RuntimeError: If unable to change the enum.
        """
        if not ida_enum.set_enum_bf(self._eid, value):
            raise RuntimeError("Unable to change the enum bitfield characteristic")

    def __str__(self):
        return "Enum: {}".format(self.name)

    @property
    def comment(self):
        """
            Property which return the comment associated with an enum.

            :return: The comment as a string or None if no comment is
                associated with it.
        """
        return ida_enum.get_enum_cmt(self._eid, False)

    @comment.setter
    def comment(self, value):
        """
            Property setter for changing the enum comment.

            :param str value: The new comment to set.
        """
        ida_enum.set_enum_cmt(self._eid, value, False)

    @property
    def rcomment(self):
        """
            Property which return the repeatable comment associated with an
            enum.

            :return: The comment as a string or None if no comment is
                associated with it.
        """
        return ida_enum.get_enum_cmt(self._eid, True)

    @rcomment.setter
    def rcomment(self, value):
        """
            Property setter for changing the enum repeatable comment.

            :param str value: The new comment to set.
        """
        ida_enum.set_enum_cmt(self._eid, value, True)


    ############################### MEMBERS ###############################

    @property
    def nb_members(self):
        """
            Property which return the number of members present in this enum.
        """
        return ida_enum.get_enum_size(self._eid)

    def add(self, name, value):
        """
            Property for adding a new member to this enum.

            :param str name: The name of the new member to add.
            :param int value: The value of the new member to add.
            :raise RuntimeError: If it was not possible to add the new member.
        """
        if ida_enum.add_enum_member(self._eid, name, value,  ida_enum.DEFMASK) != 0:
            raise RuntimeError("Unable to add new member {} ({}) to enum {}".format(name, value, self.name))

    def member_by_name(self, name):
        """
            Function for getting a member of this enum from its name.

            Internally this function use :meth:`BEnumMember.get` and check
            that the parent of the member is indeed this enum.

            :param str name: The name of the member to get.
            :return: A :class`BEnumMember` object.
            :raise ValueError: If the name for the enum member does not exist
                or if the enum member is not part of this enum.
        """
        bem = BEnumMember.get(name) # this will raise a ValueError if name does not exist
        if bem.enum != self: # check that we are in the good enum
            raise ValueError("Enum member {} exist but not in enum {}".format(name, self.name))
        return bem

    def __getitem__(self, key):
        """
            Getitem method which allow access to the members of the enum from
            their name.

            This is just a convinient wrapper on top
            of :meth:`~BipEnum.member_by_name`.

            :param str key: The name of the member to get.
            :return: A :class`BEnumMember` object.
            :raise ValueError: If the name for the enum member does not exist
                or if the enum member is not part of this enum.
        """
        return self.member_by_name(key)

    def members_by_value(self, value, _bmask=None):
        """
            Function for getting members with a particular value in this enum.

            :param int value: The value for which to get the members.
            :param int _bmask: Optionnal value for precising the mask, by
                default use the default mask.
            :return: A list of :class:`BEnumMember` representing the enum
                member with that value
        """
        if _bmask is None:
            _bmask = ida_enum.DEFMASK
        tmp = ida_enum.get_first_serial_enum_member(self._eid, value, _bmask)
        # tmp is a list with the first element being the member id and the
        #   second a serial ?
        mid = tmp[0]
        fmid = mid
        ser = tmp[1]
        midl = []
        while mid != idc.BADADDR:
            midl.append(mid)
            tmp = ida_enum.get_next_serial_enum_member(ser, fmid)
            mid = tmp[0]
            ser = tmp[1]
        return [BEnumMember(m) for m in midl]

    def del_member(self, name):
        """
            Function for deleting a member from this enum by its name.

            Internally this will first get the enum using
            :meth:`~BipEnum.member_by_name` then try to delete it.

            :param str name: The name of the member to delete.
            :raise ValueError: If the name does not exist.
            :raise RuntimeError: If was not able to delete the enum member.
        """
        bem = self.member_by_name(name)
        if not ida_enum.del_enum_member(self._eid, bem.value, bem._serial, bem._bmask):
            raise RuntimeError("Unable to delete enum member {} from {}".format(name, self.name))

    @property
    def members(self):
        """
            Property for getting a list of the members of this enum.

            :return: A list of :class:`BEnumMember`.
        """
        mml = []
        # only way to iterate on members is to use a visitor, thx IDA
        class _BipEnumVisitIterator(ida_enum.enum_member_visitor_t):
            def visit_enum_member(self, cid, val):
                mml.append(BEnumMember(cid))
                return 0
        ida_enum.for_all_enum_members(self._eid, _BipEnumVisitIterator())
        return mml

    def __iter__(self):
        """
            Iter method for allowing to iterate on all members of the enum.

            This is just a wrapper on :meth:`BipEnum.members`. Update to the
            enum during the iteration will not be taken into account.
        """
        for m in self.members:
            yield m

    ########################### GET & CREATE ENUM ########################

    @classmethod
    def get(cls, name):
        """
            Class method for getting a :class:`BipEnum` object from the name
            of an existing enum.

            :param str name: The name of the enum to get.
            :raise ValueError: If the enum ``name`` does not exist.
            :return: A :class:`BipEnum` object corresponding to the enum
                identified by the name provided.
        """
        eid = ida_enum.get_enum(name)
        if eid == idc.BADADDR:
            raise ValueError("Enum {} does not exist".format(name))
        return cls(eid)

    @classmethod
    def create(cls, name):
        """
            Class method allowing to create a new empty enum.

            :param str name: The name of the enum to create. If this is
                ``None`` a default name ``enum_INT`` will be created by IDA.
            :raise ValueError: If the enum ``name`` already exist.
            :raise RuntimeError: If it was not possible to create the enum.
            :return: A :class:`BipEnum` object corresponding to the newly
                created enum.
        """
        eid = ida_enum.get_enum(name)
        if eid != idc.BADADDR:
            raise ValueError("Enum {} already exist".format(name))
        eid = ida_enum.add_enum(idc.BADADDR, name, 0)
        if eid == idc.BADADDR:
            raise RuntimeError("Unable to create enum {}".format(name))
        return cls(eid)


    @staticmethod
    def delete(arg):
        """
            Static method allowing to delete an enum by its name or its id.

            :parm arg: String representing the name of the enum or id (int)
                representing the enum in IDA or a :class:`BipEnum` object (in
                that case the object will not be valid after that).
            :raise ValueError: If the argument is invalid.
        """
        if isinstance(arg, (str, unicode)):
            eid = ida_enum.get_enum(arg)
            if eid == idc.BADADDR:
                raise ValueError("Enum {} does not exist".format(arg))
        elif isinstance(arg, (int, long)):
            eid = arg
        elif isinstance(arg, BipEnum):
            eid = arg._eid
        else:
            raise ValueError("Invalid argument")
        ida_enum.del_enum(eid)

class BEnumMember(BipRefElt):
    """
        Class for representing and manipulating an enum member. Object
        of this class can be access, created and delete through methods of
        :class:`BipEnum`. It is possible to directly get an object of this
        type using :meth:`BEnumMember.get`.

        The object of this class support the xref API implemented in the
        parent class :class:`BipRefElt`.
    """

    ############################# BASE ####################################

    def __init__(self, member_id):
        super(BEnumMember, self).__init__(member_id)
        self._member_id = member_id

    @classmethod
    def _is_this_elt(cls, idelt):
        """
            Return true if ``idelt`` correspond to a enum member id.

            In practice this try to get the associated enum for this potential
            enum id and check if it succeed or not.
        """
        return ida_enum.get_enum_member_enum(idelt) != idc.BADADDR

    @property
    def _mid(self):
        """
            Property which return the enum member id for this object.

            Use for interfacing with IDAPython internals.
        """
        return self._member_id

    @property
    def _serial(self):
        """
            Property which return the "serial" of this enum member. This is
            used only for interfacing with native IDAPython API.

            The serial is not a unique id for this enum, the serials for enum
            members always start at 0 and is incremented only when two enum
            members have the same value.

            :return: The serial integer for this enum member.
        """
        return ida_enum.get_enum_member_serial(self._mid)

    @property
    def _bmask(self):
        """
            Property for getting the bitmask of this enum member. This is used
            only for interfacting with native IDAPython API. Do not know what
            the bitmask is actual used for in IDA.

            :return: An integer representing the bitmask for this member.
        """
        return ida_enum.get_enum_member_bmask(self._mid)

    def __eq__(self, other):
        """
            Equality operator for two :class:`BEnumMember`.
        """
        if isinstance(other, BEnumMember):
            return self._mid == other._mid
        elif isinstance(other, (int, long)):
            return self._mid == other
        else:
            return NotImplemented

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def value(self):
        """
            Property for getting the value of this enum member.

            :return int: The value of this enum member.
        """
        return ida_enum.get_enum_member_value(self._mid)

    @property
    def name(self):
        """
            Property for getting and setting the name of this enum member.

            :return str: The name of this enum member.
        """
        return ida_enum.get_enum_member_name(self._mid)

    @name.setter
    def name(self, value):
        """
            Setter property for changing the name of an enum member.

            :param str value: The new name for the enum member.
            :raise RuntimeError: If was unable to change the name.
        """
        if not ida_enum.set_enum_member_name(self._mid, value):
            raise RuntimeError("Unable to set enum name to {}".format(value))

    @property
    def enum(self):
        """
            Property for getting the :class:`BipEnum` object from this member.

            :return: The :class:`BipEnum` associated with this member.
        """
        return BipEnum(ida_enum.get_enum_member_enum(self._mid))

    def __str__(self):
        return "EnumMember: {}.{} ({})".format(self.enum.name, self.name, self.value)

    @property
    def comment(self):
        """
            Property which return the comment associated with an enum member.

            :return: The comment as a string or None if no comment is
                associated with it.
        """
        return ida_enum.get_enum_member_cmt(self._mid, False)

    @comment.setter
    def comment(self, value):
        """
            Property setter for changing the enum member comment.

            :param str value: The new comment to set.
        """
        ida_enum.set_enum_member_cmt(self._mid, value, False)

    @property
    def rcomment(self):
        """
            Property which return the repeatable comment associated with an
            enum member.

            :return: The comment as a string or None if no comment is
                associated with it.
        """
        return ida_enum.get_enum_member_cmt(self._mid, True)

    @rcomment.setter
    def rcomment(self, value):
        """
            Property setter for changing the enum member repeatable comment.

            :param str value: The new comment to set.
        """
        ida_enum.set_enum_member_cmt(self._mid, value, True)

    ############################### GET #################################

    @classmethod
    def get(cls, name):
        """
            Class method for recuperating a :class:`BEnumMember` object from
            its name.

            :return: A :class:`BEnumMember` object associated with the name.
            :raise ValueError: If no enum member with this name exist.
        """
        mid = ida_enum.get_enum_member_by_name(name)
        if mid == idc.BADADDR:
            raise ValueError("Enum member with name {} was not found".format(name))
        return cls(mid)






