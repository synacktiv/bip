import idc
import ida_enum

class BipEnum(object): # TODO: BipRefElt ?
    """
        Class for representing and manipulating an enum in IDA.
        Class method :meth:`~BipEnum.get` and :meth:`~BipEnum.create` allows
        to easily create and recuperate a :class:`BipEnum` object.

        .. todo:: support xref

        .. todo:: create class for enum members (needed for xref)
        .. todo:: support accessing and creating members

        .. todo:: add to the doc
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
        return ((isinstance(other, BipEnum) and self._eid == other._eid) or
                isinstance(other, (int, long)) and self._eid == other)

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

            :param str value: The 
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

    # TODO: will need to create a class for the members for being able to
    #   support the xref

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


