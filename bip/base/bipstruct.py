import idc
import idautils
import ida_struct
import ida_typeinf

from bip.py3compat.py3compat import *

from .bipidb import BipIdb
#from .biptype import BipType
import bip.base.biptype
from .bipelt import BipRefElt
from .biperror import BipError

class BipStruct(BipRefElt):
    """
        Class for representing and manipulating a structure in IDA.
        Static functions :func:`~BipStruct.create` and :func:`~BipStruct.get` allow
        to easilly get an instance of those object.

        .. todo:: get/set alignement

        .. todo:: support deletion of members

        .. todo:: allow to iterate on all structure and other stuff like that

        .. todo:: test

    """

    ############################ BASE ###########################

    def __init__(self, st):
        """
            Constructor for a :class:`BipStruct` object. There is few reason
            to directly use this constructor, see functions
            :func:`~BipStruct.get` or :func:`~BipStruct.create`.

            :param st: A structure ``struc_t`` from IDA such as return
                by ``get_struc`` or an sid (int) representing a structure.
            :raise ValueError: If an integer is provided and is not a valid
                sid, or if an incorrect type is provided as ``st``.
        """
        if isinstance(st, (int, long)):
            super(BipStruct, self).__init__(st)
            # we got a sid, get the struct from that
            struct_t = ida_struct.get_struc(st)
            if struct_t is None:
                raise ValueError("sid 0x{:X} is invalid".format(st))
        elif isinstance(st, ida_struct.struc_t):
            super(BipStruct, self).__init__(st.id)
            struct_t = st
        else:
            raise ValueError("Invalid structure object {}".format(st))
        #: Internal ``struct_t`` object from IDA.
        self._struct = struct_t

    @property
    def _sid(self):
        """
            Property which return the sid for this :class:`BipStruct` object. The
            sid is the struct id number (``tid_t``) from IDA and there is no
            reason it should be used except for interfacing with the standard
            API from IDA.

            :return: An int corresponding to the sid.
        """
        return self._struct.id


    @classmethod
    def _is_this_elt(cls, idelt):
        """
            Return true if ``idelt`` correspond to a sid.
        """
        return ida_struct.get_struc(idelt) is not None

    @property
    def name(self):
        """
            Property which return the name (as a string) of this structure.
        """
        return ida_struct.get_struc_name(self._sid)

    @name.setter
    def name(self, value):
        """
            Setter for the name of the struct.

            :param str value: The new name for this structure.
        """
        return ida_struct.set_struc_name(self._sid, value)

    @property
    def size(self):
        """
            Property returning the size of the structure as an integer.
        """
        return ida_struct.get_struc_size(self._struct)

    def __str__(self):
        return "Struct: {} (size=0x{:X})".format(self.name, self.size)

    @property
    def comment(self):
        """
            Property which return the comment associated with a structure.
            For repeatable comment see :meth:`~BipStruct.rcomment`
        """
        return ida_struct.get_struc_cmt(self._sid, 0)

    @comment.setter
    def comment(self, value):
        """
            Setter which allow to set a comment associated with this
            :class:`BipStruct` object.

            :param str value: The new comment to associate with this object.
        """
        if value is None:
            value = ""
        ida_struct.set_struc_cmt(self._sid, value, 0)

    @property
    def rcomment(self):
        """
            Property which return the repeatable comment associated with this
            :class:`BipStruct` object.
        """
        return ida_struct.get_struc_cmt(self._sid, 1)

    @rcomment.setter
    def rcomment(self, value):
        """
            Setter which allow to set a repeatable comment for :class:`BipStruct`
            object.

            :param str value: The new comment to associate with this object.
        """
        if value is None:
            value = ""
        ida_struct.set_struc_cmt(self._sid, value, 1)

    ########################## GUI ###############################

    @property
    def is_hidden(self):
        """
            Property for knowing if a struct is fully shown in the gui.

            :return: True if the structure is "collapsed", False if it is
                shown.
        """
        return self._struct.is_hidden()


    @is_hidden.setter
    def is_hidden(self, value):
        """
            Property setter for setting if a struct is "collapsed" in the
            GUI.

            :param value: True for hidding the struct, false for showing it.
        """
        ida_struct.set_struc_hidden(self._struct, value)

    ############################ MEMBERS ###########################

    @property
    def nb_members(self):
        """
            Property which return the number of members in this
            :class:`BipStruct` object.
        """
        return self._struct.memqty

    @property
    def members(self):
        """
            Property which return a list of :class:`BStructMember` objects
            representing the members of this structure.

            :rtype: A list of :class:`BStructMember` object.
        """
        return [BStructMember(self._struct.get_member(i), self) for i in range(self.nb_members)]

    @property
    def members_iter(self):
        """
            Property returning an iterable of
            :class:`BStructMember` representing the different
            members of this struct. This is similar to :meth:`BipStruct.members`.

            .. todo:: maybe delete this ? I am worried because of the
                get_member property which may create problem if the number of
                members change during the iteration.

            :rtype: Iterable of :class:`BStructMember` object.
        """
        for i in range(self.nb_members):
            # WARNING: get_member does not check for bound in IDA
            #   implementation, possible to access adjacent memory.
            yield BStructMember(self._struct.get_member(i), self)

    def member_at(self, off):
        """
            Method which return the member of this :class:`BipStruct` at the
            offset provided in argument. This will return the correct member
            even if the offset is not aligned.

            :param int off: The offset of the member to get.
            :raise IndexError: If the member was not found (offset bigger than
                the struct).
            :return: An :class:`BStructMember` object corresponding to the
                member.
        """
        mm = ida_struct.get_member(self._struct, off)
        if mm is None:
            raise IndexError("Member at offset {} does not seems to exist in {}".format(off, self))
        return BStructMember(mm, self)

    def member_by_name(self, name):
        """
            Method which return the member of this :class:`BipStruct` from its
            name.

            :param str name: The name of the member to get.
            :raise KeyError: If the member was not found.
            :return: An :class:`BStructMember` object corresponding to the
                member.
        """
        mm = ida_struct.get_member_by_name(self._struct, name)
        if mm is None:
            raise KeyError("Member {} does not seems to exist in {}".format(name, self))
        return BStructMember(mm, self)

    def __getitem__(self, key):
        """
            Getitem method which allow access to the members of the struct.

            :param key: If key is a string it will search the member by name,
                if it is a integer it will search the member by offset.
            :raise ValueError: If the member was not found.
            :raise TypeError: If ``key`` is not an integer or a string.
            :return: An :class:`BStructMember` object corresponding to the
                member.
        """
        if isinstance(key, (int, long)):
            return self.member_at(key)
        elif isinstance(key, (str, unicode)):
            return self.member_by_name(key)
        else:
            raise TypeError("BipStruct.__getitem__ expect a integer or a string as key, got: {}".format(key))

    def __iter__(self):
        """
            Iter method for accessing the members as a list. This is
            equivalent to :meth:`~BipStruct.members_iter`.

            .. note::
            
                By default python will try to use the __getitem__ method
                which is not what we want because the __getitem__ method takes
                offset.

            :return: An iterator on the :class:`BStructMember` object of this
                struct.
        """
        for i in range(self.nb_members):
            yield BStructMember(self._struct.get_member(i), self)

    def add(self, name, size, comment=None, offset=None):
        """
            Add a new member to the structure (at the end by default).

            :param str name: The name of the field to add. If None or an empty
                string the default name used by IDA will be used (``field_``).
            :param int size: The size of the field to add in bytes,
                can be 1, 2, 4 or 8.
            :param str comment: Optional parameter which allow to add a
                comment associated with the new member.
            :param int offset: The offset at which to add the new member, by
                default (None) it will be added at the end.
            :raise TypeError: If one argument is not of the correct type or
                with the correct value.
            :raise ValueError: If an error occur when adding the member.
            :return: An :class:`BStructMember` object corresponding to the
                member added.
        """
        if name is None:
            name = ""
        if size not in (1, 2, 4, 8) or not isinstance(name, (str, unicode)):
            raise TypeError("Invalid type for adding in {}".format(self))
        if offset is None:
            offset = idc.BADADDR
        # compute flags
        flags = idc.FF_DATA
        d= {8:idc.FF_QWORD, 4:idc.FF_DWORD, 2:idc.FF_WORD, 1:idc.FF_BYTE}
        flags |= d[size]

        if len(name) == 0:
            name = "field_{:X}".format(self.size if offset == idc.BADADDR else offset)
        # create member
        r = ida_struct.add_struc_member(self._struct, name, offset, flags, None, size)
        if r != 0:
            raise ValueError("Unable to add member {} (size={}) in {}".format(name, size, self))

        # get member and add comment if needed
        mm = self[name]
        if comment is not None:
            mm.comment = comment
        return mm

    def add_varsize(self, name, comment=None):
        """
            Add a variable size new member at the end of the structure.

            :param str name: The name of the field to add.
            :param str comment: Optional parameter which allow to add a
                comment associated with the new member.
            :raise ValueError: If an error occur when adding the member.
            :return: An :class:`BStructMember` object corresponding to the
                member added.
        """
        flags = idc.FF_DATA
        r = ida_struct.add_struc_member(self._struct, name, -1, flags, None, 0)
        if r != 0:
            raise ValueError("Unable to add variable size member {} in {}".format(name, self))

        # get member and add comment if needed
        mm = self[name]
        if comment is not None:
            mm.comment = comment
        return mm

    def fill(self, size, prefix='field_'):
        """
            Add new members to the structure until it reach
            ``size`` . Thie function add field the size of a pointer
            at the end of the structure.

            :param int size: The size in bytes wanted for the structure.
            :param str prefix: Prefix for the name of the structure member.
                Default is ``field_`` .
        """
        offset = self.size
        ptr_sz = BipIdb.ptr_size() // 8

        # start ptr by ptr
        while offset < size - ptr_sz + 1:
            self.add("{}{:X}".format(prefix, offset), ptr_sz)
            offset += ptr_sz

        # finish byte per byte
        while offset < size:
            self.add("{}{:X}".format(prefix, offset), 1)
            offset += 1

    ########################### GET & CREATE STRUCT ########################

    @classmethod
    def get(cls, name):
        """
            Class method allowing to get a :class:`BipStruct` object from the
            name of an existing structure.

            .. todo:: support providing a sid directly instead of a name ?

            .. todo:: support typedef on struct

            :param str name: The name of the structure to get.
            :raise ValueError: if the structure ``name`` does not exist.
            :return: A :class:`BipStruct` object corresponding to the structure
                identified by the name provided.
        """
        sid = ida_struct.get_struc_id(name)
        if sid == idc.BADADDR:
            raise ValueError('Struct {} does not exists'.format(name))

        return cls(ida_struct.get_struc(sid))

    @classmethod
    def create(cls, name):
        """
            Class method allowing to create a new empty struct.

            :param str name: The name of the structure to create.
            :raise ValueError: If the structure ``name`` already exist.
            :raise BipError: If it was not possible to create the structure.
            :rtype: A :class:`Struct` object.
        """
        sid = ida_struct.get_struc_id(name)
        if sid != idc.BADADDR:
            raise ValueError('Struct {} already exists'.format(name))

        sid = ida_struct.add_struc(idc.BADADDR, name, 0)
        if sid == idc.BADADDR:
            raise BipError("Impossible to create structure with name={}".format(name))
        return cls(ida_struct.get_struc(sid))

    @classmethod
    def exist(cls, name):
        """
            Class method for checking if a struct with a name exist. Return
            True if it does, False otherwise.

            :param str name: The name of the structure to test.
        """
        return ida_struct.get_struc_id(name) != idc.BADADDR

    @classmethod
    def iter_all(cls):
        """
            Class method allowing to iter on all the struct define in the IDB.

            :return: A generator of :class:`BipStruct`.
        """
        for i in range(ida_struct.get_first_struc_idx(), ida_struct.get_struc_qty()):
            sid = ida_struct.get_struc_by_idx(i)
            if sid == idc.BADADDR:
                continue # error
            yield cls(ida_struct.get_struc(sid))

    @staticmethod
    def delete(name):
        """
            Static method allowing to delete a struct by its name.

            :param str name: The name of the structure to delete.
            :raise ValueError: If the structure ``name`` does not exist.
            :raise RuntimeError: If it was not possible to delete the
                strucutre.
        """
        sid = ida_struct.get_struc_id(name)
        if sid == idc.BADADDR:
            raise ValueError('Struct {} does not exists'.format(name))

        if not ida_struct.del_struc(ida_struct.get_struc(sid)):
            raise RuntimeError("Unable to delete structure {}".format(name))


class BStructMember(BipRefElt):
    """
        Class for representing and manipulating a member of an
        :class:`BipStruct` structure.

        .. todo:: flags

        .. todo:: implement comparaison with other members (mid) and test for
            presence in a struct.
    """

    def __init__(self, member, istruct=None):
        """
            Constructor for a :class:`BStructMember` object. There is no
            reason this constructor should be used.

            There is few reason to use directly this constructor except for
            interfacing directly with IDA.

            :param member: A ``member_t`` object from ida corresponding to
                this member or a member id (int, long) corresponding to this
                member.
            :param istruct: A :class:`BipStruct` object corresponding to
                the structure from which member this member is part of. If it
                is ``None`` the structure will found dynamically.
            :raise ValueError: If the parameter is incorrect.
        """
        if isinstance(member, (int, long)):
            tmp = ida_struct.get_member_by_id(member)
            if tmp is None:
                raise ValueError("{} is not a member id".format(member))
            super(BStructMember, self).__init__(member)
            member = tmp[0]
            if istruct is None:
                istruct = BipStruct(tmp[2])
        elif isinstance(member, ida_struct.member_t):
            super(BStructMember, self).__init__(member.id)
            if istruct is None:
                tmp = ida_struct.get_member_by_id(member.id)
                if tmp is None:
                    raise ValueError("{} is not a member id".format(member.id))
                istruct = BipStruct(tmp[2])
        else:
            raise ValueError("BStructMember invalid member: {}".format(member))
        #: ``member_t`` object from ida corresponding to this member.
        self._member = member
        #: :class:`BipStruct` parent of this member.
        self.struct = istruct

    @classmethod
    def _is_this_elt(cls, idelt):
        """
            Return true if ``idelt`` correspond to a mid.
        """
        return cls._is_member_id(idelt)

    @property
    def _mid(self):
        """
            Property which return the member id corresponding to this object.
            This is used internally by IDA and there should be few reason to
            use this except for interfacing with IDA native interface.
        """
        return self._member.id

    @property
    def name(self):
        """
            Property which return the name of this member.
        """
        return ida_struct.get_member_name(self._mid)

    @name.setter
    def name(self, value):
        """
            Setter for the name of this member.

            :param str value: The new name of this member.
            :raise ValueError: If an error occured during the setting of the
                name.
        """
        if not ida_struct.set_member_name(self.struct._struct, self.offset, value):
            raise ValueError("Impossible to set name {} for {}".format(value, self))

    @property
    def fullname(self):
        """
            Property which return the full name of this member. The fullname
            correspond to the struct name follow by the name of this member
            seperated by a point: ``STRUCT.MEMBER`` .
        """
        return ida_struct.get_member_fullname(self._mid)

    @property
    def size(self):
        """
            Property which return the size of this member as an integer.
        """
        return ida_struct.get_member_size(self._member)

    @size.setter
    def size(self, value):
        """
            Setter for the size of a member.

            :param value: The size to set in bytes (1, 2, 4 or 8), if 0 is set,
                this will set the member as being of variable size.
            :raise RuntimeError: If it was not possible to set the size for the
                member. This typically occurs when another member is define
                after it, or if setting a variable size not at the end of a
                structure.
            :raise ValueError: If the value parameter is not correct.
        """
        if value not in (0, 1, 2, 4, 8):
            raise ValueError("Size to set for BStructMember.size is not valid")
        flags = idc.FF_DATA
        d= {8:idc.FF_QWORD, 4:idc.FF_DWORD, 2:idc.FF_WORD, 1:idc.FF_BYTE, 0:0}
        flags |= d[value]
        if not ida_struct.set_member_type(self.struct._struct, self.offset, flags, None, value):
            raise RuntimeError("Unable to set size for member {}".format(self.fullname))


    @property
    def offset(self):
        """
            Property providing access to the start offset of this member in
            the structure as an integer.
        """
        return self._member.soff

    @property
    def end_offset(self):
        """
            Property which return the end offset of this member as an integer.
            This should be equivalent to use ``offset + size`` .
        """
        return self._member.eoff

    def __str__(self):
        return "Member: {} (offset=0x{:X}, size=0x{:X})".format(self.fullname, self.offset, self.size)

    ############################# COMMENTS ################################

    @property
    def comment(self):
        """
            Return the comment associated with this member as a string.
        """
        return ida_struct.get_member_cmt(self._mid, 0)

    @comment.setter
    def comment(self, value):
        """
            Setter for the comment associated with this member.

            :param str value: The new comment for this member.
        """
        if value is None:
            value = ""
        ida_struct.set_member_cmt(self._member, value, 0)

    @property
    def rcomment(self):
        """
            Return the repeatable comment associated with this member as a
            string.
        """
        return ida_struct.get_member_cmt(self._mid, 1)

    @rcomment.setter
    def rcomment(self, value):
        """
            Setter for the repeatable comment associated with this member.

            :param str value: The new comment for this member.
        """
        if value is None:
            value = ""
        ida_struct.set_member_cmt(self._member, value, 1)

    ################################ TYPES ################################

    @property
    def has_type(self):
        """
            Property which return True if this member as a type defined (which
            can be recuperated through :meth:`BStructMember.type`) False if
            no type is defined for this member.
        """
        return self._member.has_ti()

    @property
    def type(self):
        """
            Property which return an object which inherit from
            :class:`~bip.base.biptype.BipType` and represent the type of this member.

            :raise RuntimeError: If it was not possible to get the type of
                this member, this may happen in particular if
                :meth:`~BStructMember.has_type` returned false.
        """
        ti = ida_typeinf.tinfo_t()
        if not ida_struct.get_member_tinfo(ti, self._member):
            raise RuntimeError("Could not get the type for {}".format(self))
        return bip.base.biptype.BipType.from_tinfo(ti)

    def del_type(self):
        """
            Method which allow to delete the type for this member.

            .. todo:: handle failure
        """
        ida_struct.del_member_tinfo(self.struct._struct, self._member)

    def set_type(self, new_type, userspecified=True, may_destroy=False,
            compatible=False, funcarg=False, bytil=False):
        """
            Method which allow to change the type of this member.

            :param new_type: An object which inherit from :class:`~bip.base.biptype.BipType`
                which represent the new type for this member.
            :param bool userspecified: Is this type specified by the user,
                True by default.
            :param bool may_destroy: Is the setting of this type can destroy
                other members of the struct, default is False.
            :param bool compatible: The new type should be compatible with
                the previous one. Default is False.
            :param bool funcarg: Is the member used as argument of a function,
                in particular this forbid the setting of array. Default is
                False.
            :param bool bytil: The new type was created by the type subsystem.
                Default False.
            :raise RuntimeError: If setting the type failed.
            :raise TypeError: If the argument is not an :class:`~bip.base.biptype.BipType` object.
        """
        if not isinstance(new_type, bip.base.biptype.BipType):
            raise TypeError("BStructMember.set_type setter expect an object which inherit from BipType")
        # compute the flags, from SET_MEMTI_* in struct.hpp
        flags = 0
        if userspecified:
            flags |= 0x10
        if may_destroy:
            flags |= 0x01
        if compatible:
            flags |= 0x02
        if funcarg:
            flags |= 0x04
        if bytil:
            flags |= 0x08
        if not ida_struct.set_member_tinfo(self.struct._struct, self._member, 0, new_type._get_tinfo_copy(), flags):
            raise RuntimeError("Unable to set type {} for this {}".format(value, self))

    @type.setter
    def type(self, value):
        """
            Setter for changing the type of this member. If ``value`` is
            ``None`` the type is deleted instead.

            This will set the type as being a user-specified type and will not
            destroy other members. For more specific change of type see
            :meth:`BStructMember.set_type` method.

            .. note::

                This will create a copy of the type for avoiding problem with
                the IDA interface. See :class:`~bip.base.biptype.BipType` for more information.

            :param value: An object which inherit from :class:`~bip.base.biptype.BipType` which
                represent the new type for this member or a string
                representing a declaration in C.
            :raise RuntimeError: If setting the type failed.
            :raise TypeError: If the argument is not None, a string or a
                :class:`~bip.base.biptype.BipType` object.
        """
        if value is None:
            self.del_type()
            return
        if isinstance(value, (str, unicode)):
            value = bip.base.biptype.BipType.from_c(value)
        self.set_type(value)

    @property
    def is_nested(self):
        """
            Return True if this member represent a nested struct included
            inside the current one. The structure can be recuperated using
            :meth:`~BStructMember.nested_struct` .
        """
        return ida_struct.get_sptr(self._member) is not None

    @property
    def nested_struct(self):
        """
            If this member represent a nested structure this property allows
            to get the :class:`BipStruct` corresponding to the nested struct.
            
            :raise RuntimeError: If this member does not have a nested struct.
                This can be tested using :meth:`~BStructMember.is_nested`.
            :return: An :class:`BipStruct` object corresponding to the nested
                struct.
        """
        st = ida_struct.get_sptr(self._member)
        if st is None:
            raise RuntimeError("{} does not represent a nested struct".format(self))
        return BipStruct(st)

    ########################### STATIC METHODS #######################

    @staticmethod
    def _is_member_id(mid):
        """
            Allow to check if an id (address) from IDA represent a member id.
            This is a wrapper on ``ida_struct.is_member_id`` and there should
            not be any reason to use this method except for interfacing with
            the IDAPython interface.

            :param int mid: The id to check for being a member id.
            :return: ``True`` if ``mid`` is a member id which can be used for
                getting a :class:`BStructMember` object, ``False`` otherwise.
        """
        return ida_struct.is_member_id(mid)

    @classmethod
    def _from_member_id(cls, mid):
        """
            Class method for getting a :class:`BStructMember` object from an
            id which  represent a member in IDA. There should be no reason to
            use this method except for interfacing with the IDAPython
            interface.

            :param int mid: The member id to convert to a
                :class:`BStructMember`.
            :raise ValueError: If the argument ``mid`` is not a valid member
                id. This can be check using the static method
                :meth:`~BStructMember._is_member_id` .
            :return: A :class:`BStructMember` object corresponding to the
                member with id ``mid``.
        """
        tmp = ida_struct.get_member_by_id(mid)

        if tmp is None:
            raise ValueError("{} is not a member id".format(mid))

        return cls(tmp[0], BipStruct(tmp[2]))

