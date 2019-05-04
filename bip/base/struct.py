import idc
import idautils
import ida_struct
import ida_typeinf

from .type import IdaType
from bip.base import get_ptr_size
from biperror import BipError

class IdaStruct(object):
    """
        Class for representing and manipulating a structure in IDA.
        Static functions :func:`~IdaStruct.create` and :func:`~IdaStruct.get` allow
        to easilly get an instance of those object.

        .. todo::
            
            Should make this accessible by the xref. Maybe inherit from
            IdaElt ?

        .. todo:: get/set alignement

        .. todo:: allow to iterate on all structure and other stuff like that

        .. todo:: allow to access child struct

        .. todo:: test

    """

    ############################ BASE ###########################

    def __init__(self, struct_t):
        """
            Constructor for a :class:`IdaStruct` object. There is few reason
            to directly use this constructor, see functions
            :func:`~IdaStruct.get` or :func:`~IdaStruct.create`.

            :param struct_t: A structure ``struc_t`` from IDA such as return
                by ``get_struc`` .
        """
        #: Internal ``struct_t`` object from IDA.
        self._struct = struct_t

    @property
    def _sid(self):
        """
            Property which return the sid for this :class:`IdaStruct` object. The
            sid is the struct id number (``tid_t``) from IDA and there is no
            reason it should be used except for interfacing with the standard
            API from IDA.

            :return: An int corresponding to the sid.
        """
        return self._struct.id

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
            For repeatable comment see :meth:`~IdaStruct.rcomment`
        """
        return ida_struct.get_struc_cmt(self._sid, 0)

    @comment.setter
    def comment(self, value):
        """
            Setter which allow to set a comment associated with this
            :class:`IdaStruct` object.

            :param str value: The new comment to associate with this object.
        """
        ida_struct.set_struc_cmt(self._sid, value, 0)

    @property
    def rcomment(self):
        """
            Property which return the repeatable comment associated with this
            :class:`IdaStruct` object.
        """
        return ida_struct.get_struc_cmt(self._sid, 1)

    @rcomment.setter
    def rcomment(self, value):
        """
            Setter which allow to set a repeatable comment for :class:`IdaStruct`
            object.

            :param str value: The new comment to associate with this object.
        """
        ida_struct.set_struc_cmt(self._sid, value, 1)

    ############################ MEMBERS ###########################

    @property
    def nb_members(self):
        """
            Property which return the number of members in this
            :class:`IdaStruct` object.
        """
        return self._struct.memqty

    @property
    def members(self):
        """
            Property which return a list of :class:`IStructMember` objects
            representing the members of this structure.

            :rtype: A list of :class:`IStructMember` object.
        """
        return [IStructMember(self._struct.get_member(i), self) for i in range(self.nb_members)]

    @property
    def members_iter(self):
        """
            Property returning an iterable of
            :class:`IStructMember` representing the different
            members of this struct. This is similar to :meth:`IdaStruct.members`.

            .. todo:: maybe delete this ? I am worried because of the
                get_member property which may create problem if the number of
                members change during the iteration.

            :rtype: Iterable of :class:`IStructMember` object.
        """
        for i in range(self.nb_members):
            # WARNING: get_member does not check for bound in IDA
            #   implementation, possible to access adjacent memory.
            yield IStructMember(self._struct.get_member(i), self)

    def member_at(self, off):
        """
            Method which return the member of this :class:`IdaStruct` at the
            offset provided in argument. This will return the correct member
            even if the offset is not aligned.

            :param int off: The offset of the member to get.
            :raise ValueError: If the member was not found (offset bigger than
                the struct).
            :return: An :class:`IStructMember` object corresponding to the
                member.
        """
        mm = ida_struct.get_member(self._struct, off)
        if mm is None:
            raise ValueError("Member at offset {} does not seems to exist in {}".format(off, self))
        return IStructMember(mm, self)

    def member_by_name(self, name):
        """
            Method which return the member of this :class:`IdaStruct` from its
            name.

            :param str name: The name of the member to get.
            :raise ValueError: If the member was not found.
            :return: An :class:`IStructMember` object corresponding to the
                member.
        """
        mm = ida_struct.get_member_by_name(self._struct, name)
        if mm is None:
            raise ValueError("Member {} does not seems to exist in {}".format(name, self))
        return IStructMember(mm, self)

    def __getitem__(self, key):
        """
            Getitem method which allow access to the members of the struct.

            :param key: If key is a string it will search the member by name,
                if it is a integer it will search the member by offset.
            :raise ValueError: If the member was not found.
            :raise TypeError: If ``key`` is not an integer or a string.
            :return: An :class:`IStructMember` object corresponding to the
                member.
        """
        if isinstance(key, (int, long)):
            return self.member_at(key)
        elif isinstance(key, (str, unicode)):
            return self.member_by_name(key)
        else:
            raise TypeError("IdaStruct.__getitem__ expect a integer or a string as key, got: {}".format(key))

    def add(self, name, size, comment=None):
        """
            Add a new member at the end of the structure.

            :param str name: The name of the field to add.
            :param int size: The size of the field to add in bytes,
                can be 1, 2, 4 or 8.
            :param str comment: Optional parameter which allow to add a
                comment associated with the new member.
            :raise TypeError: If one argument is not of the correct type or
                with the correct value.
            :raise ValueError: If an error occur when adding the member.
            :return: An :class:`IStructMember` object corresponding to the
                member added.
        """
        if size not in (1, 2, 4, 8) or not isinstance(name, (str, unicode)):
            raise TypeError("Invalid type for adding in {}".format(self))
        # compute flags
        flags = idc.FF_DATA
        d= {8:idc.FF_QWRD, 4:idc.FF_DWRD, 2:idc.FF_WORD, 1:idc.FF_BYTE}
        flags |= d[size]
        
        # create member
        r = ida_struct.add_struc_member(self._struct, name, -1, flags, None, size)
        if r != 0:
            raise ValueError("Unable to add member {} (size={}) in {}".format(name, size, self))

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
        ptr_sz = get_ptr_size()/8

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
            Class method allowing to get a :class:`IdaStruct` object from the
            name of an existing structure.

            .. todo:: support providing a sid directly instead of a name ?
            
            .. todo:: support typedef on struct

            :param str name: The name of the structure to get.
            :raise ValueError: if the structure ``name`` does not exist.
            :return: A :class:`IdaStruct` object corresponding to the structure
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
        
        sid = ida_struct.add_struc(-1, name, 0)
        if sid == idc.BADADDR:
            raise BipError("Impossible to create structure with name={}".format(name))
        return cls(ida_struct.get_struc(sid))

                

class IStructMember(object):
    """
        Class for representing and manipulating a member of an
        :class:`IdaStruct` structure.

        .. todo:: flags

        .. todo:: link to child struct for embedded struct.
    """

    def __init__(self, member, istruct):
        """
            Constructor for a :class:`IStructMember` object. There is no
            reason this constructor should be used.

            There is few reason to use directly this constructor except for
            interfacing directly with IDA.

            :param member: A ``member_t`` object from ida corresponding to
                this member.
            :param istruct: A :class:`IdaStruct` object corresponding to
                the structure from which member this member is part of.
        """
        self._member = member
        #: :class:`IdaStruct` parent of this member.
        self.struct = istruct

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
        ida_struct.set_member_cmt(self._member, value, 1)

    @property
    def has_type(self):
        """
            Property which return True if this member as a type defined (which
            can be recuperated through :meth:`IStructMember.type`) False if 
            no type is defined for this member.
        """
        return self._member.has_ti()

    @property
    def type(self):
        """
            Property which return an object which inherit from
            :class:`IdaType` and represent the type of this member.

            :raise RuntimeError: If it was not possible to get the type of
                this member, this may happen in particular if
                :meth:`~IStructMember.has_type` returned false.
        """
        ti = ida_typeinf.tinfo_t()
        if not ida_struct.get_member_tinfo(ti, self._member):
            raise RuntimeError("Could not get the type for {}".format(self))
        return IdaType.GetIdaType(ti)

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

            :param new_type: An object which inherit from :class:`IdaType`
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
            :raise TypeError: If the argument is not an :class:`IdaType` object.
        """
        if not isinstance(new_type, IdaType):
            raise TypeError("IStructMember.set_type setter expect an object which inherit from IdaType")
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
            :meth:`IStructMember.set_type` method.

            .. note::
            
                This will create a copy of the type for avoiding problem with
                the IDA interface. See :class:`IdaType` for more information.

            :param value: An object which inherit from :class:`IdaType` which
                represent the new type for this member.
            :raise RuntimeError: If setting the type failed.
            :raise TypeError: If the argument is not None or an
                :class:`IdaType` object.
        """
        if value is None:
            self.del_type()
            return
        self.set_type(value)

    #def to_dict(self):
    #    """
    #        Recuperate information about this field as a dictionnary.
    #        Field of the dictionnary are:

    #        * ``name`` (``str``): the name of this field.
    #        * ``offset`` (``int``): the offset of this field.
    #        * ``size`` (``int``): the size of this field.
    #        * ``comment`` (``str``): the comment of this field, empty string if no comment.
    #        * ``type`` (``str``): the type of this field.

    #        :rtype: dict()
    #    """
    #    return {
    #        'name':self.name,
    #        'offset':self.offset,
    #        'size':self.size,
    #        'comment':self.comment,
    #        'type':self.type
    #    }
    #
