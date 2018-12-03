from idaapi import *
from idc import *
from idautils import *

from bip.base import get_ptr_size
from biperror import BipError

E_NOTFOUND = 0xFFFFFFFFFFFFFFFF

class Struct(object):
    """
        Class for representing and manipulating a structure in IDA.
        Static functions :func:`~Struct.create` and :func:`~Struct.get` allow
        to easilly get an instance of those object.

        .. todo::
            
            Should make this accessible by the xref. Maybe inherit from
            IdaElt ?
    """
    def __init__(self, sid, name):
        """
            Constructor for a :class:`Struct` object. There is few reason
            to directly use this constructor, see functions
            :func:`~Struct.get` or :func:`~Struct.create`.
        
            .. todo:: Should probably only take sid in param and make name a property

            :param int sid: The structure id from IDA such as return by
                ``GetStrucIdByName`` .
            :param str name: The name of the structure.
        """
        self.sid = sid #: Structure id representing the structure in IDA.
        self.name = name #: Name of the structure.

    @property
    def size(self):
        """
            Property returning the size of the structure.

            :rtype: int
        """
        return int(GetStrucSize(self.sid))

    def add_ptr_field(self, name, comment=None):
        """
            Add a new member with the size of a poitner at the end of
            the structure.

            :param str name: the name of the field to add.
            :param str comment: optional parameter which allow to provide a comment to associate with a member.
        """
        ptr_sz = get_ptr_size()/8
        flag = ({8:FF_QWRD, 4:FF_DWRD, 2:FF_WORD}[ptr_sz])|FF_DATA
        
        AddStrucMember(self.sid, name, -1, flag, -1, ptr_sz)

        if comment:
            SetMemberComment(self.sid, GetStrucSize(self.sid)-1, comment, True)
    
    def fill(self, size, prefix='field_'):
        """
            Add new members to the structure until it reach at least
            ``size`` . Thie function add field the size of a pointer
            at the end of the structure. The structure at the end can
            be bigger than the ``size`` parameter.

            .. todo:: handle the exact size

            :param int size: the size wanted for the structure.
            :param str prefix: prefix for the name of the structure member. Default is ``field_`` .
        """
        offset = self.size
        ptr_sz = get_ptr_size()/8

        flag = ({8:FF_QWRD, 4:FF_DWRD, 2:FF_WORD}[ptr_sz])|FF_DATA
        
        while offset < size:
            AddStrucMember(self.sid, "{}{:X}".format(prefix, offset), -1, flag, -1, ptr_sz)
            offset += ptr_sz

    @property
    def members(self):
        """
            Property returning an iterable of
            :class:`~StructField` representing the different
            members of this struct.

            :rtype: iterable of :class:`~StructField` object.
        """
        for f in StructMembers(self.sid):
            yield StructField.from_struct(self, f[0])
            
    @staticmethod
    def create(name):
        """
            Static method allowing to create a new empty struct.

            :param str name: the name of the structure to create.
            :raise ValueError: if the structure ``name`` already exist.
            :rtype: a :class:`Struct` object.
        """
        sid = GetStrucIdByName(name)
        if sid != E_NOTFOUND:
            raise ValueError('struct already exists')
        
        sid = AddStrucEx(-1, name, 0)
        if sid == 0xffffffffffffffff:
            raise BipError("Impossible to create structure with name={}".format(name))
        return Struct(sid, name)
                
    @staticmethod
    def get(name):
        """
            Static method allowing to get a :class:`Struct` object on
            an already existing structure.

            :param str name: the name of the structure to get.
            :raise ValueError: if the structure ``name`` does not exist.
            :rtype: a :class:`Struct` object.
        """
        sid = GetStrucIdByName(name)
        if sid == E_NOTFOUND:
            raise ValueError('struct doesnt exists')

        return Struct(sid, name)

class StructField(object):
    """
        Class for representing and manipulating a member of an IDA
        structure. Static method :func:`~StructField.from_struct` allow
        to easily get one this object.

        .. todo:: make an example here

        .. todo:: why not make ``comment`` and ``size`` a property ? and in
                fact everythingm except maybe the m_id or the offset (with the
                sid ?
    """
    def __init__(self, m_id, name, offset, size, struct, flags, comment=""):
        """
            Constructor for a :class:`StructField` object.

            :param int m_id: The member id from IDA which represent
            this field such as return by ``GetMemberId`` .
            :param str name: The name of this field.
            :param int offset: The position inside the structure of
            this field.
            :param int size: The size of the field.
            :param struct: An object representing the structure in
            which this field is included.
            :type struct: a :class:`Struct` object.
            :param int flags: Flags for this field such as returned by
            ``GetMemberFlag`` .
            :param str comment: An optional parameter representing the
            comment associated with this field.
        """
        self.name = name #: The name of this field.
        self.offset = offset #: The offset in the parent structure.
        self.size = size #: The size in bytes of this field.
        self.struct = struct #: The parent structure in which this object is included (:class:`Struct`).
        self.flags = flags #: The flags as used in IDA.
        self.comment = comment #: The comment for this field.
        self.m_id = m_id #: The member id representing this field in IDA.

    @property
    def type(self):
        """
            Property returning the type of this field. In case of
            error this method will return ``None`` (this should not
            happen).

            :rtype: ``str`` or ``None``
        """
        t = GetType(self.m_id)
        common_types = {
            8: "_QWORD",
            4: "_DWORD",
            2: "_WORD",
            1: "_BYTE"
        }

        if t is None and self.size in common_types:
            t = common_types[self.size]
        return t

    def to_dict(self):
        """
            Recuperate information about this field as a dictionnary.
            Field of the dictionnary are:

            * ``name`` (``str``): the name of this field.
            * ``offset`` (``int``): the offset of this field.
            * ``size`` (``int``): the size of this field.
            * ``comment`` (``str``): the comment of this field, empty string if no comment.
            * ``type`` (``str``): the type of this field.

            :rtype: dict()
        """
        return {
            'name':self.name,
            'offset':self.offset,
            'size':self.size,
            'comment':self.comment,
            'type':self.type
        }
    
    @staticmethod
    def from_struct(struct, offset):
        """
            Static method which allow to recuperate a
            :class:`StructField` object from a structure and an offset
            in it.

            .. todo:: what happens when this fail ?

            :param struct: object representing the structure containing
            the field to recuperate.
            :type struct: :class:`Struct`
            :param int offset: offset in the structure at which is 
            present the member to get.
            :return: An object representing a member in the structure.
            :rtype: :class:`StructField`
        """
        name = GetMemberName(struct.sid, offset)
        # assume rpt comment
        comment = GetMemberComment(struct.sid, offset, 1)
        flags = GetMemberFlag(struct.sid, offset)
        size = GetMemberSize(struct.sid, offset)
        m_id = GetMemberId(struct.sid, offset)
        return StructField(m_id, name, offset, size, struct, flags, comment)


