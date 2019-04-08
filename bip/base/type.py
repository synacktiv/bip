"""
    File for basic type gestion. In particular this contain the wrapper on top
    of the type implementation in IDA (typeinf). In particular this contain
    the abstraction on top of the ``tinfo_t`` (:class:`IdaType`).

    .. todo:: explain here the recursive concept of the implementation.
        Provide a representation of the class hierarchy.

    .. todo:: fix the problem of the bellow ptr which change, the easiest way is
        to duplicate the type when creating the object which could be done 
        in the GetIdaType function directly (with another for creating a type
        without a copy ?). This seems to work even if we copy a ptr (subjacent
        type will also be copied but it is necessary to test when doing change
        using the API). But that technics will be way more painfull
        to use on the other API (everything will be by copy) so maybe not the
        best way to do it. Black magic python is probably possible but not sure
        what the best way (dynamic change of properties and methods, will disable
        the test by class, change of parent class (with double inheritance) maybe
        possible but could create really wierd case).

    .. todo:: once the previous problem is fix the implementation should be
        documented and usage with example should be provided.

    .. todo:: remove comment and useless notes about implementation.

    .. todo:: support creation of the type

    .. todo:: Bitfield implementation ?

    .. todo:: link to important part:
        
        * lvar
        * hxcfunc
        * HxCStmt/HxCExpr ? (and CNode ?)
        * func
        * struct
        * data (in particular globals)
        * stack (once implemented)
        * operand/instruction ?
        * call ?
"""

from ida_typeinf import tinfo_t, array_type_data_t, func_type_data_t, udt_type_data_t, enum_type_data_t


# The tinfo_t class will have to be recursive...
# Need to allow to create tinfo "by hand" and to create them from a C string.

# Example for getting a tinfo_t is the HxLvar._ida_tinfo property

class IdaType(object):
    """
        Abstract class for representing a ``tinfo_t`` object from ida in bip.
        All basic types are subclasses of this one, the class name start with
        the prefix ``IType``:

        * :class:`ITypeInt` : an integer (signed or unsigned with different size)
        * TODO

        .. todo:: precise "basic types" and more complex, also doc. which one
            have childs and which do not.

        The objects which inherit from :class:`IdaType` can contain other
        *child* :class:`IdaType` objects. For example a pointer (TODO class
        name in bip) will contain one child object corresponding to the
        pointed type. The :meth:`childs` property allow to get a list of the
        child object.

        .. note::
            
            No representation of a ``type_t`` is directly supported in bip.
            A ``type_t`` is only a bit field of one byte which indicate the
            basic type of the IDA object with some flags. This is directly
            mask by bip.

        .. todo:: allow test
        
        .. todo:: test this

        .. todo:: allow creation of types

        .. todo::
        
            General todo for types:
            
            * SSE
            * const
    """


    ############################# BASE ####################################

    def __init__(self, tinfo):
        """
            Base constructor for the child classes of :class:`IdaType`. This
            constructor is used for interfacing with IDA and initializing. A
            bip user should probably used the :func:`IdaType.GetIdaType`
            function which will directly create the object of the correct
            class.

            :param tinfo: The ``tinfo_t`` representing the type in IDA.
        """
        #: Internal object which correspond to the ``tinfo_t`` object
        #:  equivalent to this object in IDA.
        self._tinfo = tinfo

    @property
    def size(self):
        """
            Property which return the number of bytes in this type.
        """
        return self._tinfo.get_size()

    @property
    def str(self):
        """
            Property which return the C String equivalent to the type of this
            object. It will take into account the child type. This
            should never be empty (except for unknown ? TODO test).

            :return: A string which represent the type as in C.
        """
        return self._tinfo.dstr()

    @property
    def is_named(self):
        """
            Return true if this type has a name. This can be because of a
            typedef, a structure declaration, ... The name can be recuperated
            with the :meth:`IdaType.name` property.
        """
        return self._tinfo.get_type_name() is not None

    @property
    def name(self):
        """
            Property which return the name of this type if it has one. A type
            can a name because of a typedef, a structure, ... If it does not
            have one this property will return an empty string. The presence
            of a named can be tested using the :meth:`IdaType.is_named`
            property.

            :return: A string corresponding to the name of this type. Empty
                if this type does not have a name.
        """

        return self._tinfo.get_type_name()

    ############################# CHILDS INJECTION ##########################

    @property
    def childs(self):
        """
            Property which return a list of childs types. All elements of this
            list will be object which inherit from :class:`IdaType`.

            :return: A list of object inheriting from :class:`IdaType`
                which are "child" of this type.
        """
        return []


    ########################### OBJECT CREATION ############################

    @classmethod
    def is_handling_type(cls, tinfo):
        """
            Class method which allow to test if this class support a
            particular type info (IDA ``tinfo_t``). Return True if the
            function handle the type, false otherwise.

            :param tinfo: A ``tinfo_t`` swig object from idapython.
            :return: A boolean.
        """
        return False

    @staticmethod
    def GetIdaType(tinfo):
        """
            Function which convert a ``tinfo_t`` object from ida to one of the
            child object of :class:`IdaType` . This should be used for
            converting the type from IDA into their correct object for bip.
            This function is used as an interface with the IDA object.
    
            If no :class:`IdaType` child object supports the ``tinfo_t`` a
            ``ValueError`` exception will be raised. Internally this use
            the :func:`~IdaType._GetClassIdaType` function.
            
            This create a **copy** of the underlying ``tinfo_t`` object, this
            allow to avoid problems if when using the IdaPython API or the GUI
            from IDA the type is change. This is a problem because it means
            bip should dynamically change the class of the object and even if
            possible this will create an error prone API. Instead types are
            handle by copy instead of by reference, and interface with other
            bip object take this into account. For creating an object of the
            correct class without a copy the :func:`~IdaType.GetIdaTypeNoCopy`
            can be used by is subject to the above problems.
    
            :param tinfo: A ``tinfo_t`` from ida.
            :return: The equivalent object to the ``tinfo_t`` for bip. This
                will be an object which inherit from :class:`IdaType` .
        """
        return IdaType._GetClassIdaType(tinfo)(tinfo_t(tinfo))


    @staticmethod
    def GetIdaTypeNoCopy(tinfo):
        """
            Function which convert a ``tinfo_t`` object from ida to one of the
            child object of :class:`IdaType` .
    
            If no :class:`IdaType` child object supports the ``tinfo_t`` a
            ``ValueError`` exception will be raised. Internally this use
            the :func:`~IdaType._GetClassIdaType` function.
            
            .. warning::
            
                This function does **not** create a copy of the underlying
                ``tinfo_t`` object which can create several problems when
                using the GUI or the IdaPython/IDC API. For creating a copy
                of the object use the :func:`~IdaType.GetIdaType` instead.
    
            :param tinfo: A ``tinfo_t`` from ida.
            :return: The equivalent object to the ``tinfo_t`` for bip. This
                will be an object which inherit from :class:`IdaType` .
        """
        return IdaType._GetClassIdaType(tinfo)(tinfo)

    @staticmethod
    def _GetClassIdaType(tinfo):
        """
            Internal function which allow to recuperate the correct child
            class of :class:`IdaType` corresponding to  ``tinfo_t`` object
            from ida. This is used internally for converting the type from IDA
            into their correct object for bip.
            This function is used as an interface with the IDA object.
    
            If no :class:`IdaType` child object supports the ``tinfo_t`` a
            ``ValueError`` exception will be raised.
    
            .. todo:: maybe return None instead of raising an exception ?

            :param tinfo: A ``tinfo_t`` from ida.
            :return: The bip class which should be used as equivalent for
                the ``tinfo_t`` provided as argument. This
                will be an object which inherit from :class:`IdaType` .
        """
        done = set()
        todo = set(IdaType.__subclasses__())
        while len(todo) != 0:
            cl = todo.pop()
            if cl in done:
                continue
            if cl.is_handling_type(tinfo):
                return cl
            else:
                done.add(cl)
                todo |= set(cl.__subclasses__())
        raise ValueError("GetHxCItem could not find an object matching the tinfo_t type provided ({})".format(tinfo))

    def _get_tinfo_copy(self):
        """
            Return a copy of the ida type (``tinfo_t``) represented by this
            object. This is an internal function which is used as an helper
            for setting the types of an element from a :class:`IdaType`

            :return: A copy of the ``tinfo_t`` represented by this object.
        """
        return tinfo_t(self._tinfo)

# TODO: unknown type

class ITypeVoid(IdaType):
    """
        Class which represent the :class:`IdaType` for a void. 

        .. todo:: test this more.
    """

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_void()

class ITypeInt(IdaType):
    """
        Class which represent the :class:`IdaType` for an integer, it can be
        signed or unsigned and may have different :meth:`~IdaType.size`.

        .. todo:: natural size integer
    """

    @property
    def is_signed(self):
        """
            Property which return True if the integer is signed and false if
            it is unsigned.
        """
        return self._tinfo.is_signed()

    @property
    def is_unsigned(self):
        """
            Property which return True if the integer is unsigned and false if
            it is signed.
        """
        return self._tinfo.is_unsigned()

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_int()

class ITypeBool(IdaType):
    """
        Class which represent the :class:`IdaType` for a boolean (``bool``).
        All boolean do not have the same :meth:`~IdaType.size` .
    """

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_bool()

class ITypeFloat(IdaType):
    """
        Class which represent the :class:`IdaType` for a float or a double.

        .. todo::
            
            There seems to be some wierd stuff with the size of float, see
            BT_FLOAT definition in typeinf.hpp.

        .. todo::
            
            Make a different class for double and float ? Check previous todo
            about size before doing that.
    """

    @property
    def is_double(self):
        """
            Property which return true if this type represent a double
            (by opposition to a float).
        """
        return self._tinfo.is_double()

    @property
    def is_float(self):
        """
            Property which return true if this type represent a float
            (by opposition to a double).
        """
        return self._tinfo.is_float()

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_floating()

class ITypePtr(IdaType):
    """
        Class which represent the :class:`IdaType` for a pointer. This is a
        recursive type, it is possible to have the pointed type with the
        property :meth:`pointed` .


    """

    @property
    def pointed(self):
        """
            Property which return the type pointed by this type.

            :return: An object which inherit from
                :class:`IdaType` class.
        """
        return IdaType.GetIdaType(self._tinfo.get_pointed_object())

    @property
    def is_pvoid(self):
        """
            Property which return true if this type is a pointer on void
            (``void *``).
        """
        return self._tinfo.is_pvoid()

    @property
    def is_pfunc(self):
        """
            Property which return true if this type is a pointer on a
            function.

            .. todo:: test
        """
        return self._tinfo.is_funcptr()

    @property
    def childs(self):
        return [self.pointed]

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_ptr()

class ITypeArray(IdaType):
    """
        Class which represent the :class:`IdaType` for an array (a *static*
        array: ``int[8]`` for example). This is a
        recursive type, it is poissible to have the type of the elements with
        the property :meth:`elt_type` .

        .. note::
        
            The array (and in particular the ``array_type_data_t`` from IDA)
            have a ``base`` property. Not really sure what that is, when or
            how it is used. It is possible to access it using
            :meth:`~ITypeArray._array_info` then accessing the property
            ``base`` if needed.
    """

    @property
    def _array_info(self):
        """
            Property which return ``array_type_data_t`` object from ida
            associated with this object. This is only for interfacing with
            IDA and should probably not be used directly from bip.

            This is used by the other method/property of
            :class:`ITypeArray` .
        """
        atd = array_type_data_t()
        self._tinfo.get_array_details(atd)
        return atd

    @property
    def elt_type(self):
        """
            Property which returns the type of the elements in the type array.

            :return: An object which inherit from
                :class:`IdaType` class.
        """
        return IdaType.GetIdaType(self._array_info.elem_type)

    @property
    def nb_elts(self):
        """
            Property which returns the number of elements in the type array.

            :return: An int.
        """
        return self._array_info.nelems

    @property
    def childs(self):
        return [self.elt_type]

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_array()

class ITypeFunc(IdaType):
    """
        Class which represent the :class:`IdaType` for a function. This is a
        recursive type, it is poissible to have the type of the return value
        using the :meth:`~ITypeFunc.return_type` property and the type of the
        arguments using the method :meth:`~ITypeFunc.get_arg_type` or the
        property :meth:`~ITypeFunc.args_type`.

        Other methods are available allowing to access the name of the
        arguments (:meth:`~ITypeFunc.get_arg_name`).
        
        .. todo:: complete description when more is implemented.

        .. todo:: test this!

        .. todo:: everything about arguments (ida_typeinf.funcarg_t):
            * location
            * cmt
            * flags
            * compare
        .. todo:: calling convention
        .. todo:: everything in func_type_data_t
        .. todo:: spoiled registers
        .. todo:: stack link (once stack is implemented)
        .. todo:: does function return ?
        .. todo:: flags for function type
        .. todo:: return location
        .. todo:: setter for arg (name, type, cmt, ...)
        .. todo:: setter for return value (type)
        .. todo:: the handling of the arguments may have to be change
        .. todo:: helper for if the function return void (and maybe other: a
            ptr and so on)
    """

    @property
    def _ida_func_type_data(self):
        """
            Internal property which allow to get the ``func_type_data_t`` for
            this type function.

            :return: the ``ida_typeinf.func_type_data_t`` for this object.
        """
        ftd = func_type_data_t()
        if not self._tinfo.get_func_details(ftd):
            raise BipError("Unable to get function details for function {}".format(self.name))
        return ftd

    def get_arg_name(self, pos):
        """
            Get the name of an argument.

            :param int pos: The position of the argument (start at 0).
            :return: The name of the argument at ``pos`` for this function
                type. If the argument does not have a name the empty string
                will be returned.
        """
        return self._ida_func_type_data[pos].name

    def get_arg_type(self, pos):
        """
            Get the :class:`IdaType` object corresponding to the type of an
            argument.

            .. todo:: handle the recuperation of an argument by name ?

            :return: An object which inherit from :class:`IdaType` class.
        """
        return IdaType.GetIdaType(self._ida_func_type_data[pos].type)

    @property
    def nb_args(self):
        """
            Property which return the number of arguments that this function
            type posess.

            :return: An int.
        """
        i = self._tinfo.get_nargs()
        if i == -1:
            raise BipError("A function type should have 0 arg at worst. This should never happen.")
        return i

    @property
    def args_type(self):
        """
            Property which return a list of the :class:`IdaType` object for 
            the argument of this function.

            :return: A list of objects which inherit from :class:`IdaType`
                class.
        """
        return [self.get_arg_type(i) for i in range(self.nb_args)]

    @property
    def return_type(self):
        """
            Property which return the :class:`IdaType` object corresponding
                to the type of the return of this function.

            :return: An object which inherit from :class:`IdaType` class.
        """
        return IdaType.GetIdaType(self._ida_func_type_data.rettype)

    @property
    def childs(self):
        """
            Property which return a list of childs types. All elements of this
            list will be object which inherit from :class:`IdaType`.

            First element is the return type followed by the argument types.
            The length of this property is variable depending of the function
            type but will always be equal to ``nb_args + 1`` .

            :return: A list of object inheriting from :class:`IdaType`
                which are "child" of this type.
        """
        return [self.return_type] + [self.get_arg_type(i) for i in range(self.nb_args)]

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_func()


class ITypeStruct(IdaType):
    """
        Class which represent the :class:`IdaType` for a structure. This is a
        recursive type, each member of the struct posess its own types.
        
        It is possible to get the name of the member using the
        :meth:`get_member_name` method, it is also possible to get the type
        using the :meth:`get_member_type` method or the :meth:`members_type`
        property (which return a list), the :meth:`members_info` return a
        dictionnary with the name of the members as key and their type as
        value.

        .. todo:: test

        .. todo:: link to struct in bip
        .. todo:: anonymous udt ?
        .. todo:: everything in ida_typeinf.udt_type_data_t
        .. todo:: everything in udt_member_t for the members. Change the
            handling of the members ?
        .. todo:: allow to get the offset of a member from its name and/or
            index.
        .. todo:: what about struct in struct ? Could probably make some
            helper for that.
    """

    @property
    def _ida_udt_type_data(self):
        """
            Internal property which allow to get the ``udt_type_data_t`` for
            this type structure.

            :return: the ``ida_typeinf.udt_type_data_t`` for this object.
        """
        utd = udt_type_data_t()
        if not self._tinfo.get_udt_details(utd):
            raise BipError("Unable to get struct details for struct {}".format(self.name))
        return utd

    def get_member_name(self, num):
        """
            Get the name of a member.

            :param int num: The number corresponding to the member. This is
                not the offset of the member but its index in the struct, this
                index start at 0 up to the :meth:`~ITypeStruct.nb_members`
                minus one.
            :return: The name of the ``num`` member for this struct type.
        """
        return self._ida_udt_type_data[num].name

    def get_member_type(self, num):
        """
            Get the :class:`IdaType` object corresponding to the type of a
            member.

            .. todo:: handle the recuperation of a member by name ?

            :param int num: The number corresponding to the member. This is
                not the offset of the member but its index in the struct, this
                index start at 0 up to the :meth:`~ITypeStruct.nb_members`
                minus one.
            :return: An object which inherit from :class:`IdaType` class.
        """
        return IdaType.GetIdaType(self._ida_udt_type_data[num].type)

    @property
    def nb_members(self):
        """
            Property which return the number of members present in the type
            structure.

            :return: an int.
        """
        return self._tinfo.get_udt_nmembers()

    @property
    def members_type(self):
        """
            Property which return a list of the :class:`IdaType` object for 
            the members of this struct.

            :return: A list of objects which inherit from :class:`IdaType`
                class.
        """
        return [self.get_member_type(i) for i in range(self.nb_members)]

    @property
    def members_info(self):
        """
            Property which return a dict providing information about the
            members of this struct. The keys of the dict correspond to their
            name (str) and the values to their type (:class:`IdaType`).
        """
        d = {}
        for i in range(self.nb_members):
            utd = self._ida_udt_type_data[i]
            d[utd.name] = udt.type
        return d

    @property
    def childs(self):
        """
            Property which return a list of childs types. All elements of this
            list will be object which inherit from :class:`IdaType`.

            This contain the type of the members and is equivalent to
            :meth:`~ITypeStruct.members_type`

            :return: A list of object inheriting from :class:`IdaType`
                which are "child" of this type.
        """
        return self.members_type

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_struct()

class ITypeUnion(IdaType):
    """
        Class which represent the :class:`IdaType` for an union, this is a
        recursive type which can have several members.

        .. todo:: at the exception of the doc this is duplicate code for most
            of the methods with :class:`ITypeStruct`, this should be fix. The
            simplest way would be to create a common parent class.
    """

    @property
    def _ida_udt_type_data(self):
        """
            Internal property which allow to get the ``udt_type_data_t`` for
            this union.

            :return: the ``ida_typeinf.udt_type_data_t`` for this object.
        """
        utd = udt_type_data_t()
        if not self._tinfo.get_udt_details(utd):
            raise BipError("Unable to get struct details for union {}".format(self.name))
        return utd

    def get_member_name(self, num):
        """
            Get the name of a member.

            :param int num: The number corresponding to the member. This is
                its index in the enum, this index start at 0 up to
                the :meth:`~ITypeStruct.nb_members` minus one.
            :return: The name of the ``num`` member for this struct type.
        """
        return self._ida_udt_type_data[num].name

    def get_member_type(self, num):
        """
            Get the :class:`IdaType` object corresponding to the type of a
            member.

            .. todo:: handle the recuperation of a member by name ?

            :param int num: The number corresponding to the member. This is
                the index in the enum, this index start at 0 up to the
                :meth:`~ITypeStruct.nb_members` minus one.
            :return: An object which inherit from :class:`IdaType` class.
        """
        return IdaType.GetIdaType(self._ida_udt_type_data[num].type)

    @property
    def nb_members(self):
        """
            Property which return the number of members present in the enum.

            :return: an int.
        """
        return self._tinfo.get_udt_nmembers()

    @property
    def members_type(self):
        """
            Property which return a list of the :class:`IdaType` object for 
            the members of this enum.

            :return: A list of objects which inherit from :class:`IdaType`
                class.
        """
        return [self.get_member_type(i) for i in range(self.nb_members)]

    @property
    def members_info(self):
        """
            Property which return a dict providing information about the
            members of this enum. The keys of the dict correspond to their
            name (str) and the values to their type (:class:`IdaType`).
        """
        d = {}
        for i in range(self.nb_members):
            utd = self._ida_udt_type_data[i]
            d[utd.name] = udt.type
        return d

    @property
    def childs(self):
        """
            Property which return a list of childs types. All elements of this
            list will be object which inherit from :class:`IdaType`.

            This contain the type of the members and is equivalent to
            :meth:`~ITypeEnum.members_type`

            :return: A list of object inheriting from :class:`IdaType`
                which are "child" of this type.
        """
        return self.members_type


    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_union()

class ITypeEnum(IdaType):
    """
        Class which represent the :class:`IdaType` for an enum.

        .. todo:: IDA BUG: its not possible to get the info about the enum
            members because the ``enum_type_data_t`` type which should be a
            vector on enum_member_t has apparently not been implemented in the
            IdaPython API. 
    """

    @property
    def _ida_enum_type_data(self):
        """
            Internal property which allow to get the ``enum_type_data_t`` for
            this enum.

            :return: the ``ida_typeinf.enum_type_data_t`` for this object.
        """
        etd = enum_type_data_t()
        if not self._tinfo.get_enum_details(etd):
            raise BipError("Unable to get enum details for enum {}".format(self.name))
        return etd

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_enum()

# Not sure the bitfield exist in practice, it seems to be considered as enum
#class ITypeBitfield(IdaType):
#   pass TODO





