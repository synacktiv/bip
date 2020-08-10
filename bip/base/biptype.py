"""
    File for basic type gestion. In particular this contain the wrapper on top
    of the type implementation in IDA (typeinf). In particular this contain
    the abstraction on top of the ``tinfo_t`` (:class:`BipType`).

    Each object representing a type can have "children". Those children
    represent subtypes of the current type. The most basic exemple of this is
    the case for a pointer: the pointer point on a particular type, for
    example an integer in the case of ``int *``. The :class:`BTypePtr`
    representing the pointer will have one children :class:`BTypeInt`
    representing the integer.

    .. todo:: support creation of the type

    .. todo:: Bitfield implementation ?
"""

from ida_typeinf import tinfo_t, array_type_data_t, func_type_data_t, udt_type_data_t, enum_type_data_t, apply_tinfo, guess_tinfo, GUESS_FUNC_OK, parse_decl
import ida_typeinf
import ida_nalt
import ida_kernwin
import idc

class BipType(object):
    """
        Abstract class for representing a ``tinfo_t`` object from ida in bip.
        All basic types are subclasses of this one, the class name start with
        the prefix ``BType``, see :ref:`doc-bip-base-type` for more
        information.

        The objects which inherit from :class:`BipType` can contain other
        *child* :class:`BipType` objects. For example a pointer
        (:class:`BTypePtr`) will contain one child object corresponding to the
        pointed type. The :meth:`childs` property allow to get a list of the
        child object.

        .. todo:: allow creation of types

        .. todo::

            General todo for types:

            * SSE
            * const
    """


    ############################# BASE ####################################

    def __init__(self, tinfo):
        """
            Base constructor for the child classes of :class:`BipType`. This
            constructor is used for interfacing with IDA and initializing. A
            bip user should probably used the :func:`BipType.from_tinfo`
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

            In case the number of bytes is unknown None is returned.
        """
        sz = self._tinfo.get_size()
        if sz == idc.BADADDR:
            return None
        return sz

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
            with the :meth:`BipType.name` property.
        """
        return self._tinfo.get_type_name() is not None

    @property
    def name(self):
        """
            Property which return the name of this type if it has one. A type
            can a name because of a typedef, a structure, ... If it does not
            have one this property will return an empty string. The presence
            of a named can be tested using the :meth:`BipType.is_named`
            property.

            :return: A string corresponding to the name of this type. Empty
                if this type does not have a name.
        """

        return self._tinfo.get_type_name()

    ############################ COMPARE ################################

    def __eq__(self, other):
        """
            Compare two BipType. This is only based on the compare of the IDA
            underlying object.
        """
        if not isinstance(other, BipType):
            return NotImplemented
        return self._tinfo == other._tinfo

    def __ne__(self, other):
        res = self.__eq__(other)
        if res == NotImplemented:
            return res
        else:
            return not res

    ########################## GENERAL TYPE SET/GET #########################

    def set_at(self, ea, flags=1):
        """
            Function which try to set the type of the current object at a
            given position, in particular this will work for global data and
            function. If an error occur when trying to set the type a
            :class:`RuntimeError` will be raised.

            This create a copy of the ``tinfo_t`` in this object.

            .. todo:: delete flags and make something better here.

            :param int ea: The address at which set the type.
            :param int flags: This are the ``TINFO_*`` flags from ida_typeinf,
                by default ``TINFO_DEFINITE`` .
        """
        if not apply_tinfo(ea, self._get_tinfo_copy(), flags):
            raise RuntimeError("Unable to set type {} at address {}".format(self.str, ea))

    @staticmethod
    def is_set_at(ea):
        """
            This function allow to test if a type is defined at a particular
            address. This function will return False if a type is not set but
            ida may be able to guess it. This means that this function may
            return False while :func:`BipType.get_at` return a type, if this
            function return True :func:`BipType.get_at` should always return
            a type.

            :param ea: The address at which to make the test.
            :return: True if a type is defined at the address given in
                argument, False otherwise.
        """
        tif = tinfo_t()
        return ida_nalt.get_tinfo(tif, ea)

    @staticmethod
    def get_at(ea=None):
        """
            Function which will create an object which inherit from
            :class:`BipType` representing the type at the current address.
            This function will **not** set the type at the address given and
            it may not be set if it was guess by ida.

            Internally this function will first try to get the type at the
            address, if no type are defined it will try to guess it. If ida
            is not able to guess it it will return ``None``.

            .. todo:: make something better when no type are set ?

            .. note:: **Implementation**

                Ida allow to guess the type but this "guess" ignore the fact
                that this may have been set. It seems necessary to use
                ida_nalt.get_tinfo for recuperating the type set, it will fail
                if no type has been set. If no type were set the guess_tinfo
                is then used, it will typically fail if the data is undefined,
                in this case None will be return. This may change in the
                future as by default a tinfo_t ``empty`` is true (but not the
                tinfo_t.is_unknown).

            :param ea: The address at which to get the type. If ``None``
                the screen address will be used.
            :return: An object which inherit from :class:`BipType`
                representing the type at the address given in argument.
                ``None`` will be return if no type is define and ida was not
                able to guess it .
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        tif = tinfo_t()
        # try to get the define type
        # this seems to be define in ida_nalt...
        if ida_nalt.get_tinfo(tif, ea):
            # no need to make a copy in this case
            return BipType.from_tinfo_no_copy(tif)

        # no type define, try to guess it
        # don't know when GUESS_FUNC_TRIVIAL is return so consider failure
        if guess_tinfo(tif, ea) == GUESS_FUNC_OK:
            return BipType.from_tinfo_no_copy(tif)

        # not able to guess, this should be a tinfo_t empty ? (tif.empty() ?)
        return None

    @staticmethod
    def del_at(ea):
        """
            Function which delete the type set at a particular address.

            :param ea: The address at which to delete the type. If ``None``
                the screen address will be used.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        ida_nalt.del_tinfo(ea)

    ############################# CHILDS ##############################

    @property
    def childs(self):
        """
            Property which return a list of childs types. All elements of this
            list will be object which inherit from :class:`BipType`.

            :return: A list of object inheriting from :class:`BipType`
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
    def from_tinfo(tinfo):
        """
            Function which convert a ``tinfo_t`` object from ida to one of the
            child object of :class:`BipType` . This should be used for
            converting the type from IDA into their correct object for bip.
            This function is used as an interface with the IDA object.

            If no :class:`BipType` child object supports the ``tinfo_t`` a
            ``ValueError`` exception will be raised. Internally this use
            the :func:`~BipType._get_class_bip_type` function.

            This create a **copy** of the underlying ``tinfo_t`` object, this
            allow to avoid problems if when using the IdaPython API or the GUI
            from IDA the type is change. This is a problem because it means
            bip should dynamically change the class of the object and even if
            possible this will create an error prone API. Instead types are
            handle by copy instead of by reference, and interface with other
            bip object take this into account. For creating an object of the
            correct class without a copy the :func:`~BipType.from_tinfo_no_copy`
            can be used by is subject to the above problems.

            :param tinfo: A ``tinfo_t`` from ida.
            :return: The equivalent object to the ``tinfo_t`` for bip. This
                will be an object which inherit from :class:`BipType` .
        """
        return BipType._get_class_bip_type(tinfo)(tinfo_t(tinfo))


    @staticmethod
    def from_tinfo_no_copy(tinfo):
        """
            Function which convert a ``tinfo_t`` object from ida to one of the
            child object of :class:`BipType` .

            If no :class:`BipType` child object supports the ``tinfo_t`` a
            ``ValueError`` exception will be raised. Internally this use
            the :func:`~BipType._get_class_bip_type` function.

            .. warning::

                This function does **not** create a copy of the underlying
                ``tinfo_t`` object which can create several problems when
                using the GUI or the IdaPython/IDC API. For creating a copy
                of the object use the :func:`~BipType.from_tinfo` instead.

            :param tinfo: A ``tinfo_t`` from ida.
            :return: The equivalent object to the ``tinfo_t`` for bip. This
                will be an object which inherit from :class:`BipType` .
        """
        return BipType._get_class_bip_type(tinfo)(tinfo)

    @staticmethod
    def from_c(cstr, flags=0x401):
        """
            Function which convert a C string declaration into a object which
            inherit from a :class:`BipType` . If there is no ``;`` at the end
            of the string provided, one will be added automatically.

            This is made for parsing **one** declaration and can create
            problem if several declarations are in the string.

            :param str cstr: A string representing a declaration in C.
            :param int flags: ``PT_*`` flags from IDA (see typeinf.hpp).
                The default is ``0x401`` (``PT_RAWARGS | PT_SIL``) should be
                enough in most case.
            :return: An object which inherit from :class:`BipType` equivalent
                to the C declaration.
            :raise RuntimeError: if the function was not able to create the type.
        """
        tif = tinfo_t()
        cstr = cstr.strip()
        if cstr[-1] != ';':
            cstr += ';'
        if parse_decl(tif, None, cstr, flags) is None:
            raise RuntimeError("Unable to create a BipType from declaration {}".format(repr(cstr)))
        return BipType.from_tinfo_no_copy(tif)

    @staticmethod
    def import_c_header(path, pack=0, raw_args=True, silent=False, autoimport=True):
        """
            Import a C header file.

            :param str path: The path to the C header file to import.
            :param int pack: The packing for the structure in the header. 0
                means default (from compiler/configuration), other values are
                power of 2 up to 16. No verification is made on that value.
            :param bool raw_args: Should leave the name of the argument
                unchanged: do not remove the _ in the name. True by default.
            :param bool silent: Should silently fails on error and mask
                warnings.
            :param bool autoimport: If True (the default), this function will
                import all new types in the IDB ("Structures", "Enums", ...
                Views), instead of only keeping them in the type
                library (til, the "Local Types" view).
            :return: The number of error which occur during parsing.
        """
        # This use the idc.parse_decls function, which is different of the
        #   ida_typeinf.parse_decls function, this one should be implemented
        #   using the type library
        flags = ida_typeinf.PT_FILE | ida_typeinf.PT_REPLACE
        if raw_args:
            flags |= ida_typeinf.PT_RAWARGS
        if silent:
            flags |= ida_typeinf.PT_SIL

        # handle pack conversion, hugly but should be ok
        if pack <= 2:
            flags |= (pack << 4) & ida_typeinf.PT_PACKMASK
        else:
            if pack == 4:
                flags |= (3 << 4) & ida_typeinf.PT_PACKMASK
            elif pack == 8:
                flags |= (4 << 4) & ida_typeinf.PT_PACKMASK
            elif pack == 16:
                flags |= (5 << 4) & ida_typeinf.PT_PACKMASK

        if autoimport:
            tidft = ida_typeinf.get_idati() # default type lib of the idb
            # we get the nb of ordinal type, before parsing
            nb_typ = ida_typeinf.get_ordinal_qty(tidft)
            # now we make the parsing
            nb_error = idc.parse_decls(path, flags)
            # get the new number of types after it has been parsed
            nb_typ_after = ida_typeinf.get_ordinal_qty(tidft)
            # now we can import all of them
            for i in range(nb_typ, nb_typ_after):
                # get the name of the type
                na = ida_typeinf.get_numbered_type_name(tidft, i)
                # import the type, put it at the end
                ida_typeinf.import_type(tidft, -1, na)
            return nb_error
        else:
            return idc.parse_decls(path, flags)

    @staticmethod
    def _get_class_bip_type(tinfo):
        """
            Internal function which allow to recuperate the correct child
            class of :class:`BipType` corresponding to  ``tinfo_t`` object
            from ida. This is used internally for converting the type from IDA
            into their correct object for bip.
            This function is used as an interface with the IDA object.

            If no :class:`BipType` child object supports the ``tinfo_t`` a
            ``ValueError`` exception will be raised.

            :param tinfo: A ``tinfo_t`` from ida.
            :return: The bip class which should be used as equivalent for
                the ``tinfo_t`` provided as argument. This
                will be an object which inherit from :class:`BipType` .
        """
        done = set()
        todo = set(BipType.__subclasses__())
        while len(todo) != 0:
            cl = todo.pop()
            if cl in done:
                continue
            if cl.is_handling_type(tinfo):
                return cl
            else:
                done.add(cl)
                todo |= set(cl.__subclasses__())
        raise ValueError("_get_class_bip_type could not find an object matching the tinfo_t type provided ({}: {})".format(tinfo, tinfo.dstr()))

    def _get_tinfo_copy(self):
        """
            Return a copy of the ida type (``tinfo_t``) represented by this
            object. This is an internal function which is used as an helper
            for setting the types of an element from a :class:`BipType`

            :return: A copy of the ``tinfo_t`` represented by this object.
        """
        return tinfo_t(self._tinfo)


class BTypeEmpty(BipType):
    """
        Class which represent the :class:`BipType` for a type with no
        information (empty or unknown). This
        is really used by IDA including in structures and so on.
    """

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.empty()


class BTypePartial(BipType):
    """
        Class which represent the :class:`BipType` for a partial type: when
        only the size is known but no other information is available.
    """

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_partial()

class BTypeVoid(BipType):
    """
        Class which represent the :class:`BipType` for a void.
    """

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_void()

class BTypeInt(BipType):
    """
        Class which represent the :class:`BipType` for an integer, it can be
        signed or unsigned and may have different :meth:`~BipType.size`.
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

class BTypeBool(BipType):
    """
        Class which represent the :class:`BipType` for a boolean (``bool``).
        All boolean do not have the same :meth:`~BipType.size` .
    """

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_bool()

class BTypeFloat(BipType):
    """
        Class which represent the :class:`BipType` for a float or a double.
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

class BTypePtr(BipType):
    """
        Class which represent the :class:`BipType` for a pointer. This is a
        recursive type, it is possible to have the pointed type with the
        property :meth:`pointed` .


    """

    @property
    def pointed(self):
        """
            Property which return the type pointed by this type.

            :return: An object which inherit from
                :class:`BipType` class.
        """
        return BipType.from_tinfo(self._tinfo.get_pointed_object())

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
        """
        return self._tinfo.is_funcptr()

    @property
    def childs(self):
        return [self.pointed]

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_ptr()

class BTypeArray(BipType):
    """
        Class which represent the :class:`BipType` for an array (a *static*
        array: ``int[8]`` for example). This is a
        recursive type, it is poissible to have the type of the elements with
        the property :meth:`elt_type` .

        .. note::

            The array (and in particular the ``array_type_data_t`` from IDA)
            have a ``base`` property. Not really sure what that is, when or
            how it is used. It is possible to access it using
            :meth:`~BTypeArray._array_info` then accessing the property
            ``base`` if needed.
    """

    @property
    def _array_info(self):
        """
            Property which return ``array_type_data_t`` object from ida
            associated with this object. This is only for interfacing with
            IDA and should probably not be used directly from bip.

            This is used by the other method/property of
            :class:`BTypeArray` .
        """
        atd = array_type_data_t()
        self._tinfo.get_array_details(atd)
        return atd

    @property
    def elt_type(self):
        """
            Property which returns the type of the elements in the type array.

            :return: An object which inherit from
                :class:`BipType` class.
        """
        return BipType.from_tinfo(self._array_info.elem_type)

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

class BTypeFunc(BipType):
    """
        Class which represent the :class:`BipType` for a function. This is a
        recursive type, it is poissible to have the type of the return value
        using the :meth:`~BTypeFunc.return_type` property and the type of the
        arguments using the method :meth:`~BTypeFunc.get_arg_type` or the
        property :meth:`~BTypeFunc.args_type`.

        Other methods are available allowing to access the name of the
        arguments (:meth:`~BTypeFunc.get_arg_name`).

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
            Get the :class:`BipType` object corresponding to the type of an
            argument.

            :return: An object which inherit from :class:`BipType` class.
        """
        # This does not work, don't know why
        #return BipType.from_tinfo(self._ida_func_type_data[pos].type)
        return BipType.from_tinfo(self._tinfo.get_nth_arg(pos))

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
            Property which return a list of the :class:`BipType` object for
            the argument of this function.

            :return: A list of objects which inherit from :class:`BipType`
                class.
        """
        return [self.get_arg_type(i) for i in range(self.nb_args)]

    @property
    def return_type(self):
        """
            Property which return the :class:`BipType` object corresponding
                to the type of the return of this function.

            :return: An object which inherit from :class:`BipType` class.
        """
        return BipType.from_tinfo(self._ida_func_type_data.rettype)

    @property
    def childs(self):
        """
            Property which return a list of childs types. All elements of this
            list will be object which inherit from :class:`BipType`.

            First element is the return type followed by the argument types.
            The length of this property is variable depending of the function
            type but will always be equal to ``nb_args + 1`` .

            :return: A list of object inheriting from :class:`BipType`
                which are "child" of this type.
        """
        return [self.return_type] + [self.get_arg_type(i) for i in range(self.nb_args)]

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_func()


class BTypeStruct(BipType):
    """
        Class which represent the :class:`BipType` for a structure. This is a
        recursive type, each member of the struct posess its own types.

        It is possible to get the name of the member using the
        :meth:`get_member_name` method, it is also possible to get the type
        using the :meth:`get_member_type` method or the :meth:`members_type`
        property (which return a list), the :meth:`members_info` return a
        dictionnary with the name of the members as key and their type as
        value.

        .. todo:: link to struct in bip
        .. todo:: anonymous udt ?
        .. todo:: everything in ida_typeinf.udt_type_data_t
        .. todo:: everything in udt_member_t for the members. Change the
            handling of the members ?
        .. todo:: allow to get the offset of a member from its name and/or
            index.
    """

    @property
    def _ida_udt_type_data(self):
        """
            Internal property which allow to get the ``udt_type_data_t`` for
            this type structure.

            .. warning::

                Carefull to this! The information contain in this
                object (such as the types) do not reference
                the ``udt_type_data_t`` object. Meaning that as soon as the
                ``udt_type_data_t`` object is delete by python, all the
                subobject will be deleted. All of those should be copied
                before the python object is destroyed or we may trigger
                use-after-free. For problematic of swig and memory management
                see http://www.swig.org/Doc1.3/Python.html#Python_nn30.

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
                index start at 0 up to the :meth:`~BTypeStruct.nb_members`
                minus one.
            :return: The name of the ``num`` member for this struct type.
        """
        iutd = self._ida_udt_type_data
        s = str(iutd[num].name)
        return s

    def get_member_type(self, num):
        """
            Get the :class:`BipType` object corresponding to the type of a
            member.

            .. todo:: handle the recuperation of a member by name ?

            :param int num: The number corresponding to the member. This is
                not the offset of the member but its index in the struct, this
                index start at 0 up to the :meth:`~BTypeStruct.nb_members`
                minus one.
            :return: An object which inherit from :class:`BipType` class.
        """
        iutd = self._ida_udt_type_data
        t = BipType.from_tinfo(iutd[num].type)
        return t

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
            Property which return a list of the :class:`BipType` object for
            the members of this struct.

            :return: A list of objects which inherit from :class:`BipType`
                class.
        """
        return [self.get_member_type(i) for i in range(self.nb_members)]

    @property
    def members_info(self):
        """
            Property which return a dict providing information about the
            members of this struct. The keys of the dict correspond to their
            name (str) and the values to their type (:class:`BipType`).
        """
        d = {}
        iutd = self._ida_udt_type_data
        for i in range(self.nb_members):
            utd = iutd[i]
            d[str(utd.name)] = BipType.from_tinfo(utd.type)
        return d

    @property
    def childs(self):
        """
            Property which return a list of childs types. All elements of this
            list will be object which inherit from :class:`BipType`.

            This contain the type of the members and is equivalent to
            :meth:`~BTypeStruct.members_type`

            :return: A list of object inheriting from :class:`BipType`
                which are "child" of this type.
        """
        return self.members_type

    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_struct()

class BTypeUnion(BipType):
    """
        Class which represent the :class:`BipType` for an union, this is a
        recursive type which can have several members.

        .. todo:: at the exception of the doc this is duplicate code for most
            of the methods with :class:`BTypeStruct`, this should be fix. The
            simplest way would be to create a common parent class.
    """

    @property
    def _ida_udt_type_data(self):
        """
            Internal property which allow to get the ``udt_type_data_t`` for
            this union.

            .. warning::

                Carefull to this! The information contain in this
                object (such as the types) do not reference
                the ``udt_type_data_t`` object. Meaning that as soon as the
                ``udt_type_data_t`` object is delete by python, all the
                subobject will be deleted. All of those should be copied
                before the python object is destroyed or we may trigger
                use-after-free. For problematic of swig and memory management
                see http://www.swig.org/Doc1.3/Python.html#Python_nn30.

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
                the :meth:`~BTypeStruct.nb_members` minus one.
            :return: The name of the ``num`` member for this struct type.
        """
        return str(self._ida_udt_type_data[num].name)

    def get_member_type(self, num):
        """
            Get the :class:`BipType` object corresponding to the type of a
            member.

            .. todo:: handle the recuperation of a member by name ?

            :param int num: The number corresponding to the member. This is
                the index in the enum, this index start at 0 up to the
                :meth:`~BTypeStruct.nb_members` minus one.
            :return: An object which inherit from :class:`BipType` class.
        """
        iutd = self._ida_udt_type_data
        t = BipType.from_tinfo(iutd[num].type)
        return t

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
            Property which return a list of the :class:`BipType` object for
            the members of this enum.

            :return: A list of objects which inherit from :class:`BipType`
                class.
        """
        return [self.get_member_type(i) for i in range(self.nb_members)]

    @property
    def members_info(self):
        """
            Property which return a dict providing information about the
            members of this enum. The keys of the dict correspond to their
            name (str) and the values to their type (:class:`BipType`).
        """
        d = {}
        iutd = self._ida_udt_type_data
        for i in range(self.nb_members):
            utd = iutd[i]
            d[str(utd.name)] = BipType.from_tinfo(utd.type)
        return d

    @property
    def childs(self):
        """
            Property which return a list of childs types. All elements of this
            list will be object which inherit from :class:`BipType`.

            This contain the type of the members and is equivalent to
            :meth:`~BTypeEnum.members_type`

            :return: A list of object inheriting from :class:`BipType`
                which are "child" of this type.
        """
        return self.members_type


    @classmethod
    def is_handling_type(cls, tinfo):
        return tinfo.is_union()

class BTypeEnum(BipType):
    """
        Class which represent the :class:`BipType` for an enum.

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
#class BTypeBitfield(BipType):
#   pass TODO





