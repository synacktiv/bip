import idc
import ida_bytes
import ida_kernwin

from idaelt import BipElt
from biptype import BipType
from biperror import BipError

# TODO:
#   * is_offset and setter, is_value_mapped
#   * operator (equality, cmp...)
#   * next and prev element
#   * iter_all: make a 2nd versions: which included undefined element
#   * link to struct
#   * strings
#   * array
#   * owords
#   * link to enum
#   * allow to transform to code ??

class BipData(BipElt):
    """
        Class for representing and manipulating data in IDA.


        .. todo:: make test.
        .. todo:: precise this doc
    """

    def __init__(self, ea=None):
        """
            Constructor for :class:`BipData`, take the address of the
            data in IDA in parameter.


            :param int ea: The address of the element in IDA. If ``None`` the
                screen address is taken.
            :raise BipError: If address do not correspond to data
        """
        super(BipData, self).__init__(ea)
        if ((not self.is_data) and (not self.is_unknown)):
            raise BipError("Not a data object at 0x{:X}".format(ea))


    ########################## BASE ############################

    @property
    def value(self):
        """
            Property which return the value corresponding to the data of a
            numberable elements. This property works only if the
            :meth:`~BipData.is_numerable` and :meth:`~BipData.has_data`
            properties returned True. For getting value of an element which
            is not numerable use the :meth:`~BipElt.bytes` property.

            This property is link to the type defined or guessed by IDA and
            it is a good idea to assure you have the proper type before using
            it.

            :return: An integer representing the value of the data or ``None``
                if the data element is not numerable or do not have data.
        """
        if not self.has_data:
            return None
        elif self.is_unknown or self.is_byte:
            return ida_bytes.get_wide_byte(self.ea)
        elif self.is_word:
            return ida_bytes.get_wide_word(self.ea)
        elif self.is_dword:
            return ida_bytes.get_wide_dword(self.ea)
        elif self.is_qword:
            return ida_bytes.get_qword(self.ea)
        else:
            return None

    @property
    def original_value(self):
        """
            Property which allow to get the original value of data. This is
            the same as :meth:`~BipData.value` getter property but for the
            original bytes before they were patch.
        """
        if not self.has_data:
            return None
        elif self.is_unknown or self.is_byte:
            return ida_bytes.get_original_byte(self.ea)
        elif self.is_word:
            return ida_bytes.get_original_word(self.ea)
        elif self.is_dword:
            return ida_bytes.get_original_dword(self.ea)
        elif self.is_qword:
            return ida_bytes.get_original_qword(self.ea)
        else:
            return None

    @value.setter
    def value(self, value):
        """
            Property setter which allow to set the value of this object.
            This property works only if the :meth:`~BipData.is_numerable`
            property returned True. If this object has no data
            (:meth:`~BipData.has_data` property return False) or is unknown
            (:meth:`~BipData.is_unknwon` return True) the value set is
            considered to be on 1 byte.

            For setting non numerical value or value on more than 8 bytes use
            the :meth:`~BipElt.bytes` property setter.

            This property is link to the type defined or guessed by IDA and
            it is a good idea to assure you have the proper type before using
            it.

            :param int value: An integer to which set the value of the
                current data element.
            :raise RuntimeError: If the setting of the value failed or if
                the value could not be set because of an unknown type.
        """
        if (not self.has_data) or self.is_unknown or self.is_byte:
            if not ida_bytes.patch_byte(self.ea, value):
                raise RuntimeError("Unable to patch value: {}".format(self))
        elif self.is_word:
            if not ida_bytes.patch_word(self.ea, value):
                raise RuntimeError("Unable to patch value: {}".format(self))
        elif self.is_dword:
            if not ida_bytes.patch_dword(self.ea, value):
                raise RuntimeError("Unable to patch value: {}".format(self))
        elif self.is_qword:
            if not ida_bytes.patch_qword(self.ea, value):
                raise RuntimeError("Unable to patch value: {}".format(self))
        else:
            raise RuntimeError("Unable to patch value: {}".format(self))

    @value.deleter
    def value(self):
        """
            Property deleter which allow to set one byte as unitialized
            (marked as ``?`` in IDA) at the address of this data object.
        """
        ida_bytes.del_value(self.ea)

    def __str__(self):
        if self.has_data:
            if self.is_numerable:
                return "{} at 0x{:X} = 0x{:X}".format(self.__class__.__name__, self.ea, self.value)
            else:
                return "{} at 0x{:X} = {}".format(self.__class__.__name__, self.ea, repr("".join([chr(i) for i in self.bytes])))
        else:
            return "{} at 0x{:X} without value".format(self.__class__.__name__, self.ea)

    ########################## TYPE ################################

    @property
    def is_byte(self):
        """
            Property which allow to test if this object represent a byte
            (1 byte).
            
            :return: True if this data object represent a byte, False
                otherwise.
        """
        return ida_bytes.is_byte(self.flags)

    @is_byte.setter
    def is_byte(self, value):
        """
            Property setter which allow to transform this object in a defined
            object on 1 byte. If set as False the value is undefined whichever
            its previous type.

            :param value: True for setting this data object as being on 1
                byte, False for undeffining the object type.
            :raise RuntimeError: If value was True and it was not able
                to correctly set the type for current item.
        """
        if value:
            if not ida_bytes.create_data(self.ea, ida_bytes.FF_BYTE, 1, idc.BADADDR):
                raise RuntimeError("Unable to set type for {}".format(self))
        else:
            del self.type

    @property
    def is_word(self):
        """
            Property which allow to test if this object represent a word
            (2 bytes).
            
            :return: True if this data object represent a word, False
                otherwise.
        """
        return ida_bytes.is_word(self.flags)

    @is_word.setter
    def is_word(self, value):
        """
            Property setter which allow to transform this object in a defined
            object on 2 bytes. If set as False the value is undefined
            whichever its previous type.

            :param value: True for setting this data object as being on 2
                bytes, False for undefining the object type.
            :raise RuntimeError: If value was True and it was not able
                to correctly set the type for current item.
        """
        if value:
            if not ida_bytes.create_data(self.ea, ida_bytes.FF_WORD, 2, idc.BADADDR):
                raise RuntimeError("Unable to set type for {}".format(self))
        else:
            del self.type

    @property
    def is_dword(self):
        """
            Property which allow to test if this object represent a dword
            (4 bytes).
            
            :return: True if this data object represent a dword, False
                otherwise.
        """
        return ida_bytes.is_dword(self.flags)

    @is_dword.setter
    def is_dword(self, value):
        """
            Property setter which allow to transform this object in a defined
            object on 4 bytes. If set as False the value is undefined
            whichever its previous type.

            :param value: True for setting this data object as being on 4
                bytes, False for undefining the object type.
            :raise RuntimeError: If value was True and it was not able
                to correctly set the type for current item.
        """
        if value:
            if not ida_bytes.create_data(self.ea, ida_bytes.FF_DWORD, 4, idc.BADADDR):
                raise RuntimeError("Unable to set type for {}".format(self))
        else:
            del self.type

    @property
    def is_qword(self):
        """
            Property which allow to test if this object represent a qword
            (8 bytes).
            
            :return: True if this data object represent a qword, False
                otherwise.
        """
        return ida_bytes.is_qword(self.flags)

    @is_qword.setter
    def is_qword(self, value):
        """
            Property setter which allow to transform this object in a defined
            object on 8 bytes. If set as False the value is undefined
            whichever its previous type.

            :param value: True for setting this data object as being on 8
                bytes, False for undefining the object type.
            :raise RuntimeError: If value was True and it was not able
                to correctly set the type for current item.
        """
        if value:
            if not ida_bytes.create_data(self.ea, ida_bytes.FF_DWORD, 4, idc.BADADDR):
                raise RuntimeError("Unable to set type for {}".format(self))
        else:
            del self.type

    @property
    def is_numerable(self):
        """
            Property which allow to test if this data element can be
            considered as a number for the :meth:`~BipData.value` property.

            :return: True if the data is a byte, word, dword, qword
                or unknwon, False otherwise.
        """
        return (self.is_unknown or self.is_byte or self.is_word
            or self.is_dword or self.is_qword)

    @property
    def type(self):
        """
            Property which allow to get the type of an element.
            This is a wrapper for :meth:`BipType.get_at` .

            :return: An object which inherit from :class:`BipType` or ``None``
                if it was not able to guess a type.
        """
        return BipType.get_at(self.ea)

    @type.setter
    def type(self, value):
        """
            Property setter which allow to define the type for this data
            element. This is a wrapper for :meth:`BipType.set_at` .

            :param value: An object which inherit from :class:`BipType`
                corresponding to the new type for this data object. If
                ``None`` is given in argument the type of the object is
                deleted.
        """
        if value is None:
            ida_bytes.del_items(self.ea)
        value.set_at(self.ea)

    @type.deleter
    def type(self):
        """
            Property deleter which allow to undefine the type of this data
            item. This is equivalent to using the setter with a ``None`` type.
        """
        ida_bytes.del_items(self.ea)

        

    ###################### CLASS METHODS #############################

    @classmethod
    def _is_this_elt(cls, ea):
        return (idc.is_data(ida_bytes.get_full_flags(ea))
                or idc.is_unknown(ida_bytes.get_full_flags(ea)))

    @classmethod
    def iter_heads(cls):
        """
            Class method allowing to iter on all the data **defined** in
            the IDB. This means data which are not defined (considered to
            not *heads*) will not be returned by this function.

            .. note::
                Internally this function iterate on all the ``Heads`` and
                create the object if the ``idc.is_data`` function return True.

            :return: A generator of :class:`BipData` allowing to iter on all
                the instruction define in the idb.
        """
        for h in idautils.Heads():
            if (idc.is_data(ida_bytes.get_full_flags(h))
                    or idc.is_unknown(ida_bytes.get_full_flags(h))):
                yield cls(h)

    ######################## STATIC METHOD ##############################

    @staticmethod
    def get_byte(ea=None, original=False):
        """
            Static method allowing to get the value of one byte at an address.

            :param ea: The address at which recuperating the value. If
                ``None`` the screen address is used.
            :param original: If True the value recuperated will be the
                original one (before a patch). Default: False.
            :return: An integer corresponding to the value at the address.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        if original:
            return ida_bytes.get_original_byte(ea)
        else:
            return ida_bytes.get_wide_byte(ea)

    @staticmethod
    def set_byte(ea, value):
        """
            Static method allowing to set the value of one byte at an address.

            :param ea: The address at which changing the value.
            :param value: The value to set at the address.
            :raise RuntimeError: If it was not possible to change the value.
        """
        if not ida_bytes.patch_byte(ea, value):
            raise RuntimeError("Unable to set value {} at {}".format(ea, value))

    @staticmethod
    def get_word(ea=None, original=False):
        """
            Static method allowing to get the value of one word at an address.

            :param ea: The address at which recuperating the value. If
                ``None`` the screen address is used.
            :param original: If True the value recuperated will be the
                original one (before a patch). Default: False.
            :return: An integer corresponding to the value at the address.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        if original:
            return ida_bytes.get_original_word(ea)
        else:
            return ida_bytes.get_wide_word(ea)

    @staticmethod
    def set_word(ea, value):
        """
            Static method allowing to set the value of one wordat an address.

            :param ea: The address at which changing the value.
            :param value: The value to set at the address.
            :raise RuntimeError: If it was not possible to change the value.
        """
        if not ida_bytes.patch_word(ea, value):
            raise RuntimeError("Unable to set value {} at {}".format(ea, value))

    @staticmethod
    def get_dword(ea=None, original=False):
        """
            Static method allowing to get the value of one dword at an address.

            :param ea: The address at which recuperating the value. If
                ``None`` the screen address is used.
            :param original: If True the value recuperated will be the
                original one (before a patch). Default: False.
            :return: An integer corresponding to the value at the address.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        if original:
            return ida_bytes.get_original_dword(ea)
        else:
            return ida_bytes.get_wide_dword(ea)

    @staticmethod
    def set_dword(ea, value):
        """
            Static method allowing to set the value of one dwordat an address.

            :param ea: The address at which changing the value.
            :param value: The value to set at the address.
            :raise RuntimeError: If it was not possible to change the value.
        """
        if not ida_bytes.patch_dword(ea, value):
            raise RuntimeError("Unable to set value {} at {}".format(ea, value))

    @staticmethod
    def get_qword(ea=None, original=False):
        """
            Static method allowing to get the value of one qword at an address.

            :param ea: The address at which recuperating the value. If
                ``None`` the screen address is used.
            :param original: If True the value recuperated will be the
                original one (before a patch). Default: False.
            :return: An integer corresponding to the value at the address.
        """
        if ea is None:
            ea = ida_kernwin.get_screen_ea()
        if original:
            return ida_bytes.get_original_qword(ea)
        else:
            return ida_bytes.get_qword(ea)

    @staticmethod
    def set_qword(ea, value):
        """
            Static method allowing to set the value of one qwordat an address.

            :param ea: The address at which changing the value.
            :param value: The value to set at the address.
            :raise RuntimeError: If it was not possible to change the value.
        """
        if not ida_bytes.patch_qword(ea, value):
            raise RuntimeError("Unable to set value {} at {}".format(ea, value))


