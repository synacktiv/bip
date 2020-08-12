
# define BipIdb and some helper functions for easier scripting (at the end).

import ida_kernwin
import idaapi
import idc

class BipIdb(object):
    """
        Class for representing the idb loaded by IDA, this has for goal to
        provide access to things specific to the IDB.
        
        Currently this contain only static methods.
    """

    @staticmethod
    def ptr_size():
        """
            Return the number of bits in a pointer.
    
            :rtype: int
        """
        info = idaapi.get_inf_structure()
    
        if info.is_64bit():
            bits = 64
        elif info.is_32bit():
            bits = 32
        else:
            bits = 16
    
        return bits

    @staticmethod
    def min_ea():
        """
            Return the lowest mapped address of the IDB.
        """
        return idc.get_inf_attr(idc.INF_MIN_EA)
    
    @staticmethod
    def max_ea():
        """
            Return the highest mapped address of the IDB.
        """
        return idc.get_inf_attr(idc.INF_MAX_EA)

    @staticmethod
    def image_base():
        """
            Return the base address of the image loaded in the IDB.
            
            This is different from :meth:`~BipIdb.min_ea` which is the lowest
            *mapped* address.
        """
        return idaapi.get_imagebase()

    @staticmethod
    def current_addr():
        """
            Return current screen address.

            :return: The current address selected.
        """
        return ida_kernwin.get_screen_ea()

    @staticmethod
    def relea(addr):
        """
            Calculate the relative address compare to the IDA image base.
            The calcul done is ``ADDR - IMGBASE``.
    
            The opposite of this function is :func:`absea`.
    
            :param int addr: The absolute address to translate.
            :return: The offset from image base corresponding to ``addr``.
            :rtype: int
        """
        return addr-idaapi.get_imagebase()
    
    @staticmethod
    def absea(offset):
        """
            Calculate the absolute address from an offset of the image base.
            The calcul done is ``OFFSET + IMGBASE`` .
    
            The opposite of this function is :func:`relea`.
    
            :param int offset: The offset from the beginning of the image base
                to translate.
            :return: The absolute address corresponding to the offset.
            :rtype: int
        """
        return offset+idaapi.get_imagebase()

def min_ea():
    """
        Return the lowest mapped address of the IDB.
        Wrapper on :meth:`BipIdb.min_ea`.
    """
    return BipIdb.min_ea()

def max_ea():
    """
        Return the highest mapped address of the IDB.
        Wrapper on :meth:`BipIdb.max_ea`.
    """
    return BipIdb.max_ea()

def Here():
    """
        Return current screen address.

        :return: The current address.
    """
    return BipIdb.current_addr()



