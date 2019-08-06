"""
    .. todo::
        
        This functions should be integrated in the more general class or put
        in their own submodule
"""

from re import match

import idaapi
import idc
import idautils
import ida_kernwin

def get_highlighted_identifier_as_int():
    """
        Allow to get the value of the currently highlighted identifier if
        it is an integer. If it not possible to make it match a type 
        of integer (hex, oct or dec) the function return ``None``.

        :return: the value currently highlighted.
        :rtype: int
    """
    s = idaapi.get_highlighted_identifier()
    h = match('(0x[0-9a-fA-F]+).*', s)
    o = match('(0[0-7]+).*', s)
    n = match('([0-9]+).*', s)
    
    if h:
        return int(h.group(1), 16)
    elif o:
        return int(o.group(1), 8)
    elif n:
        return int(n.group(1))
    
    return None

def Ptr(ea):
    """
        Recuperate the value of a pointer at an address. This will handle
        automatically the correct size of the pointer.

        :param int ea: the address at which get the pointer value.
        :return: the pointer value
        :rtype: int
    """
    info = idaapi.get_inf_structure()

    if info.is_64bit():
        return idc.Qword(ea)
    elif info.is_32bit():
        return idc.Dword(ea)
    else:
        return idc.Word(ea)

def get_ptr_size():
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

def get_addr_by_name(name):
    """
        Get the relative address from a name. In case of error return 0.

        .. todo:: change the name of this function in ``get_reladdr_by_name`` ?

        :param name: The name corresponding to the point where we want the address.
        :type name: :class:`str`
        :return: The relative address corresponding to name.
        :rtype: int
    """
    ea = idc.LocByName(name)
    if ea == 0xffffffffffffffff:
        return 0
    return relea(ea)

def get_name_by_addr(offset):
    """
        .. todo:: hu ? what does that do ?

        .. todo:: Remove the print and raise an exception if an error occur
    """
    s = idc.GetFuncOffset(absea(offset))
    if not s:
        nn = idaapi.NearestName({k:v for k,v in idautils.Names()})
        if nn is None:
            return '', 0
        
        ea, name, _ = nn.find(absea(offset))
        offset = absea(offset)-ea
        if offset < 0x100:
            return name, offset
        return '', 0

    print s
    name, _, offset = s.partition('+')
    if offset:
        offset = int(offset, 16)
    else:
        offset = 0
        
    # FFS IDA
    name = name.replace('__', '::')
    if not get_addr_by_name(name):
        print "[!] WUT WUT WUT '%s' returned by GetFuncOffset doesnt exist" % name

    print name, offset
    return name, offset


def get_struct_from_lvar(lvar):
    """
        Try getting a structure used by an hexrays local variable type.

        .. todo:: can do better for the description.
        
        .. todo:: This should probaly be added into the hexrays API.

        :rtype: A bip :class:`~bip.base.BipStruct` object or ``None`` on error
    """

    from bip.base import BipStruct
    
    t = lvar.type()
    
    if t.is_ptr():
        s = t.get_pointed_object()
        if s.is_struct():
            try:
                struct = BipStruct.get(s.get_type_name())
                return struct
            except ValueError:
                return None
    return None


def bip_exec_sync(func, *args, **kwargs):
    """
        Wrap around the execute_sync API to perform a call on the function ``func``
        in the main thread. If a function is not marked as THREAD_SAFE in the headers, 
        then it can only be called from the main thread of IDA.

        :param func: The function to call.
        :type func: Python Callable

        :param args: Arguments to ``func``
        
        :param kwargs: Keyworded arguments to ``func``

        :param MFF_FLAG: Flag describing the operation on the database. Default MFF_READ. Can be MFF_FAST, MFF_READ, MFF_WRITE or MFF_NOWAIT.
        :type MFF_FLAG: int

        :return: The return of ``func``
    """

    MFF_FLAG = kwargs.get("MFF_FLAG", ida_kernwin.MFF_READ)

    ret = {"ret": None}
    def handle():
        ret["ret"] = func(*args, **kwargs)
        return 1

    ida_kernwin.execute_sync(handle, MFF_FLAG)
    return ret["ret"]

