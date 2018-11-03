from re import match
from idaapi import *
from idc import *
from idautils import *
from ida_hexrays import *

def get_highlighted_identifier_as_int():
    """
        Allow to get the value of the currently highlighted identifier if
        it is an integer. If it not possible to make it match a type 
        of integer (hex, oct or dec) the function return ``None``.

        :return: the value currently highlighted.
        :rtype: int
    """
    s = get_highlighted_identifier()
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
    info = get_inf_structure()

    if info.is_64bit():
        return Qword(ea)
    elif info.is_32bit():
        return Dword(ea)
    else:
        return Word(ea)

def get_ptr_size():
    """
        Return the number of bits in a pointer.

        :rtype: int
    """
    info = get_inf_structure()

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
    return addr-get_imagebase()

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
    return offset+get_imagebase()

def get_addr_by_name(name):
    """
        Get the relative address from a name. In case of error return 0.

        .. todo:: change the name of this function in ``get_reladdr_by_name`` ?

        :param str name: The name corresponding to the point where we want the address.
        :return: The relative address corresponding to name.
            :rtype: int
    """
    ea = LocByName(name)
    if ea == 0xffffffffffffffff:
        return 0
    return relea(ea)

def get_funcs_by_name(name):
    """
        Get all the functions which are named with a particular prefix.

        .. todo:: change the parameter ``name`` in ``prefix`` ?

        .. todo:: rename this function ``get_funcs_by_prefix`` ?

        :param str name: The prefix to match again the functions named.
        :return: A list of the name of the functions which match the prefix.
        :rtype: list(str)
    """
    res = []
    for ea in Functions():
        n = GetFunctionName(ea)
        if n.startswith(name):
            res.append(n)

    return res

def get_name_by_addr(offset):
    """
        .. todo:: hu ? what does that do ?

        .. todo:: Remove the print and raise an exception if an error occur
    """
    s = GetFuncOffset(absea(offset))
    if not s:
        nn = NearestName({k:v for k,v in Names()})
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

        :rtype: A bip :class:`~bip.base.Struct` object or ``None`` on error
    """
    
    t = lvar.type()
    
    if t.is_ptr():
        s = t.get_pointed_object()
        if s.is_struct():
            try:
                struct = Struct.get(s.get_type_name())
                return struct
            except ValueError:
                return None
    return None




