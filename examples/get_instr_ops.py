from bip.base import Instr, OpType


def get_instr_with_displ(value):
    """
        Example which demonstrate how to search for all instructions which
        have at least one operand with a particular displacement value
        (``[rax+0x1C]`` as a displacement value of ``0x1C``).
        
        :param int value: The displacement value to search for.
        :return: A list of :class:`~bip.base.Instr` who match.
    """
    l = []
    for i in Instr.iter_all():
        for o in i.ops:
            if o.type == OpType.DISPL and o.value == value:
                #print(i)
                l.append(i)
    return l


#for i in get_instr_with_displ(0x1C):
#    print(i)

