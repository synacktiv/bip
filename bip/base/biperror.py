
class BipError(Exception):
    pass

class BipDecompileError(BipError):
    """
        :class:`BipError` for decompilation failure. Main reason for this
        is that hexrays failed to decompile a function or that the address
        provided was not inside a function.
    """
    pass

