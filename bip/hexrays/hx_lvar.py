

# TODO:
# Both microcode and ctree use the following class:
#   lvar_t       a local variable. may represent a stack or register
#                variable. a variable has a name, type, location, etc.
#                the list of variables is stored in mba->vars.
#   lvar_locator_t holds a variable location (vdloc_t) and its definition
#                address.
#   vdloc_t      describes a variable location, like a register number,
#                a stack offset, or, in complex cases, can be a mix of
#                register and stack locations. very similar to argloc_t,
#                which is used in ida. the differences between argloc_t
#                and vdloc_t are:
#                  - vdloc_t never uses ARGLOC_REG2
#                  - vdloc_t uses micro register numbers instead of
#                    processor register numbers
#                  - the stack offsets are never negative in vdloc_t, while
#                    in argloc_t there can be negative offsets

#class HxFlagCvar(object):
#    """
#        Enum of the value used in the :meth:`~HxVar.flags` of the hexrays
#        local variable :class:`HxVar` . Comment are from hexrays.
#    """
#    CVAR_USED    0x00000001 #: is used in the code?                      
#    CVAR_TYPE    0x00000002 #: the type is defined?                      
#    CVAR_NAME    0x00000004 #: has nice name?                            
#    CVAR_MREG    0x00000008 #: corresponding mregs were replaced?        
#    CVAR_NOWD    0x00000010 #: width is unknown                          
#    CVAR_UNAME   0x00000020 #: user-defined name                         
#    CVAR_UTYPE   0x00000040 #: user-defined type                         
#    CVAR_RESULT  0x00000080 #: function result variable                  
#    CVAR_ARG     0x00000100 #: function argument                         
#    CVAR_FAKE    0x00000200 #: fake return variable                      
#    CVAR_OVER    0x00000400 #: overlapping variable                      
#    CVAR_FLOAT   0x00000800 #: used in a fpu insn                        
#    CVAR_SPOILED 0x00001000 #: internal flag, do not use: spoiled var    
#    CVAR_MAPDST  0x00002000 #: other variables are mapped to this var    
#    CVAR_PARTIAL 0x00004000 #: variable type is partialy defined         
#    CVAR_THISARG 0x00008000 #: 'this' argument of c++ member functions   
#    CVAR_FORCED  0x00010000 #: variable was created by an explicit request otherwise we could reuse an existing var  



class HxLvar(object):
    """
        Python object for representing a local variable of hexrays.

        .. todo:: flags (not accessible publicly)
        ., todo:: setters
        ., todo:: type info
        .. todo:: raccord with cfunc_t (HxFunc)

        .. todo:: test
    """

    def __init__(self, lvar):
        """
            Constructor for the :class:`HxLvar` representing a local variable
            from hexrays.

            .. todo:: test

            :param lvar: A ``lvar_t`` object from hexrays (those are swig
                proxy) which is the ida variable corresponding to this object.
        """
        self._lvar = lvar

    #################################### BASE ################################

    @property
    def name(self):
        """
            Property which return the name of this local variable.

            .. todo:: test

            :return str: The name of the variable
        """
        return self._lvar.name

    #@name.setter
    #def name(self, value):
    #    # TODO need mbl_array_t access

    @property
    def size(self):
        return self._lvar.width

    @property
    def comment(self):
        """
            Property which return the comment of the lvar.

            .. todo:: test

            :return: The value of the comment or ``None`` if there is no
                comment.
            :rtype: :class:`str`
        """
        return self._lvar.cmt

    #@comment.setter
    #def comment(self, value):
    #    # TODO: no idea how to do this

    @property
    def _ida_tinfo(self):
        """
            Internal property which allow to get the ``tinfo_t`` swig proxy
            from IDA associated with this lvar.

            :return: The ``ida_typeinf.tinfo_t`` object (swig proxy) provided
                by IDA for this structure.
        """
        return self._lvar.type()

    #@property
    #def type(self):
    #    # TODO

    ################################ FLAGS ##################################

    @property
    def is_arg(self):
        """
            Property which return true if this local variable is an argument
            of this function, false otherwise.

            .. todo:: test

            :return: bool
        """
        return self._lvar.is_arg_var

    @is_arg.setter
    def is_arg(self, value):
        """
            Setter which allow to change if this local variable should be
            considered as an argument of this function.

            .. todo:: test

            :param bool value: If ``True`` this local variable will now be
                considered as an argument, if ``False`` this local variable
                will not be considered as an argument anymore. If this is not
                a boolean a ``TypeError`` will be raised.
        """
        if not isinstance(value, bool):
            raise TypeError("HxLvar.is_arg setter expect a boolean value")
        if value:
            self._lvar.set_arg_var()
        else:
            self._lvar.clr_arg_var()





