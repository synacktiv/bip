
class HxCType(object):
    """
        Enum and static methods for manipulating the C type defined by
        HexRays. This is a wrapper on top of the ``ctype_t`` enum: ``cot_*``
        are for the expresion (``cexpr_t`` in ida, :class:`HxCExpr` in bip )
        and ``cit_*`` are for the statement (``cinsn_t`` in ida,
        :class:`HxCStmt` in bip). This also include some static function
        which are wrapper which manipulate those types.

        .. todo:: static function for manipulating the enum ?

        Comment on the enum are from ``hexrays.hpp`` .
    """
    COT_EMPTY       = 0
    COT_COMMA       = 1     #: ``x, y``
    COT_ASG         = 2     #: ``x = y``
    COT_ASGBOR      = 3     #: ``x |= y``
    COT_ASGXOR      = 4     #: ``x ^= y``
    COT_ASGBAND     = 5     #: ``x &= y``
    COT_ASGADD      = 6     #: ``x += y``
    COT_ASGSUB      = 7     #: ``x -= y``
    COT_ASGMUL      = 8     #: ``x *= y``
    COT_ASGSSHR     = 9     #: ``x >>= y`` signed
    COT_ASGUSHR     = 10    #: ``x >>= y`` unsigned
    COT_ASGSHL      = 11    #: ``x <<= y``
    COT_ASGSDIV     = 12    #: ``x /= y`` signed
    COT_ASGUDIV     = 13    #: ``x /= y`` unsigned
    COT_ASGSMOD     = 14    #: ``x %= y`` signed
    COT_ASGUMOD     = 15    #: ``x %= y`` unsigned
    COT_TERN        = 16    #: ``x ? y : z``
    COT_LOR         = 17    #: ``x || y``
    COT_LAND        = 18    #: ``x && y``
    COT_BOR         = 19    #: ``x | y``
    COT_XOR         = 20    #: ``x ^ y``
    COT_BAND        = 21    #: ``x & y``
    COT_EQ          = 22    #: ``x == y`` int or fpu (see EXFL_FPOP)
    COT_NE          = 23    #: ``x != y`` int or fpu (see EXFL_FPOP)
    COT_SGE         = 24    #: ``x >= y`` signed or fpu (see EXFL_FPOP)
    COT_UGE         = 25    #: ``x >= y`` unsigned
    COT_SLE         = 26    #: ``x <= y`` signed or fpu (see EXFL_FPOP)
    COT_ULE         = 27    #: ``x <= y`` unsigned
    COT_SGT         = 28    #: ``x >  y`` signed or fpu (see EXFL_FPOP)
    COT_UGT         = 29    #: ``x >  y`` unsigned
    COT_SLT         = 30    #: ``x <  y`` signed or fpu (see EXFL_FPOP)
    COT_ULT         = 31    #: ``x <  y`` unsigned
    COT_SSHR        = 32    #: ``x >> y`` signed
    COT_USHR        = 33    #: ``x >> y`` unsigned
    COT_SHL         = 34    #: ``x << y``
    COT_ADD         = 35    #: ``x + y``
    COT_SUB         = 36    #: ``x - y``
    COT_MUL         = 37    #: ``x * y``
    COT_SDIV        = 38    #: ``x / y`` signed
    COT_UDIV        = 39    #: ``x / y`` unsigned
    COT_SMOD        = 40    #: ``x % y`` signed
    COT_UMOD        = 41    #: ``x % y`` unsigned
    COT_FADD        = 42    #: ``x + y`` fp
    COT_FSUB        = 43    #: ``x - y`` fp
    COT_FMUL        = 44    #: ``x * y`` fp
    COT_FDIV        = 45    #: ``x / y`` fp
    COT_FNEG        = 46    #: ``-x`` fp
    COT_NEG         = 47    #: ``-x``
    COT_CAST        = 48    #: ``(type)x``
    COT_LNOT        = 49    #: ``!x``
    COT_BNOT        = 50    #: ``~x``
    COT_PTR         = 51    #: ``*x``, access size in 'ptrsize'
    COT_REF         = 52    #: ``&x``
    COT_POSTINC     = 53    #: ``x++``
    COT_POSTDEC     = 54    #: ``x--``
    COT_PREINC      = 55    #: ``++x``
    COT_PREDEC      = 56    #: ``--x``
    COT_CALL        = 57    #: ``x(...)``
    COT_IDX         = 58    #: ``x[y]``
    COT_MEMREF      = 59    #: ``x.m``
    COT_MEMPTR      = 60    #: ``x->m``, access size in 'ptrsize'
    COT_NUM         = 61    #: n
    COT_FNUM        = 62    #: fpc
    COT_STR         = 63    #: string constant
    COT_OBJ         = 64    #: obj_ea
    COT_VAR         = 65    #: v
    COT_INSN        = 66    #: instruction in expression, internal representation only
    COT_SIZEOF      = 67    #: ``sizeof(x)``
    COT_HELPER      = 68    #: arbitrary name
    COT_TYPE        = 69    #: arbitrary type
    COT_LAST        = 69    #: All before this are ``cexpr_t`` after are ``cinsn_t``
    CIT_EMPTY       = 70    #: instruction types start here
    CIT_BLOCK       = 71    #: block-statement: { ... }
    CIT_EXPR        = 72    #: expression-statement: expr;
    CIT_IF          = 73    #: if-statement
    CIT_FOR         = 74    #: for-statement
    CIT_WHILE       = 75    #: while-statement
    CIT_DO          = 76    #: do-statement
    CIT_SWITCH      = 77    #: switch-statement
    CIT_BREAK       = 78    #: break-statement
    CIT_CONTINUE    = 79    #: continue-statement
    CIT_RETURN      = 80    #: return-statement
    CIT_GOTO        = 81    #: goto-statement
    CIT_ASM         = 82    #: asm-statement
    CIT_END         = 83


class AbstractCItem(object):
    """
        Abstract class for common element between :class:`HxCItem` and
        :class:`CNode`.


        .. todo:: precise what this class provides

        .. todo:: add cmp operators
    """
    #: Class attribute indicating which type of item this class handles,
    #:  this is used for determining if this is the good object to
    #:  instantiate. All abstract class should have a value of -1 for this
    #:  object, non-abstract class should have a value corresponding to the
    #:  :class:`HxCType` they handle.
    TYPE_HANDLE = -1

    def __init__(self, citem):
        """
            Constructor for the abstract class :class:`HxCItem` . This should
            never be used directly.

            :param citem: a ``citem_t`` object, in practice this should always
                be a ``cexpr_t`` or a ``cinsn_t`` object.
        """
        #: The ``citem_t`` object from ida, this is conserved at this level
        #:  for providing a few functionnality compatible between different
        #:  item types (such as :class:`HxCExpr` and :class:`HxCStmt`) .
        self._citem = citem

    ############################ BASE METHODS ##########################

    @property
    def ea(self):
        """
            Property which return the address corresponding to this item.

            :return: An integer corresponding to the address of the item. This
                may be ``idc.BADADDR`` if the item as no equivalent address.
        """
        return self._citem.ea

    @property
    def is_expr(self):
        """
            Property which return true if this item is a C Expression
            (:class:`HxCExpr`, ``cexpr_t``).
        """
        return self._citem.is_expr()

    @property
    def is_statement(self):
        """
            Property which return true if this item is a C Statement
            (:class:`HxCStmt`, ``cinsn_t``).
        """
        return not self.is_expr

    @property
    def _ctype(self):
        """
            Property which return the :class:`HxCType` (``ctype_t``) of this
            object.

            :return int: One of the :class:`HxCType` constant value.
        """
        return self._citem.op

    def __str__(self):
        """
            Convert a citem to a string.

            This is surcharge both by :class:`HxCStmt` and :class:`HxCExpr`.
        """
        return "{}(ea=0x{:X})".format(self.__class__.__name__, self.ea)

    ########################## LABEL METHODS ###########################

    @property
    def has_label(self):
        """
            Property which return True if the node has a label number.
        """
        return self._citem.label_num != -1

    @property
    def label_num(self):
        """
            Property which return the label number of the node. If this node
            has no label ``-1`` is return. :meth:`~AbstractCItem.has_label`
            allows to check if the node has a label.
        """
        return self._citem.label_num

    ########################### CMP METHODS ###############################

    def __eq__(self, other):
        """
            Compare to AST node. This is base on the compare implemented by
            hexrays and can return true for two different object including
            for comparing object which inherit from :class:`HxCItem` and from
            :class:`CNode`.

            This seems to not work if the function has been recompiled.

            Return ``NotImplemented`` if the element to compare does not
                inherit from AbstractCItem
        """
        if not isinstance(other, AbstractCItem):
            return NotImplemented
        return self._citem == other._citem

    def __ne__(self, other):
        res = self.__eq__(other)
        if res == NotImplemented:
            return res
        else:
            return not res

    ############################ INHERITANCE METHODS #########################

    def _createChild(self, obj):
        """
            Abstract method which allow to create child element for this
            object with the correct class. This should be implemented by child
            classes and will raise a :class:`NotImplementedError` exception
            if not surcharge.
        """
        raise NotImplementedError("_createChild is an abstract method and should be surcharge by child class")

    ############################ CLASS METHODS ##########################

    @classmethod
    def is_handling_type(cls, typ):
        """
            Class method which return True if the function handle the type
            passed as argument.

            :param typ: One of the :class:`HxCType` value.
        """
        return cls.TYPE_HANDLE == typ


