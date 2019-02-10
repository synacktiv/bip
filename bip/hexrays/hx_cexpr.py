
from hx_citem import HxCType, HxCItem, GetHxCItem

# TODO: change Statement by Stmt

# TODO: this file should probably be split

# TODO: make a parent class for all final operators:
#    COT_NUM         = 61    #: n   
#    COT_FNUM        = 62    #: fpc 
#    COT_STR         = 63    #: string constant
#    COT_OBJ         = 64    #: obj_ea
#    COT_VAR         = 65    #: v
#    COT_INSN        = 66
#    COT_HELPER      = 68    #: arbitrary name
#    COT_TYPE        = 69    #: arbitrary type

# TODO: implement COT_INSN and COT_TYPE


class HxCExpr(HxCItem):
    """
        Abstract class for representing a C Expression as returned by
        HexRays. This is an abstract class which is used as a wrapper on top
        of the ``cexpr_t`` object.

        No object of this class should be instanstiated, for getting an
        expression the function :func:`~hx_citem.GetHxCItem` should be used.

        .. todo:: implem exflags
        .. todo:: implem everything in ``cexpr_t``
    """

    def __init__(self, cexpr):
        """
            Constructor for a :class:`HxCExpr` object.

            :param cexpr: A ``cexpr_t`` object from ida.
        """
        super(HxCExpr, self).__init__(cexpr)
        #: The ``cexpr_t`` object from ida.
        self._cexpr = cexpr

    def __str__(self):
        """
            Surcharge for printing a CExpr
        """
        return "{}(ea=0x{:X}, ops={})".format(self.__class__.__name__, self.ea, self.ops)

    @property
    def ops(self):
        """
            Function which return the C Expressions child of this expression.
            This is used only when the expression is recursive.

            :return: A ``list`` of object inheriting from :class:`HxCExpr` and
                child of the current expression.
        """
        return []

class HxCExprNum(HxCExpr):
    """
        Class for representing a CExpr containing a Number
        (``HxCType.COT_NUM``). 

        .. todo:: test

        .. todo:: make an assign function with full access to all the value.

        .. todo:: flags, should make accessible and settable the flags see
            ``number_format_t`` in ``hexrays.cpp``

        .. todo:: make accessible the serial and the type_name from ``number_format_t`` .
    """
    TYPE_HANDLE = HxCType.COT_NUM

    @property
    def value(self):
        """
            Value of the number.

            :return int: the value of this number.
        """
        #return self._cexpr.n._value
        return self._cexpr.n.value(self._cexpr.type)

    @value.setter
    def value(self, val):
        """
            Setter for the value of the expression.

            :param int val: the integer representing this number.
        """
        self._cexpr.n.assign(val, self.size, 0)
        

    @property
    def size(self):
        """
            Original size in bytes of the number.

            :return int: the size in bytes.
        """
        return self._cexpr.n.nf.org_nbyes

class HxCExprFNum(HxCExpr):
    """
        Class for representing a Floating number (``HxCType.COT_FNUM``).

        .. todo:: everything, see ``fnumber_t`` in ``hexrays.hpp`` and
            ``ida_hexrays.py``

    """
    TYPE_HANDLE = HxCType.COT_FNUM

    @property
    def value(self):
        """
            .. todo:: not sure if this works at all and probably not what we
                want anyway.
        """
        return self._cexpr.fpc.fnum

    @property
    def size(self):
        """
            Original size in bytes of the number.

            :return int: the size in bytes.
        """
        return self._cexpr.fpc.nbytes

class HxCExprStr(HxCExpr):
    """
        Class for representing a string (``HxCType.COT_STR``).

        .. todo:: test

        .. todo:: equality operator with string

        .. todo:: everything

    """
    TYPE_HANDLE = HxCType.COT_STR

    @property
    def value(self):
        """
            String value.

            :return str: the value of this string.
        """
        return self._cexpr.string

class HxCExprObj(HxCExpr):
    """
        Class for representing an object (``HxCType.COT_OBJ``).

        .. todo:: test

        .. todo:: everything

    """
    TYPE_HANDLE = HxCType.COT_OBJ

    @property
    def value(self):
        """
            Address of the object.

            .. todo:: not sure test this

            :return int: the address of the object.
        """
        return self._cexpr.obj_ea

class HxCExprVar(HxCExpr):
    """
        Class for representing a variable (``HxCType.COT_VAR``).

        .. todo:: test

        .. todo:: link with variables

    """
    TYPE_HANDLE = HxCType.COT_VAR

    @property
    def value(self):
        """
            Index in the lvar array.

            .. todo:: this should probably directly return the lvar ?

            :return int: the index in the lvar array.
        """
        return self.index

    @property
    def index(self):
        """
            Index in the lvar array.

            .. todo:: this should probably directly return the lvar ?

            :return int: the index in the lvar array.
        """
        return self._cexpr.v.idx

class HxCExprHelper(HxCExpr):
    """
        Class  for representing an helper string (``HxCType.COT_HELPER``) .
    """
    TYPE_HANDLE = HxCType.COT_HELPER

    @property
    def value(self):
        """
            Value of this helper.

            :return str: the string containing the value of the helper.
        """
        return self._cexpr.helper

class HxCExprInsn(HxCExpr):
    """
        Class for representing an instruction in expression
        (``HxCType.COT_INSN``). 
        
        .. warning:: Do not confound with :class:`HxCStmt` this is a statement.
        
        .. todo:: implement this, this should be link we the statement I think
    """
    TYPE_HANDLE = HxCType.COT_INSN

    @property
    def value(self):
        raise NotImplemented("HxCInsn is not implemented")

class HxCExprType(HxCExpr):
    """
        Class for representing a type (``HxCType.COT_TYPE``). 
        
        .. todo:: implement this, this should be link we the statement I think
    """
    TYPE_HANDLE = HxCType.COT_TYPE

    @property
    def value(self):
        raise NotImplemented("HxCInsn is not implemented")

class HxCExprTernary(HxCExpr):
    """
        Class for representing a ternary operation (``cond ? expr1 : expr2``)
        (``HxCType.COT_TERN``). 

        This class contain 3 operands which are recursive.
    """
    TYPE_HANDLE = HxCType.COT_TERN

    @property
    def cond(self):
        """
            Property which return the condition of the ternary expression.

            :return: An object which inherit from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cexpr.x)

    @property
    def expr1(self):
        """
            Property which return the first expression of the ternary
            expression: the one executed if the condition
            :meth:`~HxCTernary.cond` is true.

            :return: An object which inherit from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cexpr.y)

    @property
    def expr2(self):
        """
            Property which return the second expression of the ternary
            expression: the one executed if the condition
            :meth:`~HxCTernary.cond` is false.

            :return: An object which inherit from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cexpr.z)


    @property
    def ops(self):
        return [self.cond, self.expr1, self.expr2]

class HxCExprDoubleOperation(HxCExpr):
    """
        Abstract class for representing a :class:`HxCExpr` with two operands.
        Those operands are also :class:`HxCExpr` making them recursive.
    """

    @property
    def first_op(self):
        """
            Property which return the first operand.

            :return: The first operand of the expression, an object which
                inherit from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cexpr.x)

    @property
    def second_op(self):
        """
            Property which return the second operand.

            :return: The second operand of the expression, an object which
                inherit from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cexpr.y)

    @property
    def ops(self):
        return [self.first_op, self.second_op]

class HxCExprComma(HxCExprDoubleOperation):
    """
        C Expression for a comma expression.
        
        .. todo:: wtf is a comma expression.
    """
    TYPE_HANDLE = HxCType.COT_COMMA

## BEGIN REGEX GENERATED INHERITED FROM HxCExprDoubleOperation
# TODO: clean this

class HxCExprAsg(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASG


class HxCExprAsgbor(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGBOR


class HxCExprAsgxor(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGXOR


class HxCExprAsgband(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGBAND


class HxCExprAsgadd(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGADD


class HxCExprAsgsub(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGSUB


class HxCExprAsgmul(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGMUL


class HxCExprAsgsshr(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGSSHR


class HxCExprAsgushr(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGUSHR


class HxCExprAsgshl(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGSHL


class HxCExprAsgsdiv(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGSDIV


class HxCExprAsgudiv(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGUDIV


class HxCExprAsgsmod(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGSMOD


class HxCExprAsgumod(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ASGUMOD


class HxCExprLor(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_LOR


class HxCExprLand(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_LAND


class HxCExprBor(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_BOR


class HxCExprXor(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_XOR


class HxCExprBand(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_BAND


class HxCExprEq(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_EQ


class HxCExprNe(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_NE


class HxCExprSge(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_SGE


class HxCExprUge(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_UGE


class HxCExprSle(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_SLE


class HxCExprUle(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ULE


class HxCExprSgt(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_SGT


class HxCExprUgt(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_UGT


class HxCExprSlt(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_SLT


class HxCExprUlt(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ULT


class HxCExprSshr(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_SSHR


class HxCExprUshr(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_USHR


class HxCExprShl(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_SHL


class HxCExprAdd(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_ADD


class HxCExprSub(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_SUB


class HxCExprMul(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_MUL


class HxCExprSdiv(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_SDIV


class HxCExprUdiv(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_UDIV


class HxCExprSmod(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_SMOD


class HxCExprUmod(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_UMOD


class HxCExprFadd(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_FADD


class HxCExprFsub(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_FSUB


class HxCExprFmul(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_FMUL


class HxCExprFdiv(HxCExprDoubleOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprDoubleOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_FDIV

## END REGEX GENERATED INHERITED FROM HxCExprDoubleOperation

class HxCExprUnaryOperation(HxCExpr):
    """
        Abstract for representing a :class:`HxCExpr` with a unary operation.
        This :meth:`HxCExprUnaryOperation.operand` is also a :class:`HxCExpr`
        making it recursive.
    """

    @property
    def operand(self):
        """
            Property which return the operand of this expression.

            :return: The operand of the expression, an object which
                inherit from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cexpr.x)

    @property
    def ops(self):
        return [self.operand]

class HxCExprPtr(HxCExprUnaryOperation):
    """
        Class for representing the deref. of a pointer (``*operand``). This
        inherit from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_PTR

    @property
    def access_size(self):
        """
            Property which return the size which is access by the
            derefencement of this pointer.

            :return: An int corresponding to the size acceded.
        """
        return self._cexpr.ptrsize

## BEGIN REGEX GENERATED INHERITED FROM HxCExprUnaryOperation

class HxCExprFneg(HxCExprUnaryOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_FNEG


class HxCExprNeg(HxCExprUnaryOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_NEG


class HxCExprCast(HxCExprUnaryOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_CAST


class HxCExprLnot(HxCExprUnaryOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_LNOT


class HxCExprBnot(HxCExprUnaryOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_BNOT


class HxCExprRef(HxCExprUnaryOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_REF


class HxCExprPostinc(HxCExprUnaryOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_POSTINC


class HxCExprPostdec(HxCExprUnaryOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_POSTDEC


class HxCExprPreinc(HxCExprUnaryOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_PREINC


class HxCExprPredec(HxCExprUnaryOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_PREDEC

class HxCExprSizeof(HxCExprUnaryOperation):
    """
        See :class:`HxCType` for description.
        Inherited from :class:`HxCExprUnaryOperation`.

        .. todo:: make better description
    """
    TYPE_HANDLE = HxCType.COT_SIZEOF

## END REGEX GENERATED INHERITED FROM HxCExprUnaryOperation

class HxCExprCall(HxCExpr):
    """
        Class for representing a call expression. This class also provide
        function which allow to manipulate the arguments.

        .. todo:: test this

        .. todo:: function type (carglist_t.functype)
        .. todo:: args type (carg.formal_type)
        .. todo:: vararg (carg.is_vararg) (variadic number of arguments, like printf)
        .. todo:: make a function which try to directly get the function
            called by this expr.

        TODO
    """
    TYPE_HANDLE = HxCType.COT_CALL

    ## Internal

    @property
    def _carglist(self):
        """
            Property which return the ``carglist_t`` from IDA.
        """
        return self._cexpr.a

    def _get_carg(self, num):
        """
            Internal function which give access to the argument at position
            number ``num``. There is no check on the value of num.
            
            .. todo:: test this
        """
        return self._cexpr.a[num]

    ## Caller

    @property
    def caller(self):
        """
            Property which return the caller of this expression. The caller
            is also an expression.

            :return: An object which inherit from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cexpr.x)

    @property
    def is_helper(self):
        """
            Property which return true if this function is a decompiler helper
            function.

            .. todo:: check but this is probably for intrasec and stuff like
                memcpy with rep movsd.

            :return: A bool indicating if this is a helper function (true) or
                a "real" call.
        """
        return (self._carglist.flags & ida_hexrays.CFL_HELPER) != 0

    ## Args

    @property
    def number_args(self):
        """
            Property which return the number of arguments pass to the call
            expresion.

            .. todo:: test

            :return int: The number of argument to the call expression.
        """
        return self._carglist.size()
        #return len(list(self._carglist))

    def get_arg(self, num):
        """
            Function which return one of the argument of the call to a
            function. Each argument is also an expression.

            This function will raise a :class:`ValueError` if ``num`` is
            superior to the number of arguments in the call expression.
            
            :param int num: The argument number.
            :return: An object which inherit from :class:`HxCExpr` .
        """
        if num > self.number_args:
            raise ValueError("Trying to access arg {} when the call take only {} args".format(num, self.number_args))
        return GetHxCItem(self._get_carg(num))

    @property
    def args(self):
        """
            Property which return the args of the call. Those args are also
            expressions.

            .. todo:: test

            :return: A list of :class:`HxCExpr` .
        """
        return [GetHxCItem(i) for i in self._carglist]

    @property
    def args_iter(self):
        """
            Property which return an iterator on the args of the call. This
            is similar to :meth:`~HxCExprCall.args` but with an iterator, and
            should have more perf.
        """
        for i in self._carglist:
            yield GetHxCItem(i)

    @property
    def ops(self):
        return [self.caller] + self.args


class HxCExprIdx(HxCExpr):
    """
        Class for representing access to an index in an array
        (``array[index]``). The :meth:`array` is a :class:`HxCExpr`
        representing the array and :meth:`index` is a :class:`HxCExpr`
        representing the index which is access.
    """
    TYPE_HANDLE = HxCType.COT_IDX

    @property
    def array(self):
        """
            Property which return a :class:`HxCExpr` representing the array
            element access by this expression.

            :return: An operand of the expression, an object which
                inherit from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cexpr.x)

    @property
    def index(self):
        """
            Property which return a :class:`HxCExpr` representing the index
            of the element access by this expression.

            :return: An operand of the expression, an object which
                inherit from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cexpr.y)

    @property
    def ops(self):
        return [self.array, self.index]


class HxCExprMemref(HxCExpr):
    """
        Class for representing a memory reference
        (``mem.off``). The :meth:`mem` is a :class:`HxCExpr`
        representing the object which is access and :meth:`off` is an integer
        representing the memory offset.
    """
    TYPE_HANDLE = HxCType.COT_MEMREF

    @property
    def mem(self):
        """
            Property which return a :class:`HxCExpr` representing the object
            which is access by this expression.

            :return: An operand of the expression, an object which
                inherit from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cexpr.x)

    @property
    def off(self):
        """
            Property which return the memory offset which is access by this
            expression. In practice this should be an offset in a structure or
            an enum.

            :return int: The memory offset.
        """
        return self._cexpr.m


    @property
    def ops(self):
        return [self.mem, self.off]

class HxCExprMemptr(HxCExpr):
    """
        Class for representing a memory access using a pointer
        (``ptr->off``). The :meth:`ptr` is a :class:`HxCExpr`
        representing the object which is access and :meth:`off` is an integer
        representing the memory offset. :meth:`access_size` provide the size
        access by this expression.
    """
    TYPE_HANDLE = HxCType.COT_MEMPTR

    @property
    def ptr(self):
        """
            Property which return a :class:`HxCExpr` representing the object
            which is access by this expression.

            :return: An operand of the expression, an object which
                inherit from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cexpr.x)

    @property
    def off(self):
        """
            Property which return the memory offset which is access by this
            expression. In practice this should be an offset in a structure or
            an enum.

            :return int: The memory offset.
        """
        return self._cexpr.m

    @property
    def access_size(self):
        """
            Property which return the size which is access by the
            derefencement of this pointer.

            :return: An int corresponding to the size acceded.
        """
        return self._cexpr.ptrsize

    @property
    def ops(self):
        return [self.ptr, self.off]









