from .hx_citem import HxCType, HxCItem, HxCStmt
from . import cnode
import bip.base as bbase

@cnode.buildCNode
class HxCStmtFinal(HxCStmt):
    """
        Abstract class for representing a :class:`HxCStmt` which does not
        posess child statements but as a value. All the child must have a
        :meth:`~HxCStmtFinal.value` property which return the value of the
        statement.

        This is used as a parent for:

        * :class:`HxCStmtExpr`
        * :class:`HxCStmtGoto`
        * :class:`HxCStmtFinal`
        * :class:`HxCStmtReturn`

        The :class:`HxCStmtContinue` and :class:`HxCStmtBreak` do not inherit
        from this class as they do not have a value.
    """

    def __str__(self):
        """
            Surcharge for printing a HxCExprFinal.
        """
        return "{}(ea=0x{:X}, value={})".format(self.__class__.__name__, self.ea, self.value)

    @property
    def value(self):
        """
            Property which return the value of a final expression. This is
            abstract and if not overwritten it will raise a
            :class:`RuntimeError` .
        """
        raise RuntimeError("Abstract property value access.")

@cnode.buildCNode
class HxCStmtEmpty(HxCStmt):
    """
        Class for representing a statement which is empty.
    """
    TYPE_HANDLE = HxCType.CIT_EMPTY

@cnode.buildCNode
class HxCStmtExpr(HxCStmtFinal):
    """
        Class for representing a statement which contain a single expression.
        In practice this class is used for making the transition between
        :class:`HxCStmt` and :class:`HxCExpr` .
    """
    TYPE_HANDLE = HxCType.CIT_EXPR


    @property
    def expr(self):
        """
            Property which return the expression contain in this statement.

            :return: A child object of :class:`HxCExpr` which represent the
                expression contain in this statement.
        """
        return self._create_child(self._cinsn.cexpr)

    @property
    def value(self):
        """
            The expression contain in this statement.

            :return: A child object of :class:`HxCExpr` which represent the
                expression contain in this statement.
        """
        return self.expr

    @property
    def expr_children(self):
        return [self.expr]

@cnode.buildCNode
class HxCStmtGoto(HxCStmtFinal):
    """
        Class for representing a C *goto* statement (``HxCType.CIT_GOTO``).
    """
    TYPE_HANDLE = HxCType.CIT_GOTO

    @property
    def label(self):
        """
            Property which return the label number of the goto statement.

            :return: An integer representing the label number.
        """
        return self._cinsn.cgoto.label_num
    
    @property
    def value(self):
        """
            Return the label number see :meth:`~HxCStmtGoto.label` .
        """
        return self.label

@cnode.buildCNode
class HxCStmtAsm(HxCStmtFinal):
    """
        Class for representing a inline C ASM statement (``HxCType.CIT_ASM``).
    """
    TYPE_HANDLE = HxCType.CIT_ASM

    @property
    def addr_instr(self):
        """
            Property which return a list of address corresponding to the ASM
            instruction which are inline.

            :return: A list of address (integer) representing the address of
                the inline assembly instruction in the binary.
        """
        return list(self._cinsn.casm)

    @property
    def length(self):
        """
            Property which return the number of instruction in this ASM
            statement.
        """
        return self._cinsn.casm.size()

    def __len__(self):
        """
            Return the number of instruction in this ASM statement. Same
            as :meth:`~HxCStmtAsm.length`
        """
        return self.length

    @property
    def value(self):
        """
            Return a list of :class:`~bip.base.BipInstr` corresponding to the ASM
            instructions in this ASM statement.

            :return: A list of :class:`~bip.base.BipInstr`.
        """
        return [bbase.BipInstr(ea) for ea in self._cinsn.casm]

@cnode.buildCNode
class HxCStmtReturn(HxCStmtFinal):
    """
        Class for representing a C *return* statement (``HxCType.CIT_RETURN``).
    """
    TYPE_HANDLE = HxCType.CIT_RETURN

    @property
    def ret_val(self):
        """
            Property which return the expression which is the value return by
            this *return* statement.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        return self._create_child(self._cinsn.creturn.expr)

    @property
    def value(self):
        """
            Return the :class:`HxCExpr` which is return by this statement. See
            :meth:`~HxCStmtReturn.ret_val` .
        """
        return self.ret_val

    @property
    def expr_children(self):
        return [self.ret_val]



@cnode.buildCNode
class HxCStmtIf(HxCStmt):
    """
        Class for representing a C *if* statement (``HxCType.CIT_IF``).
        This is a recursive statement with 2 or 3 child statement depending
        if a else condition is present.
    """
    TYPE_HANDLE = HxCType.CIT_IF

    @property
    def cond(self):
        """
            Property which return the expression used as a condition for the
            if.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        return self._create_child(self._cinsn.cif.expr)

    @property
    def st_then(self):
        """
            Property which return the statement executed if the condition
            (:meth:`~HxCStmtIf.cond`) is true.

            :return: An object which inherits from :class:`HxCStmt` .
        """
        return self._create_child(self._cinsn.cif.ithen)

    @property
    def has_else(self):
        """
            Property which indicate if this if statement as an else condtion.

            :return: True if this statement has an else condition, False
                otherwise.
        """
        return self._cinsn.cif.ielse is not None

    @property
    def st_else(self):
        """
            Property which return the executed if the condition
            (:meth:`~HxCStmtIf.cond`) is False.

            This property will return ``None`` if this condition has no else
            statement. This can be tested by checking
            :meth:`~HxCStmtIf.has_else` .

            :return: An object which inherits from :class:`HxCStmt` .
        """
        if self.has_else:
            return self._create_child(self._cinsn.cif.ielse)
        else:
            return None

    @property
    def stmt_children(self):
        if self.has_else:
            return [self.st_then, self.st_else]
        else:
            return [self.st_then]

    @property
    def expr_children(self):
        return [self.cond]

@cnode.buildCNode
class HxCStmtLoop(HxCStmt):
    """
        Abstract class for representing the different C loop statement
        (for, while, dowhile). All of those have at least an expression as a
        condition (:meth:`~HxCStmtLoop.cond`) and a statement as body
        (:meth:`~HxCStmtLoop.st_body`)
    """

    @property
    def cond(self):
        """
            Property which return the expression used as a condition for
            the loop.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        raise RuntimeError("Abstract property value access.")

    @property
    def st_body(self):
        """
            Property which return the statement used as a body for the loop.

            :return: An object which inherits from :class:`HxCStmt` .
        """
        raise RuntimeError("Abstract property value access.")

@cnode.buildCNode
class HxCStmtFor(HxCStmtLoop):
    """
        Class for representing a C *for* statement (``HxCType.CIT_FOR``).
        This is a recursive statement which have 2 children statement and
        2 children expression.

        The for of the for is the following:

        .. code-block:: none
            
            for (init; cond; step)
                st_body
    """
    TYPE_HANDLE = HxCType.CIT_FOR

    @property
    def cond(self):
        """
            Property which return the expression used as a condition for
            the *for*.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        return self._create_child(self._cinsn.cfor.expr)

    @property
    def st_body(self):
        """
            Property which return the statement used as a body for the *for*.

            :return: An object which inherits from :class:`HxCStmt` .
        """
        return self._create_child(self._cinsn.cfor.body)

    @property
    def init(self):
        """
            Property which return the expression for the initialization of
            the *for* loop.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        return self._create_child(self._cinsn.cfor.init)

    @property
    def step(self):
        """
            Property which return the expression for the step of the *for*
            loop.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        return self._create_child(self._cinsn.cfor.step)

    @property
    def stmt_children(self):
        return [self.st_body]

    @property
    def expr_children(self):
        return [self.init, self.cond, self.step]

@cnode.buildCNode
class HxCStmtWhile(HxCStmtLoop):
    """
        Class for representing a C *while* statement (``HxCType.CIT_WHILE``).
        This is a recursive statement.
    """
    TYPE_HANDLE = HxCType.CIT_WHILE

    @property
    def cond(self):
        """
            Property which return the expression used as a condition for
            the *while*.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        return self._create_child(self._cinsn.cwhile.expr)

    @property
    def st_body(self):
        """
            Property which return the statement used as a body for the
            *while*.

            :return: An object which inherits from :class:`HxCStmt` .
        """
        return self._create_child(self._cinsn.cwhile.body)

    @property
    def stmt_children(self):
        return [self.st_body]

    @property
    def expr_children(self):
        return [self.cond]

@cnode.buildCNode
class HxCStmtDoWhile(HxCStmtLoop):
    """
        Class for representing a C *do-while* statement (``HxCType.CIT_DO``).
        This is a recursive statement.
    """
    TYPE_HANDLE = HxCType.CIT_DO

    @property
    def cond(self):
        """
            Property which return the expression used as a condition for
            the *do-while*.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        return self._create_child(self._cinsn.cdo.expr)

    @property
    def st_body(self):
        """
            Property which return the statement used as a body for the
            *do-while*.

            :return: An object which inherits from :class:`HxCStmt` .
        """
        return self._create_child(self._cinsn.cdo.body)

    @property
    def stmt_children(self):
        return [self.st_body]

    @property
    def expr_children(self):
        return [self.cond]

@cnode.buildCNode
class HxCStmtSwitch(HxCStmt):
    """
        Class for representing a C *switch* statement
        (``HxCType.CIT_SWITCH``). This is a recursive statement. This also
        allow to get the cases value.

        A switch statement as the following form:

        .. code-block:: C
            
            switch (expr) { // statement expression for the switch
                
                case cases_val[0][0]: // first value for the first case
                case cases_val[0][1]: // second value for the first case
                // ...
                    st_cases[0]; //  statement for the first case

                case cases_val[1][0]: // first value for the second case
                // ...
                    st_cases[1]; //  statement for the second case

                // ...

                default: // when cases_val[x] is empty
                    st_cases[x]; // statement for the default case
                
            }

        .. todo:: make something for accessing the default statement.

        .. todo:: this should be accessible as a dict (correspond well to a
            switch statement).
    """
    TYPE_HANDLE = HxCType.CIT_SWITCH

    @property
    def expr(self):
        """
            Property which return the expression used as the *switch*
            expression.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        return self._create_child(self._cinsn.cswitch.expr)

    @property
    def max_val(self):
        """
            Property which return the case maximum value for the switch.

            :return: An integer which is the maximum case value for the
                switch.
        """
        return self._cinsn.cswitch.mvnf._value

    @property
    def st_cases(self):
        """
            Property which return the statement used in the different cases.

            :return: A list of statements representing the different possible
                cases of this switch.
            :rtype: Objects which inherit from :class:`HxCStmt` .
        """
        return [self._create_child(i) for i in self._cinsn.cswitch.cases]

    @property
    def cases_val(self):
        """
            Property which return the list of values for each statement. This
            list is in the same order as the list of statement return by
            :meth:`~HxCStmtSwitch.st_cases` .

            As each case can have several values for triggering it, this
            property return a list of list of values.

            :return: A list of lists of values (int), each list correspond to
                a different case and contain the values which will make the
                code enter this path. An empty list means it the default case.
        """
        return [list(c.values) for c in self._cinsn.cswitch.cases]

    @property
    def stmt_children(self):
        return self.st_cases

    @property
    def expr_children(self):
        return [self.expr]

@cnode.buildCNode
class HxCStmtContinue(HxCStmt):
    """
        Class for representing a C *continue* statement
        (``HxCType.CIT_CONTINUE``). This is not recursive nor as a value.
    """
    TYPE_HANDLE = HxCType.CIT_CONTINUE

@cnode.buildCNode
class HxCStmtBreak(HxCStmt):
    """
        Class for representing a C *break* statement
        (``HxCType.CIT_BREAK``). This is not recursive nor as a value.
    """
    TYPE_HANDLE = HxCType.CIT_BREAK


@cnode.buildCNode
class HxCStmtBlock(HxCStmt):
    """
        Class for representing a *block* statement meaning a list of other
        statement (``HxCType.CIT_BLOCK``).

        .. todo:: make this directly accessible as an iterator.

    """
    TYPE_HANDLE = HxCType.CIT_BLOCK

    @property
    def elts(self):
        """
            Property which return the list of child statement included in this
            block.

            :return: The list of child statement of this block.
            :rtype: Objects which inherit from :class:`HxCStmt` .
        """
        return [self._create_child(e) for e in self._cinsn.cblock]

    @property
    def stmt_children(self):
        return self.elts



