from hx_citem import HxCType, HxCItem, GetHxCItem

# TODO: implement CIT_EMPTY

class HxCStmt(HxCItem):
    """
        Abstract class for representing a C Statement as returned by hexrays.
        This is an abstract class which is a wrapper on top of the
        ``cinsn_t`` ida object.

        No object of this class should be instanstiated, for getting an
        expression the function :func:`~hx_citem.GetHxCItem` should be used.

        A statement can contain one or more child statement and one or more
        child expression (:class:`HxCExpr`) object.
        By convention properties which will return child statement of an
        object will start with the prefix ``st_`` .

        .. todo:: implem types

        .. todo:: implem things for modifying HxCStmt

        .. todo:: test
    """

    def __init__(self, cinsn):
        """
            Constructor for a :class:`HxCStmt` object.

            :param cinsn: A ``cinsn_t`` from ida.
        """
        super(HxCStmt, self).__init__(cinsn)
        #: The ``cinsn_t`` object from ida.
        self._cinsn = cinsn

    def __str__(self):
        """
            Surcharge for printing a CStmt.
        """
        return "{}(ea=0x{:X}, st_childs={})".format(self.__class__.__name__, self.ea, self.st_childs)

    @property
    def st_childs(self):
        """
            Property which return a list of the statements which are childs of
            this statement. This is used only when the statement is recursive,
            if not this will return an empty list.

            :return: A list of child statement of this object.
            :rtype: Objects which inherit from :class:`HxCStmt` .
        """
        return []

    @property
    def expr_childs(self):
        """
            Property which return a list of the expression (:class:`HxCExpr`)
            which are childs of this statement. This will not return childs
            expression of the statement child of the current object.

            :return: A list of child expression of this object.
            :rtype: Objects which inherit from :class:`HxCExpr` .
        """
        return []

class HxCStmtFinal(HxCStmt):
    """
        Abstract class for representing a :class:`HxCStmt` which does not
        posess child statements. All the child must have a
        :meth:`~HxCStmtFinal.value` property which return the value of the
        statement.

        This is used as a parent for:

        * :class:`HxCStmtExpr`
        * :class:`HxCStmtGoto`
        * :class:`HxCStmtFinal`
        * :class:`HxCStmtReturn`
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
        return GetHxCItem(self._cinsn.cexpr)

    @property
    def value(self):
        """
            The expression contain in this statement.

            :return: A child object of :class:`HxCExpr` which represent the
                expression contain in this statement.
        """
        return self.expr

    @property
    def expr_childs(self):
        return [self.expr]

class HxCStmtGoto(HxCStmtFinal):
    """
        Class for representing a C *goto* statement (``HxCType.CIT_GOTO``).
    """
    TYPE_HANDLE = HxCType.CIT_GOTO

    @property
    def label(self):
        """
            Property which return the label number of the goto statement.

            .. todo:: make something better ? Should be raccord to the label
                object ?

            :return: An integer representing the label number.
        """
        return self._cinsn.label_num
    
    @property
    def value(self):
        """
            Return the label number see :meth:`~HxCStmtGoto.label` .
        """
        return self.label

class HxCStmtAsm(HxCStmtFinal):
    """
        Class for representing a inline C ASM statement (``HxCType.CIT_ASM``).

        .. todo:: test this

        .. todo:: this is currently not supported by hexrays

        .. todo:: this should probably be link we the normal instruction ?

        .. todo:: this should be probably accessible as a list?
    """
    TYPE_HANDLE = HxCType.CIT_ASM

    @property
    def addr_instr(self):
        """
            Property which return a list of address corresponding to the ASM
            instruction which are inline.

            .. todo:: check this

            .. todo:: this is currently not supported by hexrays

            :return: A list of address (integer) representing the address of
                the inline assembly instruction in the binary.
        """
        return []#list(self._cinsn.casm)

    @property
    def value(self):
        """
            Return a list of address of the ASM instructions. See
            :meth:`~HxCStmtAsm.addr_instr` .

            .. todo:: bug with hexrays see addr_instr
        """
        return None#self.addr_instr

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
        return GetHxCItem(self._cinsn.creturn.expr)

    @property
    def value(self):
        """
            Return the :class:`HxCExpr` which is return by this statement. See
            :meth:`~HxCStmtReturn.ret_val` .
        """
        return self.ret_val

    @property
    def expr_childs(self):
        return [self.ret_val]



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
        return GetHxCItem(self._cinsn.cif.expr)

    @property
    def st_then(self):
        """
            Property which return the statement executed if the condition
            (:meth:`~HxCStmtIf.cond`) is true.

            :return: An object which inherits from :class:`HxCStmt` .
        """
        return GetHxCItem(self._cinsn.cif.ithen)

    @property
    def has_else(self):
        """
            Property which indicate if this if statement as an else condtion.

            .. todo:: test this

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
            return GetHxCItem(self._cinsn.cif.ielse)
        else:
            return None

    @property
    def st_childs(self):
        if self.has_else:
            return [self.st_then, self.st_else]
        else:
            return [self.st_then]

    @property
    def expr_childs(self):
        return [self.cond]

class HxCStmtFor(HxCStmt):
    """
        Class for representing a C *for* statement (``HxCType.CIT_FOR``).
        This is a recursive statement which have 2 childs statement and
        2 childs expression.

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
        return GetHxCItem(self._cinsn.cfor.expr)

    @property
    def st_body(self):
        """
            Property which return the statement used as a body for the *for*.

            :return: An object which inherits from :class:`HxCStmt` .
        """
        return GetHxCItem(self._cinsn.cfor.body)

    @property
    def init(self):
        """
            Property which return the expression for the initialization of
            the *for* loop.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cinsn.cfor.init)

    @property
    def step(self):
        """
            Property which return the expression for the step of the *for*
            loop.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cinsn.cfor.step)

    @property
    def st_childs(self):
        return [self.st_body]

    @property
    def expr_childs(self):
        return [self.init, self.cond, self.step]

class HxCStmtWhile(HxCStmt):
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
        return GetHxCItem(self._cinsn.cwhile.expr)

    @property
    def st_body(self):
        """
            Property which return the statement used as a body for the
            *while*.

            :return: An object which inherits from :class:`HxCStmt` .
        """
        return GetHxCItem(self._cinsn.cwhile.body)

    @property
    def st_childs(self):
        return [self.st_body]

    @property
    def expr_childs(self):
        return [self.cond]

class HxCStmtDoWhile(HxCStmt):
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
        return GetHxCItem(self._cinsn.cdo.expr)

    @property
    def st_body(self):
        """
            Property which return the statement used as a body for the
            *do-while*.

            :return: An object which inherits from :class:`HxCStmt` .
        """
        return GetHxCItem(self._cinsn.cdo.body)

    @property
    def st_childs(self):
        return [self.st_body]

    @property
    def expr_childs(self):
        return [self.cond]

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

        .. todo:: test this
    """
    TYPE_HANDLE = HxCType.CIT_SWITCH

    @property
    def expr(self):
        """
            Property which return the expression used as the *switch*
            expression.

            :return: An object which inherits from :class:`HxCExpr` .
        """
        return GetHxCItem(self._cinsn.cswitch.expr)

    @property
    def max_val(self):
        """
            Property which return the case maximum value for the switch.

            .. todo:: test this

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
        return [GetHxCItem(i) for i in self._cinsn.cswitch.cases]

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
    def st_childs(self):
        return self.st_cases

    @property
    def expr_childs(self):
        return [self.expr]

class HxCStmtContinue(HxCStmt):
    """
        Class for representing a C *continue* statement
        (``HxCType.CIT_CONTINUE``). This is not recursive nor as a value.
    """
    TYPE_HANDLE = HxCType.CIT_CONTINUE

class HxCStmtBreak(HxCStmt):
    """
        Class for representing a C *break* statement
        (``HxCType.CIT_BREAK``). This is not recursive nor as a value.
    """
    TYPE_HANDLE = HxCType.CIT_BREAK


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
        return [GetHxCItem(e) for e in self._cinsn.cblock]

    @property
    def st_childs(self):
        return self.elts













