from bip.base.biptype import BipType
from astnode import AbstractCItem, HxCType

class HxCItem(AbstractCItem):
    """
        Abstract class representing both C expression and C statement as
        defined by HexRays. This is the most direct API on top of Hexrays.
        However, in most cases, the :class:`CNode` equivalent classes can be
        used: those provide more functionnality and are the recommanded ones.

        An object of this class should never be created directly. The
        :func:`HxCItem.GetHxCItem` static method should be used for creating
        an item of the correct type.

        Most of the functionnality provided by this class are inherited from
        its parent class :class:`AbstractCItem` and are common with the
        :class:`CNode` class.
    """
    #: Class attribute indicating which type of item this class handles, this is used
    #:  by :func:`GetHxCItem` for determining if this is the good object to
    #:  instantiate. All abstract class should have a value of -1 for this
    #:  object, non-abstract class should have a value corresponding to the
    #:  :class:`HxCType` they handle.
    TYPE_HANDLE = -1

    ############################ ITEM CREATION ##############################

    def _createChild(self, citem):
        """
            Internal method which allow to create a :class:`HxCItem` object
            from a ``citem_t``. This must be used by :class:`HxCStmt` and
            :class:`HxCExpr` for creating their child expression and
            statement. This method is used for having compatibility with
            the :class:`CNode` class.

            Internally this function is only a wrapper on :meth:`GetHxCItem`.

            :param citem: A ``citem_t`` from ida.
            :return: The equivalent object to the ``citem_t`` for bip. This
                will be an object which inherit from :class:`HxCItem` .
        """
        return HxCItem.GetHxCItem(citem)

    @staticmethod
    def GetHxCItem(citem):
        """
            Function which convert a ``citem_t`` object from ida to one of the
            child object of :class:`HxCItem` . This should in particular be
            used for converting ``cexpr_t`` and ``cinsn_t`` in their correct
            object for bip. This function is used as interface with the IDA
            object.

            If no :class:`HxCItem` child object exist a ``ValueError`` exception
            will be raised.

            .. note:: :class:`HxCExpr` and :class:`HxCStmt` should not used
                this function for creating child item but
                :meth:`HxCItem._createChild` for compatibility with the
                :class:`CNode` class.

            :param citem: A ``citem_t`` from ida.
            :return: The equivalent object to the ``citem_t`` for bip. This
                will be an object which inherit from :class:`HxCItem` .
        """
        done = set()
        todo = set(HxCItem.__subclasses__())
        while len(todo) != 0:
            cl = todo.pop()
            if cl in done:
                continue
            if cl.is_handling_type(citem.op):
                return cl(citem)
            else:
                done.add(cl)
                todo |= set(cl.__subclasses__())
        raise ValueError("GetHxCItem could not find an object matching the citem_t type provided ({})".format(citem.op))

class HxCExpr(HxCItem):
    """
        Abstract class for representing a C Expression as returned by
        HexRays. This is an abstract class which is used as a wrapper on top
        of the ``cexpr_t`` object.

        The equivalent class which inherit from :class:`CNode` is
        :class:`CNodeExpr`, the :class:`CNode` implementation is advised.

        No object of this class should be instanstiated, for getting an
        expression the function :func:`~hx_citem.HxCItem.GetHxCItem` should be
        used.
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

    @property
    def type(self):
        """
            Property which return the type (:class:`BipType`) of this
            expression.

            :return: An object which inherit from :class:`BipType` which
                correspond to the type of this object. Change to this type
                object will not change the type of this expression.
        """
        return BipType.GetBipType(self._cexpr.type)

class HxCStmt(HxCItem):
    """
        Abstract class for representing a C Statement as returned by hexrays.
        This is an abstract class which is a wrapper on top of the
        ``cinsn_t`` ida object.

        The equivalent class which inherit from :class:`CNode` is
        :class:`CNodeStmt`, the :class:`CNode` implementation is advised.

        No object of this class should be instanstiated, for getting an
        expression the function :func:`~hx_citem.HxCItem.GetHxCItem` should be
        used.

        A statement can contain one or more child statement and one or more
        child expression (:class:`HxCExpr`) object.
        By convention properties which will return child statement of an
        object will start with the prefix ``st_`` .
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

