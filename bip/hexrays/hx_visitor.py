"""
    Implement visitor in top of the hexrays ctree visitor API. Those classes
    are define only for internal used and should probably be not used
    directly. Those are accessible through the methods
    of :class:`~bip.hexrays.HxCFunc` starting with ``hx_visit_``. Another
    implementation of visitors exist in Bip which does not rely on the
    ``ctree_visitor_t`` from IDA and which allow to visit
    on :class:`~bip.hexrays.CNode`, this is usually the prefered way to
    visit nodes using Bip. See :ref:`doc-hexrays-astnodes-visitors` for more
    information.
"""
from idaapi import ctree_visitor_t, CV_FAST
from .hx_citem import HxCItem

class _hx_visitor_expr(ctree_visitor_t):
    """
        Inherit from the ``ctree_visitor_t`` class and allow to visit all
        expressions (:class:`HxCExpr`).
    """

    def __init__(self, expr_handler):
        """
            Creator for the visitor.

            :param expr_handler: A function which take as argument an
                :class:`HxCExpr` object. This function will be called on all
                :class:`HxCExpr` part of the function on which it is applied.
        """
        ctree_visitor_t.__init__(self, CV_FAST)
        self.expr_handler = expr_handler

    def visit_expr(self, i):
        """
            Handler of the visitor expression. Create the object
            :class:`HxCExpr` call the handler.
        """
        self.expr_handler(HxCItem.GetHxCItem(i))
        return 0

class _hx_visitor_list_expr(ctree_visitor_t):
    """
        Inherit from the ``ctree_visitor_t`` class and allow to visit
        expressions which are in a list.
    """

    def __init__(self, expr_list, expr_handler):
        """
            Creator for the visitor.

            :param expr_list: A list of class which inherit from
                :class:`HxCExpr`, only expression in the list will be visited.
            :param expr_handler: A function which take as argument an
                :class:`HxCExpr` object. This function will be called on all
                element which are in the ``expr_list`` .
        """
        ctree_visitor_t.__init__(self, CV_FAST)
        self.expr_list = expr_list
        self.expr_handler = expr_handler

    def visit_expr(self, i):
        """
            Handler of the visitor expression. Create the object
            :class:`HxCExpr` and if it match the expression in the
            ``expr_list`` call the handler.
        """
        e = HxCItem.GetHxCItem(i)
        if isinstance(e, tuple(self.expr_list)):
            self.expr_handler(e)
        return 0

class _hx_visitor_stmt(ctree_visitor_t):
    """
        Inherit from the ``ctree_visitor_t`` class and allow to visit all
        statements (:class:`HxCExpr`).
    """

    def __init__(self, stmt_handler):
        """
            Creator for the visitor.

            :param stmt_handler: A function which take as argument an
                :class:`HxCStmt` object. This function will be called on all
                :class:`HxCStmt` part of the function on which it is applied.
        """
        ctree_visitor_t.__init__(self, CV_FAST)
        self.stmt_handler = stmt_handler

    def visit_insn(self, i):
        """
            Handler of the visitor statement. Create the object
            :class:`HxCStmt` call the handler.
        """
        self.stmt_handler(HxCItem.GetHxCItem(i))
        return 0

class _hx_visitor_list_stmt(ctree_visitor_t):
    """
        Inherit from the ``ctree_visitor_t`` class and allow to visit all
        statements (:class:`HxCExpr`).
    """

    def __init__(self, stmt_list, stmt_handler):
        """
            Creator for the visitor.

            :param stmt_list: A list of class which inherit from
                :class:`HxCStmt`, only statement in the list will be visited.
            :param stmt_handler: A function which take as argument an
                :class:`HxCStmt` object. This function will be called only on 
                :class:`HxCStmt` which are in the ``stmt_list``.
        """
        ctree_visitor_t.__init__(self, CV_FAST)
        self.stmt_handler = stmt_handler
        self.stmt_list = stmt_list

    def visit_insn(self, i):
        """
            Handler of the visitor statement. Create the object
            :class:`HxCStmt` and if in the list call the handler.
        """
        e = HxCItem.GetHxCItem(i)
        if isinstance(e, tuple(self.stmt_list)):
            self.stmt_handler(e)
        return 0

class _hx_visitor_all(ctree_visitor_t):
    """
        Inherit from the ``ctree_visitor_t`` class and allow to visit all
        statements (:class:`HxCStmt`) and expression (:class:`HxCExpr`).
    """

    def __init__(self, handler):
        """
            Creator for the visitor.

            :param handler: A function which take as argument an
                :class:`HxCItem` object. This function will be called on all
                :class:`HxCItem` part of the function on which it is applied.
        """
        ctree_visitor_t.__init__(self, CV_FAST)
        self.handler = handler

    def visit_insn(self, i):
        """
            Handler of the visitor statement. Create the 
            :class:`HxCItem` object and call the handler with it in arguments.
        """
        self.handler(HxCItem.GetHxCItem(i))
        return 0

    def visit_expr(self, i):
        """
            Handler of the visitor expression. Create the 
            :class:`HxCItem` object and call the handler with it in arguments.
        """
        self.handler(HxCItem.GetHxCItem(i))
        return 0


class _hx_visitor_list_all(ctree_visitor_t):
    """
        Inherit from the ``ctree_visitor_t`` class and allow to visit all
        statements (:class:`HxCExpr`).
    """

    def __init__(self, item_list, handler):
        """
            Creator for the visitor.

            :param item_list: A list of class which inherit from
                :class:`HxCItem`, only item in the list will be visited.
            :param handler: A function which take as argument an
                :class:`HxCItem` object. This function will be called on
                :class:`HxCItem` which are in the ``item_list``.
        """
        ctree_visitor_t.__init__(self, CV_FAST)
        self.handler = handler
        self.item_list = item_list

    def visit_insn(self, i):
        """
            Handler of the visitor statement. Create the 
            :class:`HxCItem` object and call the handler with it in arguments.
        """
        e = HxCItem.GetHxCItem(i)
        if isinstance(e, tuple(self.item_list)):
            self.handler(e)
        return 0

    def visit_expr(self, i):
        """
            Handler of the visitor expression. Create the 
            :class:`HxCItem` object and call the handler with it in arguments.
        """
        e = HxCItem.GetHxCItem(i)
        if isinstance(e, tuple(self.item_list)):
            self.handler(e)
        return 0

