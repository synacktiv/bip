#from cnode import CNodeExpr, CNodeStmt
import bip.hexrays.cnode # as modcnode # problem compat py2/py3, py2 do not like the ``as``

def visit_dfs_cnode(cnode, callback):
    """
        Basic visitor for a CNode: this will allow to call a callback on every
        node under the current one (and including the current node) in the
        AST. This method does not used the visitor from hexrays
        (``ctree_visitor_t``). The callback will receive a :class:`CNode` in
        argument.

        This visitor implements a Deep-First Search (DFS) algorithm which will
        always visit first the :class:`CNodeExpr` and then the
        :class:`CNodeStmt`. The callback is called before visiting deeper.
        For an object which inherit from :class:`CNodeExpr` the child nodes
        will be called in the same order than returned by
        :meth:`~CNodeExpr.ops`; for an object which inherit from
        :class:`CNodeStmt` the child nodes will be called in the same order
        than returned by :meth:`~CNodeStmt.expr_childs` (expression) follow by
        the nodes in the same order as :meth:`~CNodeStmt.stmt_childs`
        (statements).

        If the callback return ``False`` the visitor will stop. Every other
        result is ignore.

        .. note:: This function will not visit a statement which is under a
            :class:`CNodeExprInsn` . Those should not be present in the last
            stage of a ctree and so this should not be a problem.

        An exception raised by the callback will interupt the visitor.

        :param cnode: An object which inherit from :class:`CNode`. This object
            and all its child will be visited.
        :param callback: A callable taking one argument which will be called
            on all the :class:`CNode` visited with the :class:`CNode` as
            argument. If it returns False the visitor stops.
    """
    # implem using a stack for avoiding recursivity problems
    # this is a tree so no need to check if we have already treated a node.
    stack = [cnode]
    while len(stack) != 0:
        elt = stack.pop() # get the next element
        if callback(elt) == False: # call the callback before visiting the next
            return # if ret False: stop
        if isinstance(elt, bip.hexrays.cnode.CNodeExpr):
            # if we have an expr just append all the child, we append them
            #   in reverse order.
            ch = list(elt.ops)
            ch.reverse()
            stack += ch
        elif isinstance(elt, bip.hexrays.cnode.CNodeStmt):
            ch = list(elt.expr_childs)
            ch += list(elt.stmt_childs)
            ch.reverse()
            stack += ch
        else:
            # this should never happen
            raise RuntimeError("Unknown type for visiting: {}".format(elt))

def visit_dfs_cnode_filterlist(cnode, callback, filter_list):
    """
        Visitor for :class:`CNode` with filtering. This function is the same
        than :func:`visit_dfs_cnode` but allow to use the callback only on
        :class:`CNode` which are in a list (white listing of the node to
        visit).

        For information about the visitor implementation see
        :func:`visit_dfs_cnode` . If the `filter_list` parameter contain only
        statement (:class:`CNodeStmt`) the expression will not be visited at
        all, this should allow a little performance gain.

        If the callback return ``False`` the visitor will stop. Every other
        result is ignore.

        :param cnode: An object which inherit from :class:`CNode`. This object
            and all its child will be visited.
        :param callback: A callable taking one argument which will be called
            on all the :class:`CNode` visited with the :class:`CNode` as
            argument.
        :param filter_list: A list or tuple of class or a class which inherit
            from :class:`CNode`. The callback will be called only for the node
            from a class in this list. If it returns False the visitor stops.
    """
    if isinstance(filter_list, (list, tuple)) and len(filter_list) == 0:
        # we don't visit anything
        return
    # check if we need to visit the child of the expression
    vist_expr = False
    if isinstance(filter_list, (list, tuple)):
        for i in filter_list:
            if issubclass(i, bip.hexrays.cnode.CNodeExpr):
                vist_expr = True
                break
    elif issubclass(filter_list, bip.hexrays.cnode.CNodeExpr):
        vist_expr = True
    stack = [cnode]
    while len(stack) != 0:
        elt = stack.pop() # get the next element
        # check if we want the call
        if ((isinstance(filter_list, list) and elt.__class__ in filter_list) or
            (not isinstance(filter_list, list)
                and isinstance(elt, filter_list))):
            # check if we want the call
            if callback(elt) == False: # call the callback before visiting the next
                return
        if isinstance(elt, bip.hexrays.cnode.CNodeExpr):
            if vist_expr:
                ch = list(elt.ops)
                ch.reverse()
                stack += ch
        elif isinstance(elt, bip.hexrays.cnode.CNodeStmt):
            if vist_expr:
                ch = list(elt.expr_childs)
            else:
                ch = []
            ch += list(elt.stmt_childs)
            ch.reverse()
            stack += ch
        else:
            # this should never happen
            raise RuntimeError("Unknown type for visiting: {}".format(elt))


