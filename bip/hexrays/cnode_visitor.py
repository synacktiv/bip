from cnode import CNodeExpr, CNodeStmt

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
        the nodes in the same order as :meth:`~CNodeStmt.st_childs`
        (statements).

        .. note:: This function will not visit a statement which is under a
            :class:`CNodeExprInsn` . Those should not be present in the last
            stage of a ctree and so this should not be a problem.

        An exception raised by the callback will interupt the visitor.

        :param cnode: An object which inherit from :class:`CNode`. This object
            and all its child will be visited.
        :param callback: A callable taking one argument which will be called
            on all the :class:`CNode` visited with the :class:`CNode` as
            argument.
    """
    # implem using a stack for avoiding recursivity problems
    # this is a tree so no need to check if we have already treated a node.
    stack = [cnode]
    while len(stack) != 0:
        elt = stack.pop() # get the next element
        callback(elt) # call the callback before visiting the next
        if isinstance(elt, CNodeExpr):
            # if we have an expr just append all the child, we append them
            #   in reverse order.
            ch = list(elt.ops)
            ch.reverse()
            stack += ch
        elif isinstance(elt, CNodeStmt):
            ch = list(elt.expr_childs)
            ch += list(elt.st_childs)
            ch.reverse()
            stack += ch
        else:
            # this should never happen
            raise RuntimeError("Unknown type for visiting: {}".format(elt))


