from hx_lvar import HxLvar
from hx_visitor import _hx_visitor_expr, _hx_visitor_list_expr, _hx_visitor_stmt, _hx_visitor_list_stmt, _hx_visitor_all, _hx_visitor_list_all
import ida_hexrays


class HxCFunc(object):
    """
        Python object for representing a C function as decompile by hexrays.

        This is an abstraction on top of the ``ida_hexrays.cfuncptr_t``  and
        ``cfunc_t`` object.

        .. todo:: support everything

            * Comments (cfuncp.user_cmts)

        .. todo:: raccord to normal func (inheritance ?)
        .. todo:: type
        .. todo:: everything in ``cfunc_t`` .

        .. todo:: make smart? error for when ida_hexrays api does not exist

        .. todo:: pretty printer

        .. todo:: test

    """

    def __init__(self, cfunc):
        """
            Constructor for a :class:`HxCFunc` object.

            .. todo:: test

            :param cfunc: A ``cfunc_t`` pointer from IDA object such as return
                by ``ida_hexrays.decompile`` .
        """
        self._cfunc = cfunc

    @property
    def ea(self):
        """
            Property which return the start address of this function.

            .. todo:: test

            :return int: The start address of this function
        """
        return self._cfunc.entry_ea


    @property
    def cstr(self):
        """
            Property which return the C code corresponding to the
            decompilation of this function.

            :return str: The string corresponding to the decompilation of this
                function.
        """
        return str(self._cfunc)

    ################################ LVARS ###################################
    # todo args

    @property
    def lvars(self):
        """
            Return a list of :class:`HxLvar` object representing the local
            variables of this function. This function will return the argument
            as well as the local variable of the function.

            .. todo:: test

            :return: A list of :class:`HxLvar`.
        """
        return [HxLvar(l) for l in self._cfunc.get_lvars()]

    @property
    def lvars_iter(self):
        """
            Return an iterator of :class:`HxLvar` object representing the
            local variables of this function. This is similar to
            :meth:`~HxCFunc.lvars` but with an iterator instead of a list.

            .. todo:: test

            :return: A interator of :class:`HxLvar`.
        """
        for l in self._cfunc.get_lvars():
            yield HxLvar(l)

    @property
    def args(self):
        """
            Return a list of :class:`HxLvar` object representing the argument
            of this functions.

            .. todo:: test

            :return: A list of :class:`HxLvar`.
        """
        return [HxLvar(l) for l in self._cfunc.get_lvars() if l.is_arg_var]

    # TODO: make a function for recuperating a lvar from a register or a stack
    #   location

    ############################ HX VISITOR METHODS ##########################

# todo: 
# * TEST
# * indicated as deprecated or that it should use bip visitors
# * make examples ?

    def hx_visit_generic(self, visitor_class, *args):
        """
            Generic method for creating and calling the hexrays visitors on
            this function. This function is used by the other ``hx_visit_*``
            functions for using the hexrays visitor. The goal of this
            funcction  is also to allow to integrated existing IDA visitor.

            :param visitor_class: A class which inherit from the IDA
                ``ctree_visitor_t`` class.
            :param args: Argument which will be passed to the constructor of
                the ``visitor_class`` .
        """
        v = visitor_class(*args)
        v.apply_to(self._cfunc.body, None)

    def hx_visit_expr(self, func_visit):
        """
            Allow to use the hexrays visitor for visiting all expressions
            (:class:`HxCExpr`) of this function.

            Internally this function use the :class:`_hx_visitor_expr`
            visitor.

            :param func_visit: A function which take as argument an
                :class:`HxCExpr` object. This function will be called on all
                :class:`HxCExpr` element which are part of this function.
        """
        self.hx_visit_generic(_hx_visitor_expr, func_visit)

    def hx_visit_list_expr(self, expr_list, func_visit):
        """
            Allow to use the hexrays visitor for visiting only expressions
            (:class:`HxCExpr`) which are part of a list.

            .. code-block:: python

                # example which print all the HxCExprCall from the function
                # hxf is an object of this class HxCFunc.
                def fu(e):
                    print(e)

                hxf.visit_list_expr([HxCExprCall], fu)

            Internally this function use the :class:`_hx_visitor_list_expr`
            visitor.

            :param expr_list: A list of class which inherit from
                :class:`HxCExpr`, only expression in the list will be visited.
            :param func_visit: A function which take as argument an
                :class:`HxCExpr` object. This function will be called on all
                element which are in the ``expr_list`` .
        """
        self.hx_visit_generic(_hx_visitor_list_expr, expr_list, func_visit)

    def hx_visit_stmt(self, func_visit):
        """
            Allow to use the hexrays visitor for visiting all statements
            (:class:`HxCStmt`) of this function.

            Internally this function use the :class:`_hx_visitor_stmt`
            visitor.

            :param func_visit: A function which take as argument an
                :class:`HxCStmt` object. This function will be called on all
                :class:`HxCStmt` element which are part of this function.
        """
        self.hx_visit_generic(_hx_visitor_stmt, func_visit)

    def hx_visit_list_stmt(self, stmt_list, func_visit):
        """
            Allow to use the hexrays visitor for visiting only statements
            (:class:`HxCStmt`) which are part of a list.

            Internally this function use the :class:`_hx_visitor_list_stmt`
            visitor.

            :param stmt_list: A list of class which inherit from
                :class:`HxCStmt`, only statements in the list will be visited.
            :param func_visit: A function which take as argument an
                :class:`HxCStmt` object. This function will be called on all
                element which are in the ``stmt_list`` .
        """
        self.hx_visit_generic(_hx_visitor_list_stmt, stmt_list, func_visit)

    def hx_visit_all(self, func_visit):
        """
            Allow to use the hexrays visitor for visiting all items
            (statements :class:`HxCStmt` and expression :class:`HxCExpr`) of
            this function.

            Internally this function use the :class:`_hx_visitor_all`
            visitor.

            :param func_visit: A function which take as argument an object
                which inherit from :class:`HxCItem`. This function will be
                called on all those elements which are part of this function.
        """
        self.hx_visit_generic(_hx_visitor_all, func_visit)

    def hx_visit_list_all(self, item_list, func_visit):
        """
            Allow to use the hexrays visitor for visiting only statements
            (:class:`HxCStmt`) which are part of a list.
            Allow to use the hexrays visitor for visiting only items
            (statements :class:`HxCStmt` and expression :class:`HxCExpr`)
            which are part of a list.

            Internally this function use the :class:`_hx_visitor_list_all`
            visitor.

            :param item_list: A list of class which inherit from
                :class:`HxCItem`, only items in the list will be visited.
            :param func_visit: A function which take as argument an
                :class:`HxCItem` object. This function will be called on all
                element which are in the ``item_list`` .
        """
        self.hx_visit_generic(_hx_visitor_list_all, item_list, func_visit)

    ############################### CLASS METHOD ############################

    @classmethod
    def from_addr(cls, ea):
        """
            Class method which return a :class:`HxFunc` object corresponding
            to the function at a particular address.

            .. todo:: error handling

            .. todo:: test

            :param int ea: An address inside the function for which we want
                an :class:`HxFunc`.
            :return: A :class:`HxFunc` object.
        """
        return cls(ida_hexrays.decompile(ea))



############################# 




#struct cfunc_t
#{
#  ea_t entry_ea;             ///< function entry address
#  mbl_array_t *mba;          ///< underlying microcode
#  cinsn_t body;              ///< function body, must be a block
#  intvec_t &argidx;          ///< list of arguments (indexes into vars)
#  ctree_maturity_t maturity; ///< maturity level
#  // The following maps must be accessed using helper functions.
#  // Example: for user_labels_t, see functions starting with "user_labels_".
#  user_labels_t *user_labels;///< user-defined labels.
#  user_cmts_t *user_cmts;    ///< user-defined comments.
#  user_numforms_t *numforms; ///< user-defined number formats.
#  user_iflags_t *user_iflags;///< user-defined item flags \ref CIT_
#  user_unions_t *user_unions;///< user-defined union field selections.
#/// \defgroup CIT_ ctree item iflags bits
#//@{
##define CIT_COLLAPSED 0x0001 ///< display element in collapsed form
#//@}
#  int refcnt;                ///< reference count to this object. use cfuncptr_t
#  int statebits;             ///< current cfunc_t state. see \ref CFS_
#/// \defgroup CFS_ cfunc state bits
##define CFS_BOUNDS       0x0001 ///< 'eamap' and 'boundaries' are ready
##define CFS_TEXT         0x0002 ///< 'sv' is ready (and hdrlines)
##define CFS_LVARS_HIDDEN 0x0004 ///< local variable definitions are collapsed
#  eamap_t *eamap;            ///< ea->insn map. use \ref get_eamap
#  boundaries_t *boundaries;  ///< map of instruction boundaries. use \ref get_boundaries
#  strvec_t sv;               ///< decompilation output: function text. use \ref get_pseudocode
#  int hdrlines;              ///< number of lines in the declaration area
#  mutable ctree_items_t treeitems; ///< vector of ctree items
#
#public:
#  cfunc_t(mbl_array_t *mba);
#  ~cfunc_t(void) { cleanup(); }
#  void release(void) { delete this; }
#  DEFINE_MEMORY_ALLOCATION_FUNCS()
#
#  /// Generate the function body.
#  /// This function (re)generates the function body from the underlying microcode.
#  void hexapi build_c_tree(void);
#
#  /// Verify the ctree.
#  /// This function verifies the ctree. If the ctree is malformed, an internal error
#  /// is generated. Use it to verify the ctree after your modifications.
#  /// \param aul Are unused labels acceptable?
#  /// \param even_without_debugger if false and there is no debugger, the verification will be skipped
#  void hexapi verify(allow_unused_labels_t aul, bool even_without_debugger) const;
#
#  /// Print function prototype.
#  /// \param vout output buffer
#  void hexapi print_dcl(qstring *vout) const;
#
#  /// Print function text.
#  /// \param vp printer helper class to receive the generated text.
#  void hexapi print_func(vc_printer_t &vp) const;
#
#  /// Get the function type.
#  /// \param type variable where the function type is returned
#  /// \return false if failure
#  bool hexapi get_func_type(tinfo_t *type) const;
#
#  /// Get vector of local variables.
#  /// \return pointer to the vector of local variables. If you modify this vector,
#  ///         the ctree must be regenerated in order to have correct cast operators.
#  ///         Use build_c_tree() for that.
#  ///         Removing lvars should be done carefully: all references in ctree
#  ///         and microcode must be corrected after that.
#  lvars_t *hexapi get_lvars(void);
#
#  /// Get stack offset delta.
#  /// The local variable stack offsets retrieved by v.location.stkoff()
#  /// should be adjusted before being used as stack frame offsets in IDA.
#  /// \return the delta to apply.
#  ///         example: ida_stkoff = v.location.stkoff() - f->get_stkoff_delta()
#  sval_t hexapi get_stkoff_delta(void);
#
#  /// Find the label.
#  /// \return pointer to the ctree item with the specified label number.
#  citem_t *hexapi find_label(int label);
#
#  /// Remove unused labels.
#  /// This function check what labels are really used by the function and
#  /// removes the unused ones.
#  void hexapi remove_unused_labels(void);
#
#  /// Retrieve a user defined comment.
#  /// \param loc ctree location
#  /// \param rt should already retrieved comments retrieved again?
#  /// \return pointer to the comment string or NULL
#  const char *hexapi get_user_cmt(const treeloc_t &loc, cmt_retrieval_type_t rt) const;
#
#  /// Set a user defined comment.
#  /// This function stores the specified comment in the cfunc_t structure.
#  /// The save_user_cmts() function must be called after it.
#  /// \param loc ctree location
#  /// \param cmt new comment. if empty or NULL, then an existing comment is deleted.
#  void hexapi set_user_cmt(const treeloc_t &loc, const char *cmt);
#
#  /// Retrieve citem iflags.
#  /// \param loc citem locator
#  /// \return \ref CIT_ or 0
#  int32 hexapi get_user_iflags(const citem_locator_t &loc) const;
#
#  /// Set citem iflags.
#  /// \param loc citem locator
#  /// \param iflags new iflags
#  void hexapi set_user_iflags(const citem_locator_t &loc, int32 iflags);
#
#  /// Check if there are orphan comments.
#  bool hexapi has_orphan_cmts(void) const;
#
#  /// Delete all orphan comments.
#  /// The save_user_cmts() function must be called after this call.
#  int hexapi del_orphan_cmts(void);
#
#  /// Retrieve a user defined union field selection.
#  /// \param ea address
#  /// \param path out: path describing the union selection.
#  /// \return pointer to the path or NULL
#  bool hexapi get_user_union_selection(ea_t ea, intvec_t *path);
#
#  /// Set a union field selection.
#  /// The save_user_unions() function must be called after calling this function.
#  /// \param ea address
#  /// \param path in: path describing the union selection.
#  void hexapi set_user_union_selection(ea_t ea, const intvec_t &path);
#
#  /// Save user-defined labels into the database
#  void save_user_labels(void) const { ::save_user_labels(entry_ea, user_labels); }
#  /// Save user-defined comments into the database
#  void save_user_cmts(void) const { ::save_user_cmts(entry_ea, user_cmts); }
#  /// Save user-defined number formats into the database
#  void save_user_numforms(void) const { ::save_user_numforms(entry_ea, numforms); }
#  /// Save user-defined iflags into the database
#  void save_user_iflags(void) const { ::save_user_iflags(entry_ea, user_iflags); }
#  /// Save user-defined union field selections into the database
#  void save_user_unions(void) const { ::save_user_unions(entry_ea, user_unions); }
#
#  /// Get ctree item for the specified cursor position.
#  /// \return false if failed to get the current item
#  /// \param line line of decompilation text (element of \ref sv)
#  /// \param x x cursor coordinate in the line
#  /// \param is_ctree_line does the line belong to statement area? (if not, it is assumed to belong to the declaration area)
#  /// \param phead ptr to the first item on the line (used to attach block comments). May be NULL
#  /// \param pitem ptr to the current item. May be NULL
#  /// \param ptail ptr to the last item on the line (used to attach indented comments). May be NULL
#  /// \sa vdui_t::get_current_item()
#  bool hexapi get_line_item(const char *line, int x, bool is_ctree_line, ctree_item_t *phead, ctree_item_t *pitem, ctree_item_t *ptail);
#
#  /// Get information about decompilation warnings.
#  /// \return reference to the vector of warnings
#  hexwarns_t &hexapi get_warnings(void);
#
#  /// Get pointer to ea->insn map.
#  /// This function initializes eamap if not done yet.
#  eamap_t &hexapi get_eamap(void);
#
#  /// Get pointer to map of instruction boundaries.
#  /// This function initializes the boundary map if not done yet.
#  boundaries_t &hexapi get_boundaries(void);
#
#  /// Get pointer to decompilation output: the pseudocode.
#  /// This function generates pseudocode if not done yet.
#  const strvec_t &hexapi get_pseudocode(void);
#
#  bool hexapi gather_derefs(const ctree_item_t &ci, udt_type_data_t *udm=NULL) const;
#  bool hexapi find_item_coords(const citem_t *item, int *px, int *py);
#private:
#  /// Cleanup.
#  /// Properly delete all children and free memory.
#  void hexapi cleanup(void);
#  DECLARE_UNCOPYABLE(cfunc_t)
#};
#typedef qrefcnt_t<cfunc_t> cfuncptr_t;


