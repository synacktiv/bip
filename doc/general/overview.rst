.. _general-overview:

Overview
########

This overview has for goal to show how the most usual operations can be done,
it is far from being complete. All functions and objects in Bip are documented
using doc string so just use ``help(BIPCLASS)`` and ``help(OBJ.BIPMETHOD)`` for
getting the doc in your shell.

Base
====

.. module:: bip.base

The module ``bip.base`` contains most of the *basic* features for interfacing
with IDA. In practice this is mainly the disasmbleur part of IDA, this
includes: manipulation of instruction, functions, basic blocks, operands,
data, xrefs, structures, types, ...

Instructions / Operands
-----------------------

The classes :class:`~bip.base.Instr` and :class:`~bip.base.Operand`:

.. code-block:: python

    from bip.base import *
    i = Instr() # Instr is the base class for representing an instruction
    i # by default the address on the screen is taken
    # Instr: 0x1800D324B (mov     rcx, r13)
    i2 = Instr(0x01800D3242) # pass the address in argument
    i2
    # Instr: 0x1800D3242 (mov     r8d, 8)
    i2.next # access next instruction, preivous with i2.prev
    # Instr: 0x1800D3248 (mov     rdx, r14)
    l = [i3 for i3 in Instr.iter_all()] # l contain the list of all Instruction of the database, iter_all produce a generator object
    i.ea # access the address
    # 6443315787
    i.mnem # mnemonic representation
    # mov
    i.ops # access to the operands
    # [<bip.base.operand.Operand object at 0x0000022B0291DA90>, <bip.base.operand.Operand object at 0x0000022B0291DA58>]
    i.ops[0].str # string representation of an operand
    # rcx
    i.bytes # bytes in the instruction
    # [73L, 139L, 205L]
    i.size # number of bytes of this instruction
    # 3
    i.comment = "hello" # set a comment, rcomment for the repeatable comments
    i
    # Instr: 0x1800D324B (mov     rcx, r13; hello)
    i.comment # get a comment
    # hello
    i.func # access to the function
    # Func: RtlQueryProcessLockInformation (0x1800D2FF0)
    i.block # access to basic block
    # BipBlock: 0x1800D3242 (from Func: RtlQueryProcessLockInformation (0x1800D2FF0))

Function / Basic block
----------------------

The classes :class:`~bip.base.BipFunction` and :class:`~bip.base.BipBlock`:

.. code-block:: python

    from bip.base import *
    f = BipFunction() # Get the function, screen address used if not provided
    f
    # Func: RtlQueryProcessLockInformation (0x1800D2FF0)
    f2 = BipFunction(0x0018010E975) # provide an address, not necessary the first one
    f2
    # Func: sub_18010E968 (0x18010E968)
    f == f2 # compare two functions
    # False
    f == BipFunction(0x001800D3021)
    # True
    hex(f.ea) # start address
    # 0x1800d2ff0L
    hex(f.end) # end address
    # 0x1800d3284L
    f.name # get and set the name
    # RtlQueryProcessLockInformation
    f.name = "test"
    f.name
    # test
    f.size # number of bytes in the function
    # 660
    f.bytes # bytes of the function
    # [72L, ..., 255L]
    f.callees # list of function called by this function
    # [<bip.base.func.BipFunction object at 0x0000022B0291DD30>, ..., <bip.base.func.BipFunction object at 0x0000022B045487F0>]
    f.callers # list of function which call this function
    # [<bip.base.func.BipFunction object at 0x0000022B04544048>]
    f.instr # list of instructions in the function
    # [<bip.base.instr.Instr object at 0x0000022B0291DB00>, ..., <bip.base.instr.Instr object at 0x0000022B0454D080>]
    f.comment = "welcome to bip" # comment of the function, rcomment for repeatables one 
    f.comment
    # welcome to bip
    f.does_return # does this function return ?
    # True
    BipFunction.iter_all() # allow to iter on all functions define in the database
    # <generator object iter_all at 0x0000022B029231F8>
    f.nb_blocks # number of basic block
    # 33
    f.blocks # list of blocks
    # [<bip.base.block.BipBlock object at 0x0000022B04544D68>, ..., <bip.base.block.BipBlock object at 0x0000022B04552240>]
    f.blocks[5] # access the basic block 5, could be done with BipBlock(addr)
    # BipBlock: 0x1800D306E (from Func: test (0x1800D2FF0))
    f.blocks[5].func # link back to the function
    # Func: test (0x1800D2FF0)
    f.blocks[5].instr # list of instruction in the block
    # [<bip.base.instr.Instr object at 0x0000022B04544710>, ..., <bip.base.instr.Instr object at 0x0000022B0291DB00>]
    f.blocks[5].pred # predecessor blocks, blocks where control flow lead to this one
    # [<bip.base.block.BipBlock object at 0x0000022B04544D68>]
    f.blocks[5].succ # successor blocks
    # [<bip.base.block.BipBlock object at 0x0000022B04544710>, <bip.base.block.BipBlock object at 0x0000022B04544438>]
    f.blocks[5].is_ret # is this block containing a return
    # False

Data
----

The class :class:`~bip.base.BipData`:

.. code-block:: python

    from bip.base import *
    d = BipData(0x000180110068) # .rdata:0000000180110068 bip_ex          dq offset unk_180110DE0
    # BipData at 0x180110068 = 0x180110DE0
    d.name # Name of the symbol if any
    # bip_ex
    d.is_word # is it a word
    # False
    d.is_qword # is it a qword
    # True
    hex(d.value) # value at that address, this take into account the basic type (byte, word, dword, qword) defined in IDA
    # 0x180110de0L
    hex(d.ea) # address
    # 0x180110068L
    d.comment = "exemple" # comment as before
    d.comment
    # exemple
    d.value = 0xAABBCCDD # change the value 
    hex(d.value)
    # 0xaabbccddL
    d.bytes # get the bytes, as before
    # [221L, 204L, 187L, 170L, 0L, 0L, 0L, 0L]
    hex(d.original_value) # get the original value before modification
    # 0x180110de0L
    d.bytes = [0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0] # patch the bytes
    hex(d.value) # get the value
    # 0x44332211L
    BipData.iter_heads() # iter on "heads" of the IDB, heads are defined data in the IDB
    # <generator object iter_heads at 0x0000022B02923240>
    hex(BipData.get_dword(0x0180110078)) # staticmethod for reading value at an address
    # 0x60004L
    BipData.set_byte(0x0180110078, 0xAA) # static method for modifying a value at an address
    hex(BipData.get_qword(0x0180110078))
    # 0x600aaL

Element
-------

In Bip most basic object inherit from the same classes: :class:`BipBaseElt` which is
the most basic one, :class:`BipRefElt` which include all the objects which can have
xrefs (including structures (:class:`BipStruct`) and structure members
(:class:`BStructMember`), see bellow), :class:`BipElt`
which represent all elements which have an address in the IDA DataBase (idb),
including :class:`BipData` and :class:`Instr` (it is this class which
implement the properties `comment`,  `name`, `bytes`, ...).

It is possible to use the functions :func:`GetElt` and :func:`GetEltByName`
for directly recuperating the good basic element from an address or a name
representing a location in the binary.

.. code-block:: python

    from bip.base import *
    GetElt() # get the element at current address, in that case return a BipData object
    # BipData at 0x180110068 = 0x44332211
    Here() # Get the current address
    # 0x180110068
    GetElt(0x00180110078) # get the element at the address 0x00180110078
    # BipData at 0x180110078 = 0xAA
    GetElt(0x1800D2FF0) # in that case it return an Instr object because this is code
    # Instr: 0x1800D2FF0 (mov     rax, rsp)
    GetEltByName("bip_ex") # Get using a name and not an address
    # BipData at 0x180110068 = 0x44332211
    isinstance(GetElt(0x1800D2FF0), Instr) # test if that element is an instruction ?
    # True
    isinstance(GetElt(0x1800D2FF0), BipData) # or data ?
    # False

Some static function are provided for searching element in the database:

.. code-block:: python

    from bip.base import *
    GetElt()
    # Instr: 0x1800D3248 (mov     rdx, r14)
    BipElt.next_code() # find next code element
    # Instr: 0x1800D324B (mov     rcx, r13)
    BipElt.next_code(down=False) # find prev code element
    # Instr: 0x1800D3242 (mov     r8d, 8)
    BipElt.next_data() # find next data element
    # BipData at 0x1800D3284 = 0xCC
    BipElt.next_data(down=False) # find previous data element
    # BipData at 0x1800D2FE1 = 0xCC
    hex(BipElt.next_data_addr(down=False)) # find address of the previous data element
    # 0x1800d2fe1L
    BipElt.next_unknown() # same for unknown, which are not typed element of IDA and are considered data by Bip
    # BipData at 0x180110000 = 0xE
    BipElt.next_defined() # opposite of unknown: data or code
    # Instr: 0x1800D324B (mov     rcx, r13)
    BipElt.search_bytes("49 ? CD", 0x1800D3248) # search for byte sequence (ignore the current position by default)
    # Instr: 0x1800D324B (mov     rcx, r13)

Xref
----

All elements which inherit from :class:`BipRefElt` (:class:`Instr`,
:class:`BipData`, :class:`BipStruct`, ...) and some other (in
particular :class:`BipFunction`) possess methods which allow
to access xrefs. They are represented by the :class:`BipXref` object which
have a `src` (origin of the xref) and a `dst` (destination of the xref).

.. code-block:: python

    from bip.base import *
    i = Instr(0x01800D3063)
    i # exemple with instruction but works the same with BipData
    # Instr: 0x1800D3063 (cmp     r15, [rsp+98h+var_58])
    i.xTo # List of xref which point on this instruction
    # [<bip.base.xref.BipXref object at 0x0000022B04544438>, <bip.base.xref.BipXref object at 0x0000022B045447F0>]
    i.xTo[0].src # previous instruction
    # Instr: 0x1800D305E (mov     [rsp+98h+var_78], rsi)
    i.xTo[0].is_ordinaryflow # is this an ordinary flow between to instruction (not jmp or call)
    # True
    i.xTo[1].src # jmp to instruction i at 0x1800D3063
    # Instr: 0x1800D3222 (jmp     loc_1800D3063)
    i.xTo[1].is_jmp # is this xref because of a jmp ?
    # True
    i.xEaTo # bypass the xref objects and get the address directly
    # [6443315294L, 6443315746L]
    i.xEltTo # bypass the xref objects and get the elements directly, will list BipData if any
    # [<bip.base.instr.Instr object at 0x0000022B045447F0>, <bip.base.instr.Instr object at 0x0000022B04544978>]
    i.xCodeTo # bypass the xref objects and get the instr directly, if a BipData was pointed at this address it will not be listed
    # [<bip.base.instr.Instr object at 0x0000022B04544438>, <bip.base.instr.Instr object at 0x0000022B0291DD30>]
    i.xFrom # same but for comming from this instruction
    # [<bip.base.xref.BipXref object at 0x0000022B04544D68>]
    i.xFrom[0]
    # <bip.base.xref.BipXref object at 0x0000022B04544438>
    i.xFrom[0].dst # next instruction
    # Instr: 0x1800D3068 (jz      loc_1800D3227)
    i.xFrom[0].src # current instruction
    # Instr: 0x1800D3063 (cmp     r15, [rsp+98h+var_58])
    hex(i.xFrom[0].dst_ea) # address of the next instruction
    # 0x1800D3068L
    i.xFrom[0].is_codepath # this is a normal code path (include jmp and call)
    # True
    i.xFrom[0].is_call # is this because of a call ?
    # False
    f = BipFunction()
    f
    # Func: RtlQueryProcessLockInformation (0x1800D2FF0)
    f.xTo # works also for function, but only with To, not with the From
    # [<bip.base.xref.BipXref object at 0x000001D95529EB00>, <bip.base.xref.BipXref object at 0x000001D95529EB70>, <bip.base.xref.BipXref object at 0x000001D95529EBE0>, <bip.base.xref.BipXref object at 0x000001D95529EC88>]
    f.xEltTo # here we have 3 data reference to this function
    # [<bip.base.instr.Instr object at 0x000001D95529EE48>, <bip.base.data.BipData object at 0x000001D95529EEF0>, <bip.base.data.BipData object at 0x000001D95529EF28>, <bip.base.data.BipData object at 0x000001D95529EF60>]
    f.xCodeTo # but only one instruction
    # [<bip.base.instr.Instr object at 0x000001D95529EC88>]

Struct
------

Manipulating struct (:class:`BipStruct`) and members (:class:`BStructMember`):

.. code-block:: python

    from bip.base import *
    st = BipStruct.get("EXCEPTION_RECORD") # Struct are access by using get and their name
    st # BipStruct object
    # Struct: EXCEPTION_RECORD (size=0x98)
    st.comment = "struct comment"
    st.comment
    # struct comment
    st.name
    # EXCEPTION_RECORD
    st.size
    # 152
    st["ExceptionFlags"] # access to the BStructMember by their name
    # Member: EXCEPTION_RECORD.ExceptionFlags (offset=0x4, size=0x4)
    st[8] # or by their offset, this is *not* the entry number 8!!!
    # Member: EXCEPTION_RECORD.ExceptionRecord (offset=0x8, size=0x8)
    st[2] # offset does not need to be the first one
    # Member: EXCEPTION_RECORD.ExceptionCode (offset=0x0, size=0x4)
    st.members # list of members
    # [<bip.base.struct.BStructMember object at 0x000001D95529EEF0>, ..., <bip.base.struct.BStructMember object at 0x000001D95536DF28>]
    st[0].name
    # ExceptionCode
    st[0].fullname
    # EXCEPTION_RECORD.ExceptionCode
    st[0].size
    # 4
    st[0].struct
    # Struct: EXCEPTION_RECORD (size=0x98)
    st[0].comment = "member comment"
    st[0].comment
    # member comment
    st[8].xEltTo # BStructMember et BipStruct have xrefs
    # [<bip.base.instr.Instr object at 0x000001D95536DD30>, <bip.base.instr.Instr object at 0x000001D95536D9E8>]
    st[8].xEltTo[0]
    # Instr: 0x1800A0720 (mov     [rsp+538h+ExceptionRecord.ExceptionRecord], r10)

Creating struct, adding member and nested structure:

.. code-block:: python

    from bip.base import *
    st = BipStruct.create("NewStruct") # create a new structure
    st
    # Struct: NewStruct (size=0x0)
    st.add("NewField", 4) # add a new member named "NewField" of size 4 
    # Member: NewStruct.NewField (offset=0x0, size=0x4)
    st.add("NewQword", 8)
    # Member: NewStruct.NewQword (offset=0x4, size=0x8)
    st
    # Struct: NewStruct (size=0xC)
    st.add("struct_nested", 1)
    # Member: NewStruct.struct_nested (offset=0xC, size=0x1)
    st["struct_nested"].type = BipType.FromC("EXCEPTION_RECORD") # changing the type of member struct_nested as struct EXCEPTION_RECORD
    st["struct_nested"]
    # Member: NewStruct.struct_nested (offset=0xC, size=0x98)
    st["struct_nested"].is_nested # is this a nested structure ?
    # True
    st["struct_nested"].nested_struct # getting the nested structure
    # Struct: EXCEPTION_RECORD (size=0x98)

Types
-----

IDA use extensively types in hexrays but also in the base API for defining
types of data, variables and so on. In Bip the different types inherit from 
the same class :class:`BipType`. This class propose some basic methods common to all
types and subclasses (class starting by :class:`BType`) can define more specifics
ones.

The types should be seen as a recursive structure: a ``void *`` is a
:class:`BTypePtr` containing a :class:`BTypeVoid` structure. For a list of the
different types implemented in Bip see TODO.

.. code-block:: python

    pv = BipType.FromC("void *") # FromC is the easiest way to create a type
    pv
    # <bip.base.biptype.BTypePtr object at 0x000001D95536DDD8>
    pv.size # ptr on x64 is 8 bytes
    # 8
    pv.str # C string representation
    # void *
    pv.is_named # this type is not named
    # False
    pv.pointed # type bellow the pointer (recursive)
    # <bip.base.biptype.BTypeVoid object at 0x000001D95536DF60>
    pv.childs # list of type pointed
    # [<bip.base.biptype.BTypeVoid object at 0x000001D95536DEB8>]
    d = BipData(0x000180110068)
    d.type # access directly to the type at the address
    # <bip.base.biptype.BTypePtr object at 0x000001D95536D9E8>
    d.type.str
    # void *
    ps = BipType.FromC("EXCEPTION_RECORD *")
    ps.pointed # type for struct EXCEPTION_RECORD
    # <bip.base.biptype.BTypeStruct object at 0x000001D95536DD30>
    ps.pointed.is_named # this one is named
    # True
    ps.pointed.name
    # EXCEPTION_RECORD
    ps.set_at(d.ea) # set the type ps at address d.ea
    d.type.str # the type has indeed change
    # EXCEPTION_RECORD *
    d.type = pv # rolling it back
    d.type.str
    # void *
    BipType.get_at(d.ea) # Possible to directly recuperating the type with get_at(address)
    # <bip.base.biptype.BTypePtr object at 0x000001D95536DEB8>

Hexrays
=======

.. module:: bip.hexrays

The module `bip.hexrays` contains the features link to the decompiler
provided by IDA.

Functions / local variables
---------------------------

Hexrays functions are represented by the :class:`HxCFunc` objects and local
variable by the :class:`HxLvar` objects:

.. code-block:: python

    HxCFunc.from_addr() # HxCFunc represent a decompiled function
    # <bip.hexrays.hx_cfunc.HxCFunc object at 0x00000278AE80C860>
    hf = BipFunction().hxfunc # accessible from a "normal function"
    hex(hf.ea) # address of the functions
    # 0x1800d2ff0L
    hf.args # list of the arguments as HxLvar objects
    # [<bip.hexrays.hx_lvar.HxLvar object at 0x00000278AFDAACF8>]
    hf.lvars # list of all local variable (including args)
    # [<bip.hexrays.hx_lvar.HxLvar object at 0x00000278AFDAAB70>, ..., <bip.hexrays.hx_lvar.HxLvar object at 0x00000278AFDAF4E0>]
    lv = hf.lvars[0] # getting the first one
    lv
    # LVAR(name=a1, size=8, type=<bip.base.biptype.BTypeInt object at 0x00000278AFDAAFD0>)
    lv.name # getting name of lvar
    # a1
    lv.is_arg # is this variable an argument ?
    # True
    lv.name = "thisisthefirstarg" # changing name of the lvar
    lv
    lv.type = BipType.FromC("void *") # changing the type
    lv.comment = "new comment" # adding a comment
    lv.size # getting the size
    # 8

CNode / Visitors
----------------

Hexrays allow to manipulate the AST it produces, this is a particularly
usefull feature as it allow to make static analysis at a way higher level.
Bip define :class:`CNode` which represent a node of the AST, each type of node is
represented by a subclass of :class:`CNode`. All types of node have child nodes except
:class:`CNodeExprFinal` which are the leaf of the AST. Two *main* types of nodes
exist :class:`CNodeExpr` (expressions) and :class:`CNodeStmt` (statements).
Statements correspond to the C Statements: if, while, ... , expressions are everything
else. Statements can have childs statements or expressions while expressions
can only have expressions child.

A list of all the different types of node and more details on what they do and
how to write visitor is present in TODO.

Directly accessing the nodes:

.. code-block:: python

    hf = HxCFunc.from_addr() # get the HxCFunc
    rn = hf.root_node # accessing the root node of the function
    rn # root node is always a CNodeStmtBlock
    # CNodeStmtBlock(ea=0x1800D3006, st_childs=[<bip.hexrays.cnode.CNodeStmtExpr object at 0x00000278AFDAADD8>, ..., <bip.hexrays.cnode.CNodeStmtReturn object at 0x00000278B16355F8>])
    hex(rn.ea) # address of the root node, after the function prolog
    # 0x1800d3006L
    rn.has_parent # root node does not have parent
    # False
    rn.expr_childs # this node does not have expression statements
    # []
    ste = rn.st_childs[0] # getting the first statement childs
    ste # CNodeStmtExpr contain one child expression
    # CNodeStmtExpr(ea=0x1800D3006, value=CNodeExprAsg(ea=0x1800D3006, ops=[<bip.hexrays.cnode.CNodeExprVar object at 0x00000278AFDAADD8>, <bip.hexrays.cnode.CNodeExprVar object at 0x00000278B1637080>]))
    ste.parent # the parent is the root node
    # CNodeStmtBlock(ea=0x1800D3006, st_childs=[<bip.hexrays.cnode.CNodeStmtExpr object at 0x00000278B1637048>, ..., <bip.hexrays.cnode.CNodeStmtReturn object at 0x00000278B16376D8>])
    a = ste.value # getting the expression of the node
    a # Asg is an assignement
    # CNodeExprAsg(ea=0x1800D3006, ops=[<bip.hexrays.cnode.CNodeExprVar object at 0x00000278AFDAADD8>, <bip.hexrays.cnode.CNodeExprVar object at 0x00000278B1637080>])
    a.first_op # first operand of the assignement is a lvar, lvar are leaf
    # CNodeExprVar(ea=0xFFFFFFFFFFFFFFFF, value=1)
    a.first_op.lvar # recuperate the lvar object
    # LVAR(name=v1, size=8, type=<bip.base.biptype.BTypeInt object at 0x00000278B16390B8>)
    a.ops # list all operands of the expression
    # [<bip.hexrays.cnode.CNodeExprVar object at 0x00000278AFDAADD8>, <bip.hexrays.cnode.CNodeExprVar object at 0x00000278B1639080>]
    a.ops[1] # getting the second operand, also a lvar
    # CNodeExprVar(ea=0xFFFFFFFFFFFFFFFF, value=0)
    hex(a.ops[1].closest_ea) # lvar have no position in the ASM, but possible to take the one of the parents
    # 0x1800d3006L

The previous code show how to get value and manipulate quickly nodes. For
making analysis it is easier to use visitor on the complete function.
:meth:`HxCFunc.visit_cnode` allow to visit all the nodes in a function with a callback,
:meth:`HxCFunc.visit_cnode_filterlist` allow to visit only node of a certain type by
passing a list of the node.

This script is an exemple for visiting a function and recuperating the
format string pass to a `printk` function. It locates the call to `printk`,
recuperate the address of the first argument, get the string and add a comment
in the hexrays:

.. code-block:: python

    from bip.base import *
    from bip.hexrays import *
    from bip.hexrays.cnode import *
    
    """
        Search for all call to printk, if possible recuperate the string and add
        it in comments in hexrays view at the call level.
    """
    
    def ignore_cast_ref(cn):
        # ignore cast and ref (``&`` operator in C) node
        #   ignoring cast is a common problem, ignoring ref can be a really bad
        #   idea
        if isinstance(cn, (CNodeExprCast, CNodeExprRef)):
            return ignore_cast_ref(cn.ops[0])
        return cn
    
    def visit_call(cn):
        c = ignore_cast_ref(cn.caller)
        if not isinstance(c, CNodeExprObj):
            # if it is not an object just ignore it, object are for everything
            # which has an address, including functions
            return
        try:
            # check if it calls to printk
            # For more perf. we would want to use xref to printk and checks of
            #   the address of the node
            if BipFunction(c.value).name != "printk":
                return
            if cn.number_args < 1: # if we don't have a first argument ignore
                print("Call to printk without arg at 0x{:X}".format(cn.ea))
                return
            
            # lets get the address of the structure in first arg
            karg = ignore_cast_ref(cn.args[0])
            if not isinstance(karg, (CNodeExprNum, CNodeExprObj)):
                # we check for Num in case hexrays have failed, do not handle
                #   lvar and so on
                print("Call to printk with unhandle argument type ({}) at 0x{:X}".format(karg, cn.ea))
                return 
            ea = karg.value
            s = BipData.get_cstring(ea + 2) # get the string
            if s is None or s == "": # sanity check
                print("Invalid string at 0x{:X}".format(cn.ea))
                return
            s = s.strip() # remove space and \n
            # CNode.cfunc is the HxCFunc object
            cn.cfunc.add_cmt(cn.ea, s) # add a comment on the hexrays function
        except Exception: 
            print("Exception at 0x{:X}".format(cn.ea))
            return
    
    def printk_handler(eafunc):
        hf = HxCFunc.from_addr(eafunc) # get the hexrays function
        hf.visit_cnode_filterlist(visit_call, [CNodeExprCall]) # visit only the call nodes

Plugins
=======


.. module:: bip.gui

Plugins using Bip should all inherit from the class :class:`BipPlugin`. Those plugin
are different from the IDA plugin and are loaded and called by the
:class:`BipPluginManager`. Each plugin is identified by its class name and those
should be unique. For more information about plugins and internals see
TODO.

Here is a simple plugin exemple:

.. code-block:: python
    
    from bip.gui import * # BipPlugin is define in the bip.gui module
    
    class ExPlugin(BipPlugin):
        # inherit from BipPlugin, all plugin should be instantiated only once
        # this should be done by the plugin manager, not "by hand"
    
        @classmethod
        def to_load(cls): # allow to test if the plugin apply, this MUST be a classmethod
            return True # always loading
    
        @shortcut("Ctrl-H") # add a shortcut as a decorator, will call the method bellow
        @shortcut("Ctrl-5") # add an other one
        @menu("Edit/Plugins/", "ExPlugin Action!") # add a menu entry named "ExPlugin Action!", default is the method name
        def action_with_shortcut(self):
            print(self) # this is the ExPlugin object
            print("In ExPlugin action !")# code here

A plugin can expose methods which another plugin wants to call or directly
from the console. A plugin should not be directly instantiated, it is the
:class:`BipPluginManager` which is in charge of loading it. For recuperating a
:class:`BipPlugin` object it should be requested to the plugin manager:

.. code-block:: python

    from bip.gui import *
    bpm = get_plugin_manager() # recuperate the BipPluginManager object
    bpm
    # <bip.gui.pluginmanager.BipPluginManager object at 0x000001EFE42D68D0>
    tp = bpm["TstPlugin"] # recuperate the plugin object name TstPlugin
    tp # can also be recuperated by passing directly the class
    # <__plugins__tst_plg.TstPlugin object at 0x000001EFE42D69B0>
    tp.hello() # calling a method of TstPlugin
    # hello



