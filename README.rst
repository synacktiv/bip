Bip
###

Bip is a project which aims to simplify the usage of python for interacting
with IDA. Its main goals are to facilitate the usage of python in the
interactive console of IDA and the writing of plugins. In a more general way
the goal is to automate recurrent tasks done through the python API.
Bip is also developed to provide a more object oriented, a "python-like"
API and a *real* documentation.

This code is not complete, and a lot of features are still missing. Development
is prioritized on what people ask for and what the developers use, so do not
hesitate to make PR, Feature Request and Issues (including for the
documentation).

The documentation is available in the RST format (and can be compiled using
sphinx) in the ``docs/`` directory, it is also
available `online <https://synacktiv.github.io/bip/build/html/index.html>`_.

* Current IDA version: IDA 7.5SP1 and Python 2.7 or 3.8
* Last Bip Version: 1.0

Installation
============

This installation has been tested only on Windows and Linux: ``python install.py``.

It is possible to use an optional ``--dest`` argument to install in a
particular folder:

.. code-block:: none

    usage: install.py [-h] [--dest DEST]

    optional arguments:
      -h, --help   show this help message and exit
      --dest DEST  Destination folder where to install Bip

This installer does not install any plugins by default, but simply the core of
Bip. By default the destination folder is the one used by IDA locally
(``%APPDATA%\Hex-Rays\IDA Pro\`` for Windows and ``$HOME/.idapro`` for Linux
and MacOSX).

Overview
========

This overview has a goal to show how the most usual operations can be done,
it is far from being complete. All functions and objects in Bip are documented
using doc string so just use ``help(BipClass)`` and ``help(obj.bipmethod)`` to
get the doc in your shell.

Base
----

The module ``bip.base`` contains most of the *basic* features for interfacing
with IDA. In practice this is mainly the disassembler part of IDA, this
includes: manipulation of instructions, functions, basic blocks, operands,
data, xrefs, structures, types, ...

Instructions / Operands
~~~~~~~~~~~~~~~~~~~~~~~

The classes ``bip.base.BipInstr`` and ``bip.base.BipOperand``:

.. code-block:: pycon

    >>> from bip.base import *
    >>> i = BipInstr() # BipInstr is the base class for representing an instruction
    >>> i # by default the address on the screen is taken
    BipInstr: 0x1800D324B (mov     rcx, r13)
    >>> i2 = BipInstr(0x01800D3242) # pass the address in argument
    >>> i2
    BipInstr: 0x1800D3242 (mov     r8d, 8)
    >>> i2.next # access next instruction, previous with i2.prev
    BipInstr: 0x1800D3248 (mov     rdx, r14)
    >>> l = [i3 for i3 in BipInstr.iter_all()] # l contains the list of all BipInstruction of the database, iter_all produces a generator object
    >>> i.ea # access the address
    6443315787
    >>> i.mnem # mnemonic representation
    mov
    >>> i.ops # access to the operands
    [<bip.base.operand.BipOperand object at 0x0000022B0291DA90>, <bip.base.operand.BipOperand object at 0x0000022B0291DA58>]
    >>> i.ops[0].str # string representation of an operand
    rcx
    >>> i.bytes # bytes in the instruction
    [73L, 139L, 205L]
    >>> i.size # number of bytes of this instruction
    3
    >>> i.comment = "hello" # set a comment, rcomment for the repeatable comments
    >>> i
    BipInstr: 0x1800D324B (mov     rcx, r13; hello)
    >>> i.comment # get a comment
    hello
    >>> i.func # access to the function
    Func: RtlQueryProcessLockInformation (0x1800D2FF0)
    >>> i.block # access to basic block
    BipBlock: 0x1800D3242 (from Func: RtlQueryProcessLockInformation (0x1800D2FF0))

Function / Basic block
~~~~~~~~~~~~~~~~~~~~~~

The classes ``bip.base.BipFunction`` and ``bip.base.BipBlock``:

.. code-block:: pycon

    >>> from bip.base import *
    >>> f = BipFunction() # Get the function, screen address used if not provided
    >>> f
    Func: RtlQueryProcessLockInformation (0x1800D2FF0)
    >>> f2 = BipFunction(0x0018010E975) # provide an address, not necessary the first one
    >>> f2
    Func: sub_18010E968 (0x18010E968)
    >>> f == f2 # compare two functions
    False
    >>> f == BipFunction(0x001800D3021)
    True
    >>> hex(f.ea) # start address
    0x1800d2ff0L
    >>> hex(f.end) # end address
    0x1800d3284L
    >>> f = BipFunction.get_by_name("RtlQueryProcessLockInformation") # fetch the function from its name
    >>> f.name # get and set the name
    RtlQueryProcessLockInformation
    >>> f.name = "test"
    >>> f.name
    test
    >>> f.size # number of bytes in the function
    660
    >>> f.bytes # bytes of the function
    [72L, ..., 255L]
    >>> f.callees # list of functions called by this function
    [<bip.base.func.BipFunction object at 0x0000022B0291DD30>, ..., <bip.base.func.BipFunction object at 0x0000022B045487F0>]
    >>> f.callers # list of functions which call this function
    [<bip.base.func.BipFunction object at 0x0000022B04544048>]
    >>> f.instr # list of instructions in the function
    [<bip.base.instr.BipInstr object at 0x0000022B0291DB00>, ..., <bip.base.instr.BipInstr object at 0x0000022B0454D080>]
    >>> f.comment = "welcome to bip" # comment of the function, rcomment for repeatable ones
    >>> f.comment
    welcome to bip
    >>> f.does_return # does this function return ?
    True
    >>> BipFunction.iter_all() # allows to iter on all functions defined in the database
    <generator object iter_all at 0x0000022B029231F8>
    >>> f.nb_blocks # number of basic blocks
    33
    >>> f.blocks # list of blocks
    [<bip.base.block.BipBlock object at 0x0000022B04544D68>, ..., <bip.base.block.BipBlock object at 0x0000022B04552240>]
    >>> f.blocks[5] # access the basic block 5, could be done with BipBlock(addr)
    BipBlock: 0x1800D306E (from Func: test (0x1800D2FF0))
    >>> f.blocks[5].func # link back to the function
    Func: test (0x1800D2FF0)
    >>> f.blocks[5].instr # list of instructions in the block
    [<bip.base.instr.BipInstr object at 0x0000022B04544710>, ..., <bip.base.instr.BipInstr object at 0x0000022B0291DB00>]
    >>> f.blocks[5].pred # predecessor blocks, blocks where control flow lead to this one
    [<bip.base.block.BipBlock object at 0x0000022B04544D68>]
    >>> f.blocks[5].succ # successor blocks
    [<bip.base.block.BipBlock object at 0x0000022B04544710>, <bip.base.block.BipBlock object at 0x0000022B04544438>]
    >>> f.blocks[5].is_ret # is this block containing a return
    False

Data
~~~~

The class ``bip.base.BipData``:

.. code-block:: pycon

    >>> from bip.base import *
    >>> d = BipData(0x000180110068) # .rdata:0000000180110068 bip_ex          dq offset unk_180110DE0
    >>> d
    BipData at 0x180110068 = 0x180110DE0 (size=8)
    >>> d.name # Name of the symbol if any
    bip_ex
    >>> d.is_word # is it a word
    False
    >>> d.is_qword # is it a qword
    True
    >>> hex(d.value) # value at that address, this take into account the basic type (byte, word, dword, qword) defined in IDA
    0x180110de0L
    >>> hex(d.ea) # address
    0x180110068L
    >>> d.comment = "example" # comment as before
    >>> d.comment
    example
    >>> d.value = 0xAABBCCDD # change the value
    >>> hex(d.value)
    0xaabbccddL
    >>> d.bytes # get the bytes, as before
    [221L, 204L, 187L, 170L, 0L, 0L, 0L, 0L]
    >>> hex(d.original_value) # get the original value before modification
    0x180110de0L
    >>> d.bytes = [0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0] # patch the bytes
    >>> hex(d.value) # get the value
    0x44332211L
    >>> BipData.iter_heads() # iter on "heads" of the IDB, heads are defined data in the IDB
    <generator object iter_heads at 0x0000022B02923240>
    >>> hex(BipData.get_dword(0x0180110078)) # staticmethod for reading value at an address
    0x60004L
    >>> BipData.set_byte(0x0180110078, 0xAA) # static method for modifying a value at an address
    >>> hex(BipData.get_qword(0x0180110078))
    0x600aaL

Element
~~~~~~~

In Bip most basic objects inherit from the same classes: ``BipBaseElt`` which is
the most basic one, ``BipRefElt`` which includes all the objects which can have
xrefs (including structures (``BipStruct``) and structure members
(``BStructMember``), see below), ``BipElt``
which represents all elements which have an address in the IDA DataBase (idb),
including ``BipData`` and ``BipInstr`` (it is this class which
implements the properties: ``comment``,  ``name``, ``bytes``, ...).

It is possible to use the functions ``GetElt`` and ``GetEltByName``
to get the right basic element from an address or a name
representing a location in the binary.

.. code-block:: pycon

    >>> from bip.base import *
    >>> GetElt() # get the element at current address, in this case return a BipData object
    BipData at 0x180110068 = 0xAABBCCDD (size=8)
    >>> GetElt(0x00180110078) # get the element at the address 0x00180110078
    BipData at 0x180110078 = 0xAA (size=1)
    >>> GetElt(0x1800D2FF0) # in this case it returns an BipInstr object because this is code
    BipInstr: 0x1800D2FF0 (mov     rax, rsp)
    >>> GetEltByName("bip_ex") # Get using a name and not an address
    BipData at 0x180110068 = 0xAABBCCDD (size=8)
    >>> isinstance(GetElt(0x1800D2FF0), BipInstr) # test if that element is an instruction ?
    True
    >>> GetElt(0x1800D2FF0).is_code # are we on code ? same for is_data; do not work for struct
    True
    >>> isinstance(GetElt(0x1800D2FF0), BipData) # or data ?
    False

Some static functions are provided to search elements in the database:

.. code-block:: pycon

    >>> from bip.base import *
    >>> GetElt()
    BipInstr: 0x1800D3248 (mov     rdx, r14)
    >>> BipElt.next_code() # find next code elt from current addres or addr passed as arg
    BipInstr: 0x1800D324B (mov     rcx, r13)
    >>> BipElt.prev_code() # find prev code element
    BipInstr: 0x1800D3242 (mov     r8d, 8)
    >>> BipElt.next_data() # find next data elt from current address or addr passed as arg
    BipData at 0x1800D3284 = 0xCC (size=1)
    >>> BipElt.prev_data() # find previous data element
    BipData at 0x1800D2FE1 = 0xCC (size=1)
    >>> hex(BipElt.prev_data_addr()) # find address of the previous data element
    0x1800d2fe1L
    >>> BipElt.next_unknown() # same for unknown, which are not typed element of IDA and are considered data by Bip
    BipData at 0x180110000 = 0xE (size=1)
    >>> BipElt.next_defined() # opposite of unknown: data or code
    BipInstr: 0x1800D324B (mov     rcx, r13)
    >>> BipElt.search_bytes("49 ? CD", 0x1800D3248) # search for byte sequence (ignore the current position by default)
    BipInstr: 0x1800D324B (mov     rcx, r13)

Xref
~~~~

All elements which inherit from ``BipRefElt`` (``BipInstr``,
``BipData``, ``BipStruct``, ...) and some other (in
particular ``BipFunction``) contain methods which allow
to access xrefs. They are represented by the ``BipXref`` objects which
have a ``src`` (origin of the xref) and a ``dst`` (destination of the xref).

.. code-block:: pycon

    >>> from bip.base import *
    >>> i = BipInstr(0x01800D3063)
    >>> i # example with instruction but works the same with BipData
    BipInstr: 0x1800D3063 (cmp     r15, [rsp+98h+var_58])
    >>> i.xTo # List of xref which point on this instruction
    [<bip.base.xref.BipXref object at 0x0000022B04544438>, <bip.base.xref.BipXref object at 0x0000022B045447F0>]
    >>> i.xTo[0].src # previous instruction
    BipInstr: 0x1800D305E (mov     [rsp+98h+var_78], rsi)
    >>> i.xTo[0].is_ordinaryflow # is this an ordinary flow between to instruction (not jmp or call)
    True
    >>> i.xTo[1].src # jmp to instruction i at 0x1800D3063
    BipInstr: 0x1800D3222 (jmp     loc_1800D3063)
    >>> i.xTo[1].is_jmp # is this xref because of a jmp ?
    True
    >>> i.xEaTo # bypass the xref objects and get the address directly
    [6443315294L, 6443315746L]
    >>> i.xEltTo # bypass the xref objects and get the elements directly, will list BipData if any
    [<bip.base.instr.BipInstr object at 0x0000022B045447F0>, <bip.base.instr.BipInstr object at 0x0000022B04544978>]
    >>> i.xCodeTo # bypass the xref objects and get the instr directly, if a BipData was pointed at this address it will not be listed
    [<bip.base.instr.BipInstr object at 0x0000022B04544438>, <bip.base.instr.BipInstr object at 0x0000022B0291DD30>]
    >>> i.xFrom # same but for coming from this instruction
    [<bip.base.xref.BipXref object at 0x0000022B04544D68>]
    >>> i.xFrom[0]
    <bip.base.xref.BipXref object at 0x0000022B04544438>
    >>> i.xFrom[0].dst # next instruction
    BipInstr: 0x1800D3068 (jz      loc_1800D3227)
    >>> i.xFrom[0].src # current instruction
    BipInstr: 0x1800D3063 (cmp     r15, [rsp+98h+var_58])
    >>> hex(i.xFrom[0].dst_ea) # address of the next instruction
    0x1800D3068L
    >>> i.xFrom[0].is_codepath # this is a normal code path (include jmp and call)
    True
    >>> i.xFrom[0].is_call # is this because of a call ?
    False
    >>> f = BipFunction()
    >>> f
    Func: RtlQueryProcessLockInformation (0x1800D2FF0)
    >>> f.xTo # works also for functions, but only with To, not with the From
    [<bip.base.xref.BipXref object at 0x000001D95529EB00>, <bip.base.xref.BipXref object at 0x000001D95529EB70>, <bip.base.xref.BipXref object at 0x000001D95529EBE0>, <bip.base.xref.BipXref object at 0x000001D95529EC88>]
    >>> f.xEltTo # here we have 3 data references to this function
    [<bip.base.instr.BipInstr object at 0x000001D95529EE48>, <bip.base.data.BipData object at 0x000001D95529EEF0>, <bip.base.data.BipData object at 0x000001D95529EF28>, <bip.base.data.BipData object at 0x000001D95529EF60>]
    >>> f.xCodeTo # but only one instruction
    [<bip.base.instr.BipInstr object at 0x000001D95529EC88>]

Struct
~~~~~~

Manipulating struct (``BipStruct``) and members (``BStructMember``):

.. code-block:: pycon

    >>> from bip.base import *
    >>> st = BipStruct.get("EXCEPTION_RECORD") # Structs are accessed by using get and their name
    >>> st # BipStruct object
    Struct: EXCEPTION_RECORD (size=0x98)
    >>> st.comment = "struct comment"
    >>> st.comment
    struct comment
    >>> st.name
    EXCEPTION_RECORD
    >>> st.size
    152
    >>> st["ExceptionFlags"] # access to the BStructMember by their name
    Member: EXCEPTION_RECORD.ExceptionFlags (offset=0x4, size=0x4)
    >>> st[8] # or by their offset, this is *not* the entry number 8!!!
    Member: EXCEPTION_RECORD.ExceptionRecord (offset=0x8, size=0x8)
    >>> st[2] # offset does not need to be the first one
    Member: EXCEPTION_RECORD.ExceptionCode (offset=0x0, size=0x4)
    >>> st.members # list of members
    [<bip.base.struct.BStructMember object at 0x000001D95529EEF0>, ..., <bip.base.struct.BStructMember object at 0x000001D95536DF28>]
    >>> st[0].name
    ExceptionCode
    >>> st[0].fullname
    EXCEPTION_RECORD.ExceptionCode
    >>> st[0].size
    4
    >>> st[0].struct
    Struct: EXCEPTION_RECORD (size=0x98)
    >>> st[0].comment = "member comment"
    >>> st[0].comment
    member comment
    >>> st[8].xEltTo # BStructMember et BipStruct have xrefs
    [<bip.base.instr.BipInstr object at 0x000001D95536DD30>, <bip.base.instr.BipInstr object at 0x000001D95536D9E8>]
    >>> st[8].xEltTo[0]
    BipInstr: 0x1800A0720 (mov     [rsp+538h+ExceptionRecord.ExceptionRecord], r10)

Creating struct, adding members and nested structure:

.. code-block:: pycon

    >>> from bip.base import *
    >>> st = BipStruct.create("NewStruct") # create a new structure
    >>> st
    Struct: NewStruct (size=0x0)
    >>> st.add("NewField", 4) # add a new member named "NewField" of size 4
    Member: NewStruct.NewField (offset=0x0, size=0x4)
    >>> st.add("NewQword", 8)
    Member: NewStruct.NewQword (offset=0x4, size=0x8)
    >>> st
    Struct: NewStruct (size=0xC)
    >>> st.add("struct_nested", 1)
    Member: NewStruct.struct_nested (offset=0xC, size=0x1)
    >>> st["struct_nested"].type = BipType.from_c("EXCEPTION_RECORD") # changing the type of member struct_nested to struct EXCEPTION_RECORD
    >>> st["struct_nested"]
    Member: NewStruct.struct_nested (offset=0xC, size=0x98)
    >>> st["struct_nested"].is_nested # is this a nested structure ?
    True
    >>> st["struct_nested"].nested_struct # getting the nested structure
    Struct: EXCEPTION_RECORD (size=0x98)

Types
~~~~~

IDA uses extensively types in hexrays but also in the base API for defining
types of data, variables and so on. In Bip the different types inherit from
the same class ``BipType``. This class offers some basic methods common to all
types and subclasses (class starting by ``BType``) can define more specific
ones.

The types should be seen as a recursive structure: a ``void *`` is a
``BTypePtr`` containing a ``BTypeVoid`` structure. For a list of the
different types implemented in Bip see the `documentation <https://synacktiv.github.io/bip/build/html/base/type.html>`_.

.. code-block:: pycon

    >>> from bip.base import *
    >>> pv = BipType.from_c("void *") # from_c is the easiest way to create a type
    >>> pv
    <bip.base.biptype.BTypePtr object at 0x000001D95536DDD8>
    >>> pv.size # ptr on x64 is 8 bytes
    8
    >>> pv.str # C string representation
    void *
    >>> pv.is_named # this type is not named
    False
    >>> pv.pointed # type below the pointer (recursive)
    <bip.base.biptype.BTypeVoid object at 0x000001D95536DF60>
    >>> pv.children # list of type pointed
    [<bip.base.biptype.BTypeVoid object at 0x000001D95536DEB8>]
    >>> d = BipData(0x000180110068)
    >>> d.type # access directly to the type at the address
    <bip.base.biptype.BTypePtr object at 0x000001D95536D9E8>
    >>> d.type.str
    void *
    >>> ps = BipType.from_c("EXCEPTION_RECORD *")
    >>> ps.pointed # type for struct EXCEPTION_RECORD
    <bip.base.biptype.BTypeStruct object at 0x000001D95536DD30>
    >>> ps.pointed.is_named # this one is named
    True
    >>> ps.pointed.name
    EXCEPTION_RECORD
    >>> ps.set_at(d.ea) # set the type ps at address d.ea
    >>> d.type.str # the type has indeed changed
    EXCEPTION_RECORD *
    >>> d.type = pv # rolling it back
    >>> d.type.str
    void *
    >>> BipType.get_at(d.ea) # Possible to directly get the type with get_at(address)
    <bip.base.biptype.BTypePtr object at 0x000001D95536DEB8>

Hexrays
-------

The module ``bip.hexrays`` contains the features linked to the decompiler
provided by IDA.

Functions / local variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Hexrays functions are represented by the ``HxCFunc`` objects and local
variable by the ``HxLvar`` objects:

.. code-block:: pycon

    >>> HxCFunc.from_addr() # HxCFunc represents a decompiled function
    <bip.hexrays.hx_cfunc.HxCFunc object at 0x00000278AE80C860>
    >>> hf = BipFunction().hxcfunc # accessible from a "normal function"
    >>> hex(hf.ea) # address of the function
    0x1800d2ff0L
    >>> hf.args # list of the arguments as HxLvar objects
    [<bip.hexrays.hx_lvar.HxLvar object at 0x00000278AFDAACF8>]
    >>> hf.lvars # list of all local variables (including args)
    [<bip.hexrays.hx_lvar.HxLvar object at 0x00000278AFDAAB70>, ..., <bip.hexrays.hx_lvar.HxLvar object at 0x00000278AFDAF4E0>]
    >>> lv = hf.lvars[0] # getting the first one
    >>> lv
    LVAR(name=a1, size=8, type=<bip.base.biptype.BTypeInt object at 0x00000278AFDAAFD0>)
    >>> lv.name # getting name of lvar
    a1
    >>> lv.is_arg # is this variable an argument ?
    True
    >>> lv.name = "thisisthefirstarg" # changing name of the lvar
    >>> lv
    >>> lv.type = BipType.from_c("void *") # changing the type
    >>> lv.comment = "new comment" # adding a comment
    >>> lv.size # getting the size
    8

CNode / Visitors
~~~~~~~~~~~~~~~~

Hexrays allows to manipulate the AST it produces, this is a particularly
useful feature as it allows to make static analysis at a way higher level.
Bip defines ``CNode`` which represents a node of the AST, each type of node is
represented by a subclass of ``CNode``. All types of node have child nodes except
``CNodeExprFinal`` which are the leaf of the AST. Two *main* types of nodes
exist ``CNodeExpr`` (expressions) and ``CNodeStmt`` (statements).
Statements correspond to the C Statements: if, while, ... , expressions are everything
else. Statements can have children statements or expressions while expressions
can only have expression children.

A list of all the different types of nodes and more details on what they do and
how to write a visitor is available in the `documentation <https://synacktiv.github.io/bip/build/html/hexrays/astnodes.html#ast-node-types>`_.

Directly accessing the nodes:

.. code-block:: pycon

    >>> hf = HxCFunc.from_addr() # get the HxCFunc
    >>> rn = hf.root_node # accessing the root node of the function
    >>> rn # root node is always a CNodeStmtBlock
    CNodeStmtBlock(ea=0x1800D3006, stmt_children=[<bip.hexrays.cnode.CNodeStmtExpr object at 0x00000278AFDAADD8>, ..., <bip.hexrays.cnode.CNodeStmtReturn object at 0x00000278B16355F8>])
    >>> hex(rn.ea) # address of the root node, after the function prolog
    0x1800d3006L
    >>> rn.has_parent # root node does not have parent
    False
    >>> rn.expr_children # this node does not have expression statements
    []
    >>> ste = rn.stmt_children[0] # getting the first statement children
    >>> ste # CNodeStmtExpr contain one child expression
    CNodeStmtExpr(ea=0x1800D3006, value=CNodeExprAsg(ea=0x1800D3006, ops=[<bip.hexrays.cnode.CNodeExprVar object at 0x00000278AFDAADD8>, <bip.hexrays.cnode.CNodeExprVar object at 0x00000278B1637080>]))
    >>> ste.parent # the parent is the root node
    CNodeStmtBlock(ea=0x1800D3006, stmt_children=[<bip.hexrays.cnode.CNodeStmtExpr object at 0x00000278B1637048>, ..., <bip.hexrays.cnode.CNodeStmtReturn object at 0x00000278B16376D8>])
    >>> a = ste.value # getting the expression of the node
    >>> a # Asg is an assignement
    CNodeExprAsg(ea=0x1800D3006, ops=[<bip.hexrays.cnode.CNodeExprVar object at 0x00000278AFDAADD8>, <bip.hexrays.cnode.CNodeExprVar object at 0x00000278B1637080>])
    >>> a.first_op # first operand of the assignement is a lvar, lvar are leaf
    CNodeExprVar(ea=0xFFFFFFFFFFFFFFFF, value=1)
    >>> a.first_op.lvar # get the lvar object
    LVAR(name=v1, size=8, type=<bip.base.biptype.BTypeInt object at 0x00000278B16390B8>)
    >>> a.ops # list all operands of the expression
    [<bip.hexrays.cnode.CNodeExprVar object at 0x00000278AFDAADD8>, <bip.hexrays.cnode.CNodeExprVar object at 0x00000278B1639080>]
    >>> a.ops[1] # getting the second operand, also a lvar
    CNodeExprVar(ea=0xFFFFFFFFFFFFFFFF, value=0)
    >>> hex(a.ops[1].closest_ea) # lvar have no position in the ASM, but possible to take the one of the parents
    0x1800d3006L

The previous code show how to get a value and manipulate nodes quickly. To
do an analysis it is easier to use visitors on the complete function.
``HxCFunc.visit_cnode`` allows to visit all the nodes in a function with a
callback, ``HxCFunc.visit_cnode_filterlist`` allows to visit only nodes of a
certain type by passing a list of the node classes.

This script is an example to visit a function and get the
format string passed to a ``printk`` function. It locates the call to ``printk``,
gets the address of the first argument, gets the string and adds a comment
in both hexrays and the assembly:

.. code-block:: python

    from bip import *

    """
        Search for all call to printk, if possible gets the string and adds
        it in comments at the level of the call.
    """

    def is_call_to_printk(cn):
        """
            Check if the node object represent a call to the function ``printk``.

            :param cn: A :class:`CNodeExprCall` object.
            :return: True if it is a call to printk, False otherwise
        """
        f = cn.caller_func
        return f is not None and f.name == "printk"

    def visit_call_printk(cn):
        """
            Visitor for call node which will check if a node is a call to
            ``printk`` and add the string in comment if possible.

            :param cn: A :class:`CNodeExprCall` object.
        """
        # check if it calls to printk
        # For more perf. we would want to use xref to printk and checks of
        #   the address of the node
        if not is_call_to_printk(cn): # not a call to printk: ignore
            return
        if cn.number_args < 1: # not enough args
            print("Not enough args at 0x{:X}".format(cn.closest_ea))
            return
        cnr = cn.get_arg(0).ignore_cast # get the arg
        # if we have a ref (&global) we want the object under
        if isinstance(cnr, CNodeExprRef):
            cnr = cnr.ops[0].ignore_cast
        # if this is not a global object we ignore it
        if not isinstance(cnr, CNodeExprObj):
            print("Not an object at 0x{:X}".format(cn.closest_ea))
            return
        ea = cnr.value # get the address of the object
        s = None
        try:
            s = BipData.get_cstring(ea + 2) # get the string
        except Exception:
            pass
        if s is None or len(s) == 0:
            print("Invalid string at 0x{:X}".format(cn.closest_ea))
            return
        s = str(s) # python2/python3 compat
        s = s.strip() # remove \n
        # add comment both in hexrays and in asm view
        cn.hxcfunc.add_cmt(cn.closest_ea, s)
        GetElt(cn.closest_ea).comment = s

    # Final function which takes the address of a function and comments the call
    #   to printk
    def printk_handler(eafunc):
        hf = HxCFunc.from_addr(eafunc) # get the hexrays function
        hf.visit_cnode_filterlist(visit_call_printk, [CNodeExprCall]) # visit only the call nodes

While visitors are convenient (and "fast"), Bip also exposes methods to directly
get the ``CNode`` objects as a list. The methods
``HxCFunc.get_cnode_filter`` and ``HxCFunc.get_cnode_filter_type``
allow to avoid having a visitor function and make it easier to manipulate
the hexrays API. It is also worth noting that all visitors functions provided
by ``HxCFunc`` objects are also available directly in ``CNode``
objects to visit only a sub-tree of the full AST.


Plugins
-------

Plugins using Bip should all inherit from the class ``BipPlugin``. Those
plugins are different from the IDA plugins and are loaded and called by the
``BipPluginManager``. Each plugin is identified by its class name and those
should be unique. Bip can be used with standard plugin but most of the
``bip.gui`` implementation is linked to the use of ``BipPlugin``. For
more information about plugins and internals see the `documentation <https://synacktiv.github.io/bip/build/html/gui/plugin.html#gui-plugins>`_.

Here is a simple plugin example:

.. code-block:: python

    from bip.gui import * # BipPlugin is defined in the bip.gui module

    class ExPlugin(BipPlugin):
        # inherit from BipPlugin, all plugin should be instantiated only once
        # this should be done by the plugin manager, not "by hand"

        @classmethod
        def to_load(cls): # allow to test if the plugin apply, this MUST be a classmethod
            return True # always loading

        @shortcut("Ctrl-H") # add a shortcut as a decorator, will call the method below
        @shortcut("Ctrl-5") # add an other one
        @menu("Bip/MyPluginExample/", "ExPlugin Action!") # add a menu entry named "ExPlugin Action!", default is the method name
        def action_with_shortcut(self):
            print(self) # this is the ExPlugin object
            print("In ExPlugin action !")# code here

    bpm = get_plugin_manager() # get the BipPluginManager object
    bpm.addld_plugin("ExPlugin", ExPlugin) # ask the BipPluginManager to load the plugin
    # plugins in ``bipplugin`` folder will be loaded automatically and do not need those lines


The ``menu`` decorator will automatically create the ``MyPluginExample``
menu entry in the ``Bip`` top level menu entry (which is created by the
``BipPluginManager``), creating an entry in the ``Edit/Plugins/``
directory may not work because of how the entry of this submenu are created
by IDA.

A plugin can expose methods which another plugin wants to call or directly
from the console. A plugin should not be directly instantiated, it is the
``BipPluginManager`` which is in charge of loading it. To get a
``BipPlugin`` object, it should be requested to the plugin manager:

.. code-block:: python

    from bip.gui import *
    bpm = get_plugin_manager() # get the BipPluginManager object
    bpm
    # <bip.gui.pluginmanager.BipPluginManager object at 0x000001EFE42D68D0>
    tp = bpm["TstPlugin"] # get the plugin object name TstPlugin
    tp # can also be recuperated by passing directly the class
    # <__plugins__tst_plg.TstPlugin object at 0x000001EFE42D69B0>
    tp.hello() # calling a method of TstPlugin
    # hello

For the previous example with ``printk`` we could write the following plugin:

.. code-block:: python

    class PrintkComs(BipPlugin):

        def printk_handler(self, eafunc):
            """
                Comment all call to printk in a function with the format string
                pass to the printk. Comments are added in both the hexrays and ASM
                view. Works only if the first argument is a global.

                :param eafunc: The addess of the function in which to add the
                    comment.
            """
            try:
                hf = HxCFunc.from_addr(eafunc) # get hexray view of the func
            except Exception:
                print("Fail getting the decompile view for function at 0x{:X}".format(eafunc))
                return
            hf.visit_cnode_filterlist(visit_call_printk, [CNodeExprCall]) # visit only on the call

        @shortcut("Ctrl-H")
        @menu("Bip/PrintkCom/", "Comment printk in current function")
        def printk_current(self):
            """
                Add comment for the current function.
            """
            self.printk_handler(Here())

        @menu("Bip/PrintkCom/", "Comment all printk")
        def printk_all(self):
            """
                Add comment for the all the functions in the IDB.
            """
            # get the function which call printk
            f = BipFunction.get_by_name("printk")
            if f is None:
                print("No function named printk")
                return
            for fu in f.callers:
                print("Renaming for {}".format(fu))
                self.printk_handler(fu.ea)

When testing a ``BipPlugin``, it will often be necessary to reload
the plugin several times. The easiest way to do that will
be to use the ``BipPluginManager.reload_plugin``
method from the ``BipPluginManager`` and to reload
the file containing the ``BipPlugin`` using the ``Script File...``
(``Alt+F7``) IDA option. If you want to reload the ``PrintkComs`` plugin,
re-import the script with ``Alt+F7`` and call the following code:
``get_plugin_manager().reload_plugin(PrintkComs)``.


Similar projects
================

* `sark <https://sark.readthedocs.io/en/latest/>`_: "an object-oriented scripting layer written on top of IDAPython".
* `ida-minsc <https://github.com/arizvisa/ida-minsc>`_: "a plugin for IDA Pro that assists a user with scripting the IDAPython plugin that is bundled with the disassembler".
* `FIDL <https://github.com/fireeye/FIDL>`_: "FLARE IDA Decompiler Library"

Thanks
======

Some people to thanks:

* `saph <https://twitter.com/clementberthaux>`_: for starting this project.
* `hakril <https://twitter.com/hakril>`_: for the inspiration for the project and his insights on designing it.

