from bip.base import *
from bip.gui import BipPlugin, menu
import re

class UnkLibFix(BipPlugin):
    """
        Plugin for fixing the ``unknown_libname_*`` function renaming when
        FLIRT signature are used. Three things can be removed: the name, the
        library flag and the repeatable comment. Functions are identified by
        being named ``unknown_libname_[0-9]+``.
        
        For doing this all functions must be iterate.

        Main methods are:

        * ``rm_unk_func``: remove name and library flag.
        * ``rm_unk_func_comm``: remove name, library flag and repeatable
          comment, if comments have been change by the user they will also
          be deleted.

        This plugin export entries in ``Bip/UnkLibFix/``
    """

    @menu("Bip/UnkLibFix/", "Remove unk func")
    def rm_unk_func(self):
        rx = re.compile("^unknown_libname_\d+$")
        for f in BipFunction.iter_all():
            if rx.match(f.name) is not None: # unknown func
                f.name = None # reset name
                f.is_lib = False # reset flag

    @menu("Bip/UnkLibFix/", "Remove unk func (with comment)")
    def rm_unk_func_comm(self):
        rx = re.compile("^unknown_libname_\d+$")
        for f in BipFunction.iter_all():
            if rx.match(f.name) is not None: # unknown func
                f.name = None # reset name
                f.is_lib = False # reset flag
                f.rcomment = "" # reset repeatable comment


