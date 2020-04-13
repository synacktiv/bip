from bip.base import *
from bip.gui import BipPlugin, menu

class ColorCall(BipPlugin):
    """
        Plugin for coloring all call and the jumps which jump outside of the
        current function.

        Main methods are:

        * ``color_call`` : allows to iter an all instructions and color
          the call if needed.
        * ``color_calljmp`` : allows to iter an all instructions and color
          the call and jmp if needed.
        * ``colorcalljmp_in_func`` : same as ``color_call`` but color only
          instructions inside a function.

        This plugin export several entries in ``Bip/ColorCall/``.

        It is possible to change the :attr:`color` attribute of this plugin
        for changing the color to use.
    """

    def __init__(self):
        super(ColorCall, self).__init__()
        self.color = 0xFFAA55 #: Value for the color, format is BGR.

    @menu("Bip/ColorCall/", "Color only calls")
    def color_call(self):
        for i in Instr.iter_all():
            # if the instruction is a call we color it
            if i.is_call:
                i.color = self.color
                continue

    @menu("Bip/ColorCall/", "Color calls and jmp out")
    def color_calljmp(self):
        for i in Instr.iter_all():
            # if the instruction is a call we color it
            if i.is_call:
                i.color = self.color
                continue
            # if the instruction is in a func and it jump out of it we color it
            if i.is_in_func:
                f = i.func
                for elt in i.xCfNext:
                    # if the next instr is not in a function, or not the
                    #   same function: color current
                    if (not elt.is_in_func) or (elt.func != i.func):
                        i.color = self.color
                        break

    @menu("Bip/ColorCall/", "Color calls and jmp out (only in func)")
    def colorcalljmp_in_func(self):
        for f in BipFunction.iter_all():
            for i in f.instr:
                if i.is_call:
                    i.color = self.color
                    continue
                # if the instr jump out of the func we color it
                for elt in i.xCfNext:
                    if (not elt.is_in_func) or (elt.func != i.func):
                        i.color = self.color
                        break


