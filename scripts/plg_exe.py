from bip.gui import *

class ExPlugin(BipPlugin):

    def to_load(self):
        return True # always loading

    @shortcut("Ctrl-H")
    def action_with_shortcut(bipaction):
        # TODO: this should be self in arguments (and maybe context ?)
        print("In ExPlugin action !")# code here

# exp = ExPlugin()
# exp.load()
