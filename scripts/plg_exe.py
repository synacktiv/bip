from bip.gui import *

class ExPlugin(BipPlugin):

    @classmethod
    def to_load(cls):
        return True # always loading

    @shortcut("Ctrl-H")
    @shortcut("Ctrl-5")
    @menu("Edit/Plugins/", "ExPlugin Action!")
    def action_with_shortcut(self):
        print(self)
        print("In ExPlugin action !")# code here

# exp = ExPlugin()
# exp.load()
