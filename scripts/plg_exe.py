from bip.gui import *

class ExPlugin(BipPlugin):

    def to_load(self):
        return True # always loading

    @shortcut("Ctrl-H")
    @shortcut("Ctrl-0")
    @menu("Edit/Plugins/", "ExPlugin Action!")
    def action_with_shortcut(self):
        print(self)
        print("In ExPlugin action !")# code here

# exp = ExPlugin()
# exp.load()
