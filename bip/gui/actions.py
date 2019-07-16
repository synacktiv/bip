import idaapi
from bip.base import *




class BipAction(object):
    """
        Bip object for representing an action in IDA. Action can have
        shortcuts, tollbar action, icon, name and must have an handler.

        The main use of this class can be made through decorator which should
        allow to simplify the life of the developer. See TODO.

        .. todo:: doc
        .. todo:: everything

        .. todo:: this should not be a simple wrapper on action_handler_t but
            should also allow to have events, callbacks, gui, ... Or probably
            need a base class for interface with the plugin and subclasses
            for integration in IDA.

        .. todo:: decorators
        .. todo:: metaclass for actions (maybe use this for checking unique name & stuff)
        .. todo:: allow to unregister
        .. todo:: handle ctx and access to it

        .. todo:: handler should be a method ?

        .. todo:: Make properties for every attribute...

        .. todo:: Allow sevaral shortcut, menu path, icon, ...
        .. todo:: handle activate **and** update
        .. todo:: Handle tooltip & icon
    """

    def __init__(self, name=None, label=None, shortcut=None, tooltip=None, icon=None, plugin=None):
        """
            Constructor for a :class:`BipAction` object.

            .. warning:: tooltip & icon are ignored for now.

            .. todo:: Handle tooltip & icon, remove previous warning

            :param name: Unique internal name for this action.
            :param label: Label for the action.
            :param shortcut: Optional shortcut for triggering the action.
            :param tooltip: Optional tooltip for the action.
            :param icon: Option icon for the action. 
            :param plugin: :class:`BipPlugin` to which this action is attach.
                Not used for now.
                
        """
        # Param
        self._name = name
        self._label = label
        self._shortcut = shortcut
        self._tooltip = tooltip
        self._icon = icon
        self._plugin = plugin

        # Internals
        self._ida_action_handler = None #: Internal idaapi.action_handler_t object

        # Externals
        self.is_register = False #: Boolean attribute which indicate if the action is registerd

        # Handling for params at None
        if self._name is None:
            self._name = self.__class__.__name__ # TODO: check for not already registered
        if self._label is None:
            self._label = self._name # if no label use the name

    def handler(self):
        """
            Handler for an action.

            By default raise a RuntimeError.

            .. todo:: doc
            .. todo:: ctx ? see idaapi.action_handler_t.activate
        """
        raise RuntimeError("Undefine handler for {}".format(self.__class__.__name__))

    def _activate(self, action_handler, ctx):
        """
            Use for idaapi.action_handler_t.activate function.

            Intenal

            .. todo:: doc
            .. todo:: be smart here.
        """
        self.handler()

    def _update(self, action_handler, ctx):
        """
            Use for idaapi.action_handler_t.update function.

            Intenal

            .. todo:: doc
            .. todo:: be smart here.
        """
        return idaapi.AST_ENABLE_ALWAYS


    def _create_action_handler(self):
        """
            Internal function which will create the idaapi.action_handler_t
            object.

            Will set it in :attr:`BipAction._ida_action_handler` and return
            it.
            
            .. todo:: Should check if already created ?
        """
        # TODO: Should check if already created ?
        # create object with needed method
        aht = idaapi.action_handler_t()
        aht.activate = lambda *args: self._activate(self, *args) # TODO: fix this
        aht.update =  lambda *args: self._update(self, *args) # TODO: fix this

        self._ida_action_handler = aht
        return aht

    def register(self):
        """
            Register the action in IDA.

            .. todo:: This should register all the actions necessary once
                it is possible to register several shortcuts and stuff

            .. todo:: this should be called by the plugin manager
        """
        if self._ida_action_handler is not None:
            aht = self._ida_action_handler
        else:
            aht = self._create_action_handler()
        adt = idaapi.action_desc_t(
            self._name, self._label, aht, self._shortcut,
            None, -1) # TODO: handle tooltip & icon
        idaapi.register_action(adt) # TODO: handle failure to register
        self.is_register = True

    def attach_to_menu(self, path, flags=idaapi.SETMENU_APP):
        """
            .. todo:: doc this
            .. todo:: this should be a param, enable when registering the action
        """
        # by default, add menu item after the specified path (can also be SETMENU_INS)
        idaapi.attach_action_to_menu(path, self._name, flags)







