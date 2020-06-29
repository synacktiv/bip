import idaapi
import ida_kernwin

from bip.base import *
from activity import BipActivity

class BipAction(BipActivity):
    """
        Bip object for representing an action in IDA. Action can have
        shortcuts, tollbar action, icon, name and must have an handler. This
        is the equivalent of the ``idaapi.action_handler_t`` for Bip.

        The main use of this class can be made through decorator which should
        allow to simplify the life of the developer.
        See :ref:`gui-plugin-activity-decorators`.

        .. todo:: handle ctx and access to it

        .. todo:: Make properties for every attribute...

        .. todo:: handle activate **and** update
        .. todo:: Handle tooltip & icon
    """

    def __init__(self, name, handler=None, label=None, shortcut=None, path_menu=None, tooltip=None, icon=None):
        """
            Constructor for a :class:`BipAction` object.

            .. warning:: tooltip & icon are ignored for now.

            .. todo:: Handle tooltip & icon, remove previous warning

            :param name: Unique internal name for this action.
            :param handler: Handler function for this action. If it is None
                the :meth:`~BipAction.handler` method will be used instead.
            :param label: Label for the action. If ``None`` is provided
                (default) the name of the action will be used.
            :param str shortcut: Optional shortcut for triggering the action.
                This should be a string representing the shortcut
                (ex: ``Ctrl-H``).
            :param str path_menu: Optional path in the menu at which register
                the action. This should be a string representing the path
                (ex: ``Edit/Plugins/``)
            :param tooltip: Optional tooltip for the action.
            :param icon: Option icon for the action. 
        """
        # Param
        self._name = name
        self._label = label
        self._shortcut = shortcut
        self._tooltip = tooltip
        self._icon = icon
        self._path_menu = path_menu

        # Handler
        if handler is not None:
            ## create a method associated with this object
            #self.handler = types.MethodType(handler, self, self.__class__)
            # lets try simpler
            self._internal_handler = handler
        else:
            self._internal_handler = None


        # Internals
        self._ida_action_handler = None #: Internal idaapi.action_handler_t object

        # Externals
        self.is_register = False #: Boolean attribute which indicate if the action is registerd

        # Handling for params at None
        if self._name is None:
            self._name = self.__class__.__name__
        if self._label is None:
            self._label = self._name # if no label use the name

    def _activate(self, action_handler, ctx):
        """
            Intenal function which is used for 
            the idaapi.action_handler_t.activate function.

            This only call the :meth:`handler` method.

            .. todo:: doc
            .. todo:: be smart here.
        """
        self.handler()

    def _update(self, action_handler, ctx):
        """
            Intenal function which is used for the
            idaapi.action_handler_t.update function.
            
            This is always ``AST_ENABLE_ALWAYS``.

            .. todo:: doc
            .. todo:: be smart here.
        """
        return idaapi.AST_ENABLE_ALWAYS


    def _create_action_handler(self):
        """
            Internal function which will create the
            ``idaapi.action_handler_t`` object.

            Will set it in :attr:`BipAction._ida_action_handler` attribute and
            return it.
            
            .. todo:: Should check if already created ?
        """
        # TODO: Should check if already created ?
        # create object with needed method
        aht = idaapi.action_handler_t()
        aht.activate = lambda *args: self._activate(self, *args) # TODO: fix this
        aht.update =  lambda *args: self._update(self, *args) # TODO: fix this

        self._ida_action_handler = aht
        return aht

    def handler(self, *args, **kwargs):
        """
            Call the handler pass as argument of the constructor if defined or
            raise a ``RuntimeError`` if it is not defined. The arguments are
            passed to the internal handler, as is the return value.

            This is the main method of the :class:`BipAction` and the one
            which will be called one the action is triggered.
        """
        if self._internal_handler is not None:
            return self._internal_handler(self, *args, **kwargs)
        else:
            raise RuntimeError("BipAction handler is not defined.")

    def register(self):
        """
            Register the action in IDA and attach it to a menu if needed.

            Internally this will create the action handler if needed, then
            the action descriptor and register it in IDA. If a ``path_menu``
            argument as been define in the constructor it will also perform
            the attachement to the menu (using :meth:`attach_to_menu`.
        """
        if self._ida_action_handler is not None:
            aht = self._ida_action_handler
        else:
            aht = self._create_action_handler()
        adt = idaapi.action_desc_t(
            self._name, self._label, aht, self._shortcut,
            None, -1) # TODO: handle tooltip & icon
        if not ida_kernwin.register_action(adt):
            print("Unable to register action for {}".format(self._name))
            self.is_register = False
            return
        if self._path_menu is not None:
            if not self.attach_to_menu(self._path_menu):
                print("Unable to attach to menu: {}".format(self._path_menu))
        self.is_register = True

    def attach_to_menu(self, path, flags=idaapi.SETMENU_APP):
        """
            Attach this :class:`BipAction` as an element in the menu. The
            name of the action will be the one defined as the ``label`` of the
            constructor.

            This will be called automatically when the :class:`BipAction`
            is :meth:`~BipAction.register` if the path is provided in argument
            of the constructor as ``path_menu``. If the ``path_menu`` is not
            provided in the constructor this can be done by calling this
            function but the :meth:`~BipAction.register` must first be called.

            Attaching into the ``Edit/Plugins/`` menu when IDA is loading may
            create problem as this menu seems to be remade later and the entry
            may be overwritten (this seems to depend of IDA version and how
            early this method is called).

            :return: ``True`` if the action succeded, ``False`` otherwise.
        """
        # by default, add menu item after the specified path (can also be SETMENU_INS)
        return ida_kernwin.attach_action_to_menu(path, self._name, flags)

    def unregister(self):
        """
            Unregister the action in IDA, if this action was not register this
            function does nothing. Unregistering should also delete the entry
            from the menu if any.
        """
        if not self.is_register:
            return # nothing to do
        ida_kernwin.unregister_action(self._name)
        self.is_register = False


