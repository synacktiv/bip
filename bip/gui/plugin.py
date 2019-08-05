import sys

from actions import BipAction
from activity import BipActivity, BipActivityContainer

_BIP_PLUGINS_LIST = {} # dict of bip plugin for plugin manager

class MetaBipPlugin(type):
    """
        Metaclass for plugins. This is used for checking no colision are made
        and to allow the plugin manager to register all plugins.

        .. todo:: doc the handling of the actions
    """

    def __init__(cls, name, bases, dct):
        # Add plugin to the plugin list
        global _BIP_PLUGINS_LIST
        if name in _BIP_PLUGINS_LIST:
            raise RuntimeError("Plugin already registered")
        _BIP_PLUGINS_LIST[name] = cls
        # Add activity in the class list # TODO: doc this
        cls._activities = {}
        for name, value in dct.items():
            if isinstance(value, BipActivity):
                cls._activities[name] = value
        return super(MetaBipPlugin, cls).__init__(name, bases, dct) 

class BipPlugin(object):
    """
        Class for representing a plugin in IDA.

        All plugin should be instantiated only once.

        .. todo:: Put link to the PluginManager class for getting, loading,
            and Unloading driver
        
        .. todo:: provide a way to pass "arguments" to a plugin

        .. note:: **BipPlugin and metaclass**
        
            If you use a metaclass when defining a plugin, make sure
            it inherit from :class:`MetaBipPlugin` which is necessary for
            working with the plugin manager and the :class:`BipActivity`

        .. todo:: doc
        .. todo:: everything
    """
    __metaclass__ = MetaBipPlugin

    def __init__(self):
        """
            Constructor for a :class:`BipPlugin` object. This constructor
            should not be called directly but should be use by the
            :class:`BipPluginManager` . In particular this should avoid to
            have several time the same plugin register.
            
            .. todo:: link to method for registering, and activating a plugin
                in the pluginmanager.

            .. warning:: Instentiating several time the same plugin class can
                create problems in particular link to its :class:`BipActivity`
            
            In particular this constructor is in charge to provide itself
            for its :class:`BipActivity` objects. Subclasses should call this
            constructor (using ``super``) or the internal method
            :meth:`~BipPlugin._provide_plg_activities` .
        """
        self._provide_plg_activities()

    def _provide_plg_activities(self):
        """
            Iterate on all :class:`BipActivity` of this object and set
            their ``plugin`` property with this object.

            This is an internal method and should not be called directly. The
            constructor of a :class:`BipPlugin` call this function.

            Internally this will iterate on the ``_activities`` property
            (dict) for providing the plugin.
        """
        for name, act in self._activities.items():
            act.plugin = self

    @classmethod
    def to_load(cls):
        """
            Class method allowing to test if this plugin should be loaded.
            At that point the plugin object has not been loaded yet, this
            allow to test if the plugin is made for working in this
            environment (python version, OS, IDA version, ...).

            By default always return ``True``.

            :return: A boolean value indicating if the plugin should be loaded
                (``True``) or not (``False``).
        """
        return True

    def _register_activities(self): # TODO
        """
            .. todo:: doc this
        """
        for name, action in self._activities.items():
            action.register()

    def load(self): # TODO
        """
            .. todo:: doc this
            .. todo:: finish implem
        """
        self._register_activities()


def shortcut(shortcut_str):
    """
        Decorator for defining a method of a :class:`BipPlugin` as a shortcut.
        This decorator expect a string in argument representing the shortcut
        it wants to register.

        The method which is decorated should only take ``self`` in argument
        which will be the :class:`BipPlugin` object.

        An exemple of usage is the following:

        .. code-block:: python

            class MyPlugin(BipPlugin):
                
                def my_method(self): # a method inside the plugin
                    print("Hello from MyPlugin.my_method")
                
                @shortcut("Ctrl-H")
                def my_shortcut(self):
                    # self is the MyPlugin object
                    self.my_method() # call the method before

            # Pressing Ctrl-H will trigger a call to my_shortcut which will
            # call my_method and print "Hello from MyPlugin.my_method". It
            # is also possible to use mp.my_shortcut directly as a function.

        Internally this decorator will define a :class:`BipAction` object and
        define its handler as a call to the method decorated with the plugin
        as argument. Accessing (without call) to the ``MyPlugin.my_shortcut``
        attribute will return a :class:`BipActivityContainer` object which
        will contain a :class:`BipAction` object corresponding to the shortcut
        define.

        :param str shortcut: The string representation of the shortcut.
    """
    def dec(func):
        bac = BipActivityContainer.get_container(func)

        # get the original method
        of = bac.get_original_method()

        # create the new action
        # use len of the container for avoiding redef.
        ba = BipAction("{}ShortCutAction{}".format(of.__name__, len(bac)),
                handler=lambda bipa, *args, **kwargs: of(bipa.plugin, *args, **kwargs),
                label=of.__name__, # put the normal string for the label
                shortcut=shortcut_str)

        # register the new action
        bac.add_activity(ba)

        return bac
    return dec

def menu(menu_path, menu_entry=None):
    """
        Decorator for defining a method of a :class:`BipPlugin` as an entry
        in the menu of IDA. This decorator expect a string in argument
        representing the path in the menu it wants to register
        (ex.: ``Edit/Plugins/``).

        The method which is decorated should only take ``self`` in argument
        which will be the :class:`BipPlugin` object. Internally this will
        create and add a :class:`BipAction` (for more information about the
        internal see :func:`shortcut`).

        :param str menu_path: The path at which the action should be
            registered.
        :param str menu_entry: The name which will apear in the menu for this
            action. If it is ``None`` (default) the name of the function will
            be used. Internaly this is the ``label`` of the
            :class:`BipAction`.
    """
    def dec(func):
        bac = BipActivityContainer.get_container(func)

        # get the original method
        of = bac.get_original_method()
        
        if menu_entry is not None:
            lbl = menu_entry
        else:
            lbl = of.__name__

        # create the new action
        # use len of the container for avoiding redef.
        ba = BipAction("{}MenuAction{}".format(of.__name__, len(bac)),
                handler=lambda bipa, *args, **kwargs: of(bipa.plugin, *args, **kwargs),
                label=lbl,
                path_menu=menu_path)

        # register the new action
        bac.add_activity(ba)

        return bac
    return dec

