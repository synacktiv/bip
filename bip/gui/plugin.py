import pluginmanager
from actions import BipAction
from activity import BipActivity, BipActivityContainer

import sys

class MetaBipPlugin(type):
    """
        Metaclass for :class:`BipPlugin`.

        This metaclass has two main usage. The first is for interfacing
        with the plugin manager: it is used for checking no colision are made
        between the plugins and to allow the :class:`BipPluginManager` to
        register all  the plugins.

        The second usage is to create a dict of :class:`BipActivity`
        associated with a plugin. Those are stored in a dict with the name
        of the attribute as key and the :class:`BipActivity` object as value.
    """

    def __init__(cls, name, bases, dct):
        # Add activity in the class list
        cls._activities = {}
        for na, value in dct.items():
            if isinstance(value, BipActivity):
                cls._activities[na] = value
        super(MetaBipPlugin, cls).__init__(name, bases, dct) 
        # Add plugin to the plugin list
        # getting the plugin manager
        bpm = pluginmanager.get_plugin_manager()
        # black magic for the method of the plugin to be able to call super
        # we add the class to the module for it to be accessible
        # this is a hack but this should work in most case, it will be
        #   rewritten by python just after. There may be a problem in case the
        #   class is register inside a function or something
        mod_name = dct["__module__"]
        mod = sys.modules[mod_name]
        mod.__dict__[name] = cls
        # adding the plugin to the plugin manager
        bpm.addld_plugin(name, cls, ifneeded=True) # do not reload if already done

class BipPlugin(object):
    """
        Class for representing a plugin in IDA.

        All plugin should be instantiated only once.

        .. todo:: Put link to the PluginManager class for getting, loading,
            and Unloading driver
        
        .. todo:: provide a way to pass "arguments" to a plugin

        .. note:: **BipPlugin, metaclass and BipActivity**
        
            If you use a metaclass when defining a plugin, make sure
            it inherit from :class:`MetaBipPlugin` which is necessary for
            working with the plugin manager and the :class:`BipActivity`

            All :class:`BipPlugin` have an attribute ``_activities``
            corresponding to a dict of ``name`` (corresponding to the orginal
            name of the method) as key and with objects which inherit from
            :class:`BipActivity`

        .. todo:: singleton ?

        .. todo:: make a way to dynamically add and get activities

        .. todo:: should support to not automatically load plugin (doable with
            to_load but a more "standard way could be done")

        .. todo:: doc
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

            This method can be called several time.

            By default always return ``True``.

            :return: A boolean value indicating if the plugin should be loaded
                (``True``) or not (``False``).
        """
        return True

    def _register_activities(self):
        """
            Internal method which will parcour all the :class:`BipActivity`
            object which are associated with this plugin and register all of
            them.

            This method is not made for being called directly and should be
            call by the :meth:`BipPlugin.load` function.
        """
        for name, action in self._activities.items():
            action.register()

    def load(self):
        """
            Method which will be called by the :class:`BipPluginManager` when
            the plugin must be loaded.
            
            This method can be surcharge by a Plugin for allowing to take
            actions at the moment where it will be loaded.

            .. note:: This method is in charge of calling
                :meth:`~BipPlugin._register_activities` which allow to
                activate the :class:`BipActivity` link to this plugin.
                A plugin should ensure to call this method using ``super``.
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
        (ex.: ``Options/``).

        .. warning::

            Using this decorator for registering an entry in ``Edit/Plugins/``
            may create problems if the plugin is loaded during IDA
            initialisation and the entry may not be present in IDA. For more
            information see the documentation of
            :meth:`~BipAction.attach_to_menu`.

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

