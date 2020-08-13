import sys

#from . import pluginmanager
from .actions import BipAction
from .activity import BipActivity, BipActivityContainer

class BipPlugin(object):
    """
        Class for representing a plugin in IDA.

        All plugin should be instantiated only once. For adding a plugin the
        :class:`BipPluginManager` should be used (it can be recuperated using
        the :func:`get_plugin_manager` function).
        The following code can be used for loading a new plugin:

        .. code-block:: python
            
            class MyPlugin(BipPlugin): # define a new class for the plugin
                pass # implementation

            bpm = get_plugin_manager() # get the BipPluginManager
            bpm.addld_plugin("MyPlugin", MyPlugin, ifneeded=True) # add the plugin

        Once finish developping a :class:`BipPlugin` it can be directly
        set in the ``bipplugin`` folder for being loaded at start by the
        :class:`BipPluginManager`, in that case there is no need to call the
        :meth:`~BipPluginManager.addld_plugin`. The :meth:`BipPlugin.to_load`
        method can be rewritten for deciding when to load or not the plugin
        and the :meth:`BipPlugin.load` method allow to make actions directly
        when the plugin is loaded. :class:`BipActivity` and the associated
        decorators (:func:`menu`, :func:`shortcut`, ...) can be used for
        registering actions in IDA.

        .. note:: **BipPlugin and BipActivity**

            All :class:`BipPlugin` have an attribute ``_activities``
            corresponding to a dict of ``name`` (corresponding to the orginal
            name of the method) as key and with objects which inherit from
            :class:`BipActivity`. This dictionary is created by the
            constructor of this object and the activities are launch when
            the plugin is loaded.

        .. todo:: make a way to dynamically add and get activities
    """

    def __init__(self):
        """
            Constructor for a :class:`BipPlugin` object. This constructor
            should not be called directly but should be use by the
            :class:`BipPluginManager` . In particular this should avoid to
            have several time the same plugin register.

            .. warning:: Instentiating several time the same plugin class can
                create problems in particular link to its :class:`BipActivity`

            In particular this constructor is in charge to provide itself
            for its :class:`BipActivity` objects. Subclasses should call this
            constructor (using ``super``).
        """
        self._activities = {}
        self._init_activities()
        self._provide_plg_activities()

    ############################## ACTIVITIES ################################

    def _init_activities(self):
        """
            Internal methods which look for the object which inherit from
            :class:`BipActivity` and add them to the ``_activities``
            dictionary.
            
            This functions iter on all items in the object ``__dict__`` and
            the associated class for finding the :class:`BipActivity`.
        """
        for na, value in self.__dict__.items():
            if isinstance(value, BipActivity):
                self._activities[na] = value
        for na, value in self.__class__.__dict__.items():
            if isinstance(value, BipActivity):
                self._activities[na] = value

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

    ############################## LOADING  ################################

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

        An example of usage is the following:

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

