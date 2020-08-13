Plugin Manager
##############

.. module:: bip.gui

The :class:`~bip.gui.pluginmanager.BipPluginManager` is in charge of loading
the :class:`BipPlugin`, create and register the :class:`BipActivity` link to
them and allow to access the :class:`BipPlugin` instances once loaded.

The :class:`~bip.gui.pluginmanager.BipPluginManager` is a singleton and
should only be accessed using the :func:`get_plugin_manager` functions.
It is also the only class in Bip which is a *real* IDA plugin.

The main reason to use the :class:`~bip.gui.pluginmanager.BipPluginManager`
is to recuperate a :class:`BipPlugin` instance:

.. code-block:: python

    bpm = get_plugin_manager() # get the BipPluginManager
    plg = bpm["PLUGINNAME"] # get the plugin PLUGINNAME, PLUGINNAME should be the class of the plugin

or for loading a new plugin:

.. code-block:: python

    class MyPlugin(BipPlugin): # define a new class for the plugin
        pass # implementation

    bpm = get_plugin_manager() # get the BipPluginManager
    bpm.addld_plugin("MyPlugin", MyPlugin, ifneeded=True) # add the plugin
    # plugin in bipplugin folder will be loaded automatically and do not need those lines

The :class:`~bip.gui.pluginmanager.BipPluginManager` is not exposed at the
level of the module for avoiding instantiating a second object which will
trigger bugs, use :func:`get_plugin_manager` for getting the singleton object.

The :class:`~bip.gui.pluginmanager.BipPluginManager` is also in charge of
loading automatically 


BipPluginManager API
====================

.. autofunction:: get_plugin_manager

.. module:: bip.gui.pluginmanager

.. autoclass:: BipPluginManager
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. autoclass:: BipPluginLoader
    :members:
    :member-order: bysource
    :special-members:
    :private-members:


