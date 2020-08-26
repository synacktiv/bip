.. _gui-plugins:

Plugins
#######

.. module:: bip.gui

Bip has it own systems of plugins refered as :class:`BipPlugin`. All plugins
should inherit of the :class:`BipPlugin` class. It is still possible to use
bip in classic IDA plugin, however the gui part of Bip is mostly link to
:class:`BipPlugin`.

A plugin is made for being load by the
:class:`~bip.gui.pluginmanager.BipPluginManager` and will be
instantiated only once. Once loaded it is possible to get the plugin instance
through the :class:`~bip.gui.pluginmanager.BipPluginManager` object:
``get_plugin_manager()["PLUGINNAME"]`` .

A typicall implementation of a plugin will:

* surcharge the :meth:`~BipPlugin.to_load` classmethod for checking if
  the plugin should be loaded.
* surcharge the :meth:`~BipPlugin.load` method for making actions when it it
  loaded in IDA.
* use some `activity decorators`_ for declaring actions.

For example of a plugin and advice on how to write one, you can check the
:ref:`general-overview-plugins` part of the :ref:`general-overview`.

.. _gui-plugin-internals:

Implementation internals
========================

This part as the goal to describe the internal of the :class:`BipPlugin`:
how are they loaded by the :class:`~bip.gui.pluginmanager.BipPluginManager` 
and how the interface with :class:`BipActivity`.
It is not necessary to read it for using them or writing one.

Loading of the plugins
----------------------

:class:`BipPlugin` are made for being loaded by the
:class:`~bip.gui.pluginmanager.BipPluginManager`. :class:`BipPlugin` present
in a particular directory (``bipplugin`` by default) will be loaded
automatically by the :class:`~bip.gui.pluginmanager.BipPluginManager`. For
doing this, the :class:`~bip.gui.pluginmanager.BipPluginManager` will search
for all ``.py`` files present in the ``bipplugin`` directory and will search
for classes which inherit from the :class:`BipPlugin` class. When the
:class:`~bip.gui.pluginmanager.BipPluginManager` is loaded by IDA it will load
all the plugins which has been found (this is done in the
:meth:`~bip.gui.pluginmanager.BipPluginManager.init` method).

It is also possible to load :class:`BipPlugin` "by hand" using the
:meth:`~bip.gui.pluginmanager.BipPluginManager.addld_plugin` method. If this
is done before the :class:`~bip.gui.pluginmanager.BipPluginManager` is loaded
by IDA, it will load the plugin later: the same way it is done for the
ones in the ``bipplugin`` directory. If the
:class:`~bip.gui.pluginmanager.BipPluginManager` is already loaded, the plugin
will be loaded immediately.

When a :class:`BipPlugin` is loaded the following actions are made:

1. The attributes of the class are check for objects which inherit from the
   :class:`BipActivity` class and are stored in a ``_attributes`` list of the
   object (done by the :class:`BipPlugin` constructor, implemented in the
   :meth:`BipPlugin._init_activities` method).
2. The class method :meth:`BipPlugin.to_load` will be called: if it returns
   ``False`` the plugin will not be loaded, if it return ``True`` the
   manager continue its steps (done by :class:`~bip.gui.pluginmanager.BipPluginManager`).
3. The :class:`BipPlugin` object is then created and the constructor will
   try to register its :class:`BipActivity` (see `Registering activities`_).
4. The plugin is added in the list of instance maintain by the
   :class:`~bip.gui.pluginmanager.BipPluginManager`.
5. Finally the :meth:`BipPlugin.load` method will be called
   (done by the :class:`~bip.gui.pluginmanager.BipPluginManager`).

It is important to note that if the
:class:`~bip.gui.pluginmanager.BipPluginManager` has already been init by IDA
this will all be made directly through the
:meth:`~bip.gui.pluginmanager.BipPluginManager.addld_plugin` method, but if
the :class:`~bip.gui.pluginmanager.BipPluginManager` has not yet been loaded
the plugin will be loaded later. It is possible to use the
:meth:`~bip.gui.pluginmanager.BipPluginManager.is_ready` to check if the
:class:`BipPluginManager` has initialized and as loaded its plugins.

.. note:: **Several loading of python scripts**

     :class:`BipPlugin` should be loaded only once, it is important for not
     having problems with activities (see `Registering activities`_) and to
     keep a unique reference to the actual object. However python files
     in the ``plugins`` directory are actually loaded twice by IDA which
     creates problem with the design explain before.

Registering activities
----------------------

When a :class:`BipPlugin` is created the :class:`BipActivity` which are used
must be registered. All :class:`BipPlugin` will be instantiated by the
:class:`BipPluginManager` through the method
:meth:`~BipPluginManager.load_all` or :meth:`~BipPluginManager.load_one`.
Those methods will called the class method :class:`BipPlugin.to_load` of the
:class:`BipPlugin` and if it returned true the constructor will be called
follow by the :meth:`BipPlugin.load` method.

When a plugin is instantiated, the :meth:`~BipPlugin.__init__` constructor
will call the :meth:`~BipPlugin._init_activities` which will create a dict
of all the :class:`BipActivity` objects define for the object and its class.
Then the method :meth:`~BipPlugin._provide_plg_activities` will provide to the
:class:`BipActivity` object the plugin in itself.

Once the :class:`BipPlugin` is instantiated, the :meth:`BipPlugin.load` method
will be called. This method will call :meth:`~BipPlugin._register_activities`
which will take the dict of :class:`BipActivity` and for each one call its
:meth:`~BipActivity.register` method.

BipPlugin API
=============

.. autoclass:: BipPlugin
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

.. _gui-plugin-activity-decorators:

Activity decorators
===================

Here is an overview of the currently available decorators, for more information
on how they work see :ref:`gui-activity-actions`:

=================== =================================================================== =========================================
Decorator Name      Description                                                         Usage example
=================== =================================================================== =========================================
:func:`shortcut`    Register a "hot-key" which will call the function when triggered.   ``@shortcut("Ctrl-H")``
:func:`menu`        Register an entry in a menu in IDA.                                 ``@menu("Edit/Plugins/", "PRINTNAME")``
=================== =================================================================== =========================================

.. autofunction:: shortcut
.. autofunction:: menu

