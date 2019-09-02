.. _gui-plugins:

Plugins
#######

.. module:: bip.gui

Bip has it own systems of plugins refered as :class:`BipPlugin`, it is however
still possible to use bip in classic IDA plugin. All plugins should inherit
of the :class:`BipPlugin` class.

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

For example of a plugin you can check the overview (TODO: link) or look at the
printk plugin (TODO: link).

.. _gui-plugin-internals:

Implementation internals
========================

This part as for goal to describe the internal of the :class:`BipPlugin`:
how are they loaded by the :class:`~bip.gui.pluginmanager.BipPluginManager` 
and how the interface with :class:`BipActivity`.
It is not necessary to read it for using them or writting one.

Automatic loading of the plugins
--------------------------------

:class:`BipPlugin` are made for being loaded automatically by the
:class:`~bip.gui.pluginmanager.BipPluginManager`. For doing that the 
:class:`BipPlugin` use a metaclass: :class:`MetaBipPlugin` . When a new
plugin is created, the metaclass will warn the manager that a new plugin is
created. At that point if the plugin manager has already loaded the plugin
it will try to load it immediately, if not it will keep it in a list and try
to load it later (when the :class:`~bip.gui.pluginmanager.BipPluginManager`
is actually loaded by IDA).

When a :class:`BipPlugin` is loaded the following actions are made:

1. The attributes of the class are check for objects which inherit from the
   :class:`BipActivity` class and are stored in a ``_attributes`` list of the
   object (done by :class:`MetaBipPlugin`).
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
this will all be made during the creation of the :class:`BipPlugin` class
(which means we actually create the object during the creation of the class).
If you think this is a bad idea, well you're probably right but the number
of choices for having such a design is limited.

.. note:: **Several loading of python scripts**

     :class:`BipPlugin` should be loaded only once, it is important for not
     having problems with activities (see `Registering activities`_) and to
     keep a unique reference to the actual object. However python files
     in the ``plugins`` directory are actually loaded twice by IDA which
     creates problem with the design explain before. The manager will in that
     case just ignore the second appel.

.. note:: **Dynamic creation of plugins**

    If a :class:`BipPlugin` is loaded at the launch of IDA the manager will
    actually create it later (at the moment or it is himself loaded by IDA).
    However if a plugin is loaded later it will instanciated directly when
    the class is contructed (through the metaclass), this actually pose
    a problem if its constructor or the :meth:`BipPlugin.load` method use
    ``super``. When using ``super`` the class should be passed as first
    argument however, as we are still in the metaclass, the class is still
    not defined in the scope accessible by those methods. Using
    ``self.__class__`` works fine but can be counter intuitive. For avoiding
    the user to have problem with this, the class is artifically adding to
    the scope of the module before calling the constructor and
    :meth:`BipPlugin.load` method. This should work in most case however it
    can create problem in case the plugins are define in a different scope
    than the one of their module (for exemple inside a function).

Registering activities
----------------------

When a :class:`BipPlugin` is created the :class:`BipActivity` which are used
must be registered. During the creation of the class the :class:`MetaBipPlugin`
metaclass will create a list of all the :class:`BipActivity` link to the
plugin (see `Automatic loading of the plugins`_).

When a plugin is instantiated the :meth:`~BipPlugin.__init__` constructor will
call the :meth:`~BipPlugin._register_activities` which will take this list
and for each :class:`BipActivity` call its :meth:`~BipActivity.register`
method.

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

Internal API
============

.. autoclass:: MetaBipPlugin
    :members:
    :member-order: bysource

