Plugin Manager
##############

.. module:: bip.gui

The :class:`~bip.gui.pluginmanager.BipPluginManager` is in charge of loading
the :class:`BipPlugin`, create and register the :class:`BipActivity` link to
them and allow to access the :class:`BipPlugin` instances once loaded.

The :class:`~bip.gui.pluginmanager.BipPluginManager` is a singleton and
should only be accessed using the :func:`get_plugin_manager` functions.
It is also the only class in Bip which is a *real* IDA plugin.

There is few reason to directly use the
:class:`~bip.gui.pluginmanager.BipPluginManager` because
plugin are loaded automatically. The main reason for accessing it will be
to recuperate a :class:`BipPlugin` instance:

.. code-block:: python

    bpm = get_plugin_manager() # get the BipPluginManager
    plg = bpm["PLUGINNAME"] # get the plugin PLUGINNAME, PLUGINNAME should be the class of the plugin


.. note:: **Internals**

    The :class:`~bip.gui.pluginmanager.BipPluginManager` is not exposed at the
    level of the module for avoiding instantiating a second object which will
    trigger bugs.
    
    The loading and creation of a :class:`BipPlugin` is link to their metaclass
    and internal, see :ref:`gui-plugin-internals` for more information.

BipPluginManager API
====================

.. autofunction:: get_plugin_manager

.. module:: bip.gui.pluginmanager

.. autoclass:: BipPluginManager
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

