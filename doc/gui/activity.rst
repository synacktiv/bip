.. _gui-activity-actions:

Activities and Actions
######################

.. module:: bip.gui

For allowing to define interaction between the user-interface and the plugins
Bip define :class:`BipActivity` . The intended way to use :class:`BipActivity` and
:class:`BipAction` is using the :ref:`gui-plugin-activity-decorators` with
a :class:`BipPlugin`.

The :class:`BipActivity` is an abstract class allowing to define interaction
with the IDA API and UI, in practice there is few reason to use them directly.

The :class:`BipActivityContainer` is a :class:`BipActivity` containing several
other :class:`BipActivity`, it is used internally for allowing to have several
decorators (and so :class:`BipActivity`) on the same method of a
:class:`BipPlugin`.

The :class:`BipAction` (which inherit from :class:`BipActivity`) allows
to define hotkeys (:func:`shortcut` decorator) or entries in the IDA menu
(:func:`menu` decorator). It can be created directly as an object for defining
actions dynamically and not link to a particular plugin.

.. _gui-activity-internals:

Implementation internals
========================

This part as for goal to describe the internal of the :class:`BipActivity`:
how they interface with :class:`BipPlugin` and how to create a new kind of
:class:`BipActivity` . It is not necessary to read it for simply using them.

Creating a new BipActivity
--------------------------

All :class:`BipActivity` subclasses should implement the methods:

* :meth:`~BipActivity.register`: register the interface with IDA. This
  will be called when a plugin is loaded.
* :meth:`~BipActivity.unregister`: register the interface with IDA.
  This is the oposite of :meth:`~BipActivity.register`, it will be
  called when a plugin is unloaded.
* :meth:`~BipActivity.handler`: the handler function of the activity
  which actually does the action. It is not necessary to implement
  this function if the ``handler`` parameter for the constructor is
  defined. This method will also be called if the object is called.

Those are the only mandatory methods to implement.

Activities have for main goal to be used as decorator when writing
a plugin and as such are *callable* object. *Calling* this object
will triger a call to the :meth:`~BipActivity.handler` method.

Activity and decorator
----------------------

Some decorators are define for being use inside a
:class:`BipPlugin` class for defining interactions with IDA. Those
decorators will dynamically create :class:`BipActivity` objects.

When a :class:`BipPlugin` class is created, its constructor will create a
list of the :class:`BipActivity` associtated with the plugin
(stored in ``_activities``) and when the plugin object is created
it will set itself in the :attr:`BipActivity.plugin` of each
:class:`BipActivity` it contains.

For allowing several :class:`BipActivity` decorators to be used
on the same method the :class:`BipActivityContainer` class is
defined. The decorator will still need to be able to define the
handler function for the new :class:`BipActivity` decorators
after the first one, this is done by storing the function in the
:class:`BipActivityContainer` which is accessible through the
:meth:`~BipActivityContainer.get_original_method` method.

All decorators should return a :class:`BipActivityContainer` which
will contain the :class:`BipActivity` to define. If the container
was already defined it should simply add the new one using the 
:meth:`~BipActivityContainer.add_activity` method.

BipAction API
=============

.. autoclass:: BipAction
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

BipActivity API
===============

.. autoclass:: BipActivity
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

BipActivityContainer API
========================

.. autoclass:: BipActivityContainer
    :members:
    :member-order: bysource
    :special-members:
    :private-members:



