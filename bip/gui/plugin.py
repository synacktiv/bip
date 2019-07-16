import sys

from actions import BipAction

# I need 2 different objects:
#   * one BipPlugin which allow to create and register plugin_t object
#   * one BipAction which allow to register action inside a BipPlugin object

# TODO:
#   * register actions
#   * make system for dependencies (using decorator ?)


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
        # Add action in the class list # TODO: doc this
        cls._actions_dict = {}
        for name, value in dct.items():
            if isinstance(value, BipAction):
                cls._actions_dict[name] = value
        return super(MetaBipPlugin, cls).__init__(name, bases, dct) 


#class BipActionMethod(object):
#    """
#        Object allowing to define an action inside a plugin.
#
#        .. todo:: doc
#    """


class BipPlugin(object):
    """
        Class for representing a plugin in IDA.

        .. warning:: If you use a metaclass when defining a plugin, make sure
            it inherit from :class:`MetaBipPlugin` which is necessary for
            working with the plugin manager. 

        .. todo:: doc
        .. todo:: everything
    """
    __metaclass__ = MetaBipPlugin

    def __init__(self):
        pass

    @classmethod
    def to_load(cls):
        """
            Class method allowing to test if this plugin should be loaded.
            At that point the plugin object at not been loaded yet, this allow
            to test if the plugin is made for working in this environment.

            By default always return ``True``.

            :return: A boolean value indicating if the plugin should be loaded
                (``True``) or not (``False``).
        """
        return True

    def _register_actions(self): # TODO
        """
            .. todo:: doc this
        """
        for name, action in self._actions_dict.items():
            action.register()

    def load(self): # TODO
        """
            .. todo:: doc this
            .. todo:: finish implem
        """
        self._register_actions()


def _descriptor_get_action(self, instance, owner):
    """
        Descriptor function for defining the __get__ object for the
        :class:`BipAction` used inside the :class:`BipPlugin`.

        This is used by the decorator TODO. And should be for internal use
        only.

        See https://docs.python.org/2/howto/descriptor.html and
        https://docs.python.org/2/reference/datamodel.html#implementing-descriptors

        .. todo:: better doc
        .. todo:: fix TODO in this doc
    """
    if instance is not None:
        return self.f.__get__(instance, owner)
    else:
        return self


def shortcut(shortcut_str):
    """
        Decorator for method inside a :class:`BipPlugin` for indicating a
        function should be a shortcut.

        .. todo:: support nested decorator (take a BipAction in parameter)
        .. todo:: more doc on internals
    """
    def dec(func): # function decorator
        # TODO: should check if func is not already a BipAction for supporting
        #   nesting decorator
        # Dynamically create the class for this shortcut
        cls = type(func.__name__ + "ShortCutAction", (BipAction,),
                {
                    "__get__": _descriptor_get_action, # __get__ descriptor
                    "handler": func # TODO: fix this I should pass the instance of the plugin, I should be able to do that through the descriptor get action
                    })
        return cls(shortcut=shortcut_str)
    return dec



