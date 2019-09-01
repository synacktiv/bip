import inspect # isfunction


class BipActivity(object):
    """
        Class allowing to make the link between the IDA API and a
        :class:`BipPlugin` . In particular this will allow to define
        :class:`BipAction` (including :func:`shortcut` and :func:`menu` entry)
        or callbacks.

        .. todo:: put link to callbacks when realized

        All :class:`BipActivity` object link to a :class:`BipPlugin` have a
        property ``plugin`` which give them access to the plugin object.

        Activities have for main goal to be used as decorator when writing
        a plugin and as such are *callable* object. *Calling* this object
        will triger a call to the :meth:`~BipActivity.handler` method.
    """
    #: :class:`BipPlugin` object if this activity is link to a plugin. This
    #:  will be set automatically by the constructor of the
    #:  :class:`BipPlugin`. If this :class:`BipActivity` is not link to a
    #:  :class:`BipPlugin` this attribute should be ``None``.
    plugin = None

    def __call__(self, *args, **kwargs):
        return self.handler(*args, **kwargs)

    def register(self):
        """
            Abstract method which register the activity inside the IDA
            interface. By default will raise a ``RuntimeError``.

            This should be implemented by child classes for interfacing with
            IDA.
        """
        raise RuntimeError("BipActivity.register is an abstract method and should be defined by subclasses")

    def unregister(self):
        """
            Abstract method which register the activity inside the IDA
            interface. By default will raise a ``RuntimeError``.

            This should be implemented by child classes for interfacing with
            IDA.
        """
        raise RuntimeError("BipActivity.unregister is an abstract method and should be defined by subclasses")

    def handler(self, *args, **kwargs):
        """
            Abstract method which represent the action to realise when the
            activity is triger by IDA. In most case each
            :class:`BipActivity` object will want a different handler. 
            By default this will raise a ``RuntimeError``.

            This should be implemented by child classes or object for
            interfacing with IDA.
        """
        raise RuntimeError("BipActivity.handler is an abstract method and should be defined by subclasses")

class BipActivityContainer(BipActivity):
    """
        This class is a BipActivity which contains several bip activities with
        the same handler.
        
        In particular this class allow to use several decorators on the same
        :class:`BipPlugin` method for defining several :class:`BipActivity`.
        For this to work with the decorators, the original function should
        be stored.
    """

    def __init__(self, original_func):
        """
            Constructor for a :class:`BipActivityContainer` object.
            
            :param handler: Handler function for this action. If it is None
                the :meth:`~BipActivityContainer.handler` method will raise
                a ``RuntimeError`` if not redefined.
        """
        #: List of :class:`BipActivity` contained in this container.
        self._activities = []

        #: Property which contain the original function
        self._org_func = original_func

        #: :class:`BipPlugin` object internal, this is needed for redefining
        #:   the ``plugin`` attribute in the internal activites.
        self._plugin = None

    @property
    def plugin(self):
        return self._plugin

    @plugin.setter
    def plugin(self, plg):
        # register the plugin for the property getter
        self._plugin = plg
        # pass the plugin to contained activities
        for act in self._activities:
            act.plugin = plg

    def get_original_method(self):
        """
            Method allowing to get the original method used when creating
            this :class:`BipActivityContainer`.

            :return: A function corresponding to the original function as
                originally define.
        """
        return self._org_func

    def add_activity(self, activity):
        """
            Add an activity in this container. The activity should be a
            correctly setup activity including its handler.

            :param activity: An object which inherit from
                :class:`BipActivity`.
        """
        self._activities.append(activity)

    def __len__(self):
        """
            Return the number of :class:`BipActivity` register in this
            container.
        """
        return len(self._activities)

    def handler(self, *args, **kwargs):
        """
            Call the original function with the :class:`BipPlugin` in first
            argument. This is implemented for allowing the call from a plugin
            object.
        """
        return self._org_func(self.plugin, *args, **kwargs)

    def register(self):
        """
            Register all contained activities in IDA. Internally this
            will just call the :meth:`~BipActivity.register` method for each
            contained :class:`BipActivity` object.
        """
        for act in self._activities:
            act.register()

    def unregister(self):
        """
            Unregister all contained activities in IDA. Internally this
            will just call the :meth:`~BipActivity.unregister` method for each
            contained :class:`BipActivity` object.
        """
        for act in self._activities:
            act.unregister()

    @classmethod
    def get_container(cls, func):
        """
            Classmethod allowing to get an object of this class from a
            function or a container.

            This class method is made for being used by decorator for them not
            having the problem to handle type of argument and if it is the
            first decorator or not.
        """
        if inspect.isfunction(func):
            # we have a function we need to create the BipActivityContainer
            return cls(func)
        elif isinstance(func, cls):
            return func
        else:
            # We don't have a BipActivityContainer nor a function, raise a runtimeerror
            raise RuntimeError("get_container expect a function or a BipActivityContainer as argument")




