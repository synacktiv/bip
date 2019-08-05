import inspect # isfunction


class BipActivity(object):
    """
        Class allowing to make the link between the IDA API and a
        :class:`BipPlugin` .

        All :class:`BipActivity` object link to a :class:`BipPlugin` have a
        property ``plugin`` which give them access to the plugin object.

        All :class:`BipActivity` subclasses should implement the methods:

        * :meth:`~BipActivity.register`: register the interface with IDA. This
          will be called when a plugin is loaded.
        * :meth:`~BipActivity.unregister`: register the interface with IDA.
          This is the oposite of :meth:`~BipActivity.register`, it will be
          called when a plugin is unloaded.
        * :meth:`~BipActivity.handler`: the handler function of the activity
          which actually does the action. It is not necessary to implement
          this function if the ``handler`` parameter for the constructor is
          defined.

        Activities have for main goal to be used as decorator when writing
        a plugin and as such are *callable* object. *Calling* this object
        will triger a call to the :meth:`~BipActivity.handler` method.

        .. todo:: relocate this note in the main doc.

        .. note:: **Activity and decorator**

            Some decorators are define for being use inside a
            :class:`BipPlugin` class for defining interactions with IDA. Those
            decorators will dynamically create :class:`BipActivity` objects.

            When a :class:`BipPlugin` class is create the metaclass
            :class:`MetaBipPlugin` of the :class:`BipPlugin` will create a
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




