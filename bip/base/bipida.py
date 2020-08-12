import ida_kernwin

class BipIda(object):
    """
        Class for regrouping interfaces with IDA in itself. This can include
        configurations and thing specific to the IDA API.

        Currently this contain only static methods.
    """

    @staticmethod
    def exec_sync(func, *args, **kwargs):
        """
            Wrap around the execute_sync API to perform a call on the function
            ``func`` in the main thread. If a function is not marked as
            THREAD_SAFE in the headers, then it can only be called from the
            main thread of IDA.

            .. todo:: unit test
    
            :param func: The function to call.
            :type func: Python Callable
            :param args: Arguments to ``func``
            :param kwargs: Keyworded arguments to ``func``
            :param MFF_FLAG: Flag describing the operation on the database.
                Default ``MFF_READ``. Can be ``MFF_FAST``, ``MFF_READ``,
                ``MFF_WRITE`` or ``MFF_NOWAIT`` (from ida_kernwin).
            :type MFF_FLAG: int
            :return: The return of ``func``
        """
    
        MFF_FLAG = kwargs.get("MFF_FLAG", ida_kernwin.MFF_READ)
    
        ret = {"ret": None}
        def handle():
            ret["ret"] = func(*args, **kwargs)
            return 1
    
        ida_kernwin.execute_sync(handle, MFF_FLAG)
        return ret["ret"]

