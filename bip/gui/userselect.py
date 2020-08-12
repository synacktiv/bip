
from re import match
import ida_kernwin

class BipUserSelect(object):
    """
        Class for helping with interfacing with user selection.

        This class contains only static method for now.
    """

    @staticmethod
    def get_curr_highlighted_str():
        """
            Return the currently highlighted identifier or None if nothing is
            highlighted. This get it from the current view.

            :return: The string of the highlighted object or None if nothing
                is highlighted.
        """
        t = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
        if t is None:
            return t
        return t[0]

    @staticmethod
    def get_curr_highlighted_int():
        """
            Allow to get the value of the currently highlighted identifier (in
            the current view) if it is an integer. If it not possible to make
            it match a type  of integer (hex, oct or dec) or if nothing is
            highlighted the function return ``None``.

            :return: the value currently highlighted.
        """
        s = BipUserSelect.get_curr_highlighted_str()
        if s is None:
            return s
        h = match('(0x[0-9a-fA-F]+).*', s)
        
        if h:
            return int(h.group(1), 16)

        o = match('(0[0-7]+).*', s)
        if o:
            return int(o.group(1), 8)

        n = match('([0-9]+).*', s)
        if n:
            return int(n.group(1))
        
        return None


