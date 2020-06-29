"""
    Methods for creating top level menu and toolbars. As we currently do not
    have access to objects reflected by those elements this is a set of
    wrapper on top of IDA API.
"""
import ida_kernwin

def add_top_menu(name, uid=None, before=None):
    """
        Add a top level menu entry in IDA (a directory in the menu at the
        top). This should be used only for top level menu and will not work
        for subdirectory which can br created directly when register a
        :class:`BipAction` (or using the :func:`menu` decorator).

        This is different from the :func:`menu` decorator. This is a
        wrapper on the ``create_menu`` from IDAPython. Those top level menu
        are in practice different of the submenu, those submenu can
        be directly set using a :class:`BipAction` while those top menu can't
        be.

        :param str name: The name of the top level menu
            (ex.: ``NewTopLevelMenu``).
        :param str uid: Unique id for this menu, this will not be shown
            in the gui but can be used for deleting it
            after (:func:`del_top_menu`) or for the ``before`` argument (see
            bellow). If it not unique this function will fail. By default
            (``None``) the value of the ``name`` will be used as there is
            few case where having two top level menu of the same name is
            usefull.
        :param str before: The uid of a menu before which to insert this new
            menu. If the ``uid`` does not exist it this function will still
            succeed but insert the entry at the end.
        :return: ``True`` on success, ``False`` otherwise.
    """
    if uid is None:
        uid = name
    return ida_kernwin.create_menu(uid, name, before)

def del_top_menu(uid):
    """
        Delete a top level menu from IDA.

        :param str uid: The unique ID of the menu. For more information see
            :func:`add_top_menu` .
    """
    ida_kernwin.delete_menu(uid)


