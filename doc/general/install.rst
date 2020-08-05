.. _general-install:

Installation steps
##################

Installing Bip
==============

The script ``install.py`` is made for installing Bip, it has been tested only
on Windows and Linux, for making a default install:

.. code-block:: bash

    python install.py

This installer do not insall any plugins by default, but simply the core of
Bip. By default the destination folder is the one use by IDA locally
(``%APPDATA%\Hex-Rays\IDA Pro\`` for Windows and ``$HOME/.idapro`` for Linux
and MacOSX).

It is possible to use an optional `--dest` argument for installing in a
particular folder:

.. code-block:: none

    usage: install.py [-h] [--dest DEST]
    
    optional arguments:
      -h, --help   show this help message and exit
      --dest DEST  Destination folder where to install Bip

Installing BipPlugin
====================

Plugin written for Bip, which inherit from :class:`~bip.gui.BipPlugin`, can
be loaded automatically when opening IDA. For a plugin to be loaded
automatically it has to be present in the ``plugins/bipplugin`` folder. This
folder will be created automatically when `installing Bip`_ in the destination
folder of the installation, by default: ``%APPDATA%\Hex-Rays\IDA Pro\`` for
Windows and ``$HOME/.idapro`` for Linux.




