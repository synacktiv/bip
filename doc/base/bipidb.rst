IDB representation
##################

.. module:: bip.base

Some usefull information are link to the IDB loaded by IDA, those information
are accessible through static methods of the :class:`BipIdb` class. Those
information include things such as the base address of the image, the minium
and maximum address mapped in the IDB and so on. A few `helper functions`_ are
also defined directly at the top level of ``bipidb.py`` for making it more
easy to script.

BipIdb API
==========

.. autoclass:: BipIdb
    :members:
    :member-order: bysource
    :special-members:
    :private-members:

Helper functions
================

.. autofunction:: min_ea

.. autofunction:: max_ea

.. autofunction:: Here



