.. _general-contrib:

Contributions
#############

Contributions to Bip are welcome, it can be Issues, Feature Request or Pull
Request (PR), all of those can be made on github. Those can concern the code
but also the documentation, which has the goal to be clear and complete.
The integrality of Bip is currently maintained by a unique person, so please
take the time to read those and thank you in advance for your patience.

As general rules for Issues and Feature Request, provided a clear
description, an example (with the line of the API and if needed the content
of IDA) and if possible a way to reproduce or test it. Do not hesitate to
propose an example of what you would like to have as an API in Bip. If you
have it, an example of how to do it with the IDAPython API would be amazing.

Pull Request
============

For Pull Request, please provide a clear description of what your code does
and, especially if it is a big PR, how you implemented it. The only release of
IDA for which Bip is maintained is the last one, so be sure it works with it.
No pull request will be merged in ``master`` if:

* the code is not documented,
* the code is not integrated in the documentation,
* the code is not compatible for python2 and python3 (as long as both are
  supported in Bip),
* there are no tests for the new functions/methods/classes/...

You can make a PR without those, however it will take some time for it to be
merged because those will have to be written.

Regarding the code in itself, no hardline coding convention is enforced (for
now) but please follow as much as possible those rules:

* use 4 spaces instead of tabulation,
* write python2 and python3 compatible code,
* follow naming convention of Python (``UpperCaseCamel`` for classes
  and ``lower_with_underscore`` for methods),
* start the name of the class with ``Bip`` or ``Hx`` (for hexrays) or a clear
  prefix which identifies it (the goal is to avoid collisions with IDAPython
  and other python packages, as well as to make auto-completion easier),
* write **readable** code (avoid nested list comprehension and so on),
* simpler code is often better,
* stay around 80 chars (a little more is fine).

Finally, if the PR introduces a breaking change (change in names of a
method or a class, change in arguments, change in behavior, ...), it has to
log in the changelog including in this documentation. Further rules on
breaking changes and Bip versions may be introduced.

Change of version
=================

This is a checklist of things to do for a change of version in Bip:

* change version in sphinx doc (``docs/conf.py``),
* change Bip Python version (``bip/__init__.py``),
* change last stable version in ``README.rst``,
* check changelog is done and has the right version numbers,
* check all tests pass in py2 and py3,
* check the doc build correctly, build it and push it (for github.io page).


