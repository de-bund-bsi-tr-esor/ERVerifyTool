How to generate the documentation of ErVerifyTool
=================================================

In this directory there are sources and scripts to generate the documentation
of ErVerifyTool. The documentation can be assembled without building the
application.


Preconditions
-------------

Make sure the following software is installed
* Python 2.7
* pip (recommended)
* Sphinx 1.6.6 (may be installed using pip)
* javasphinx 0.9.15 (may be installed using pip)
* LaTeX (for instance TeXLive on Linux)

WARNING: Python may display misleading error messages if one of these
applications is missing.


Creating the documentation
--------------------------

Call the script ``doc.py`` either by calling ``python doc.py`` or make it
executable (only Linux) with the following parameters:

* no parameters for creating the documentation
* ``clean`` for removing artifacts
* ``-h`` for displaying further options

You will find the generated documentation in the _build directory.
