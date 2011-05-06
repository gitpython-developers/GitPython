# odict.py
# An Ordered Dictionary object
# Copyright (C) 2005 Nicola Larosa, Michael Foord
# E-mail: nico AT tekNico DOT net, fuzzyman AT voidspace DOT org DOT uk

# This software is licensed under the terms of the BSD license.
# http://www.voidspace.org.uk/python/license.shtml
# Basically you're free to copy, modify, distribute and relicense it,
# So long as you keep a copy of the license with it.

# Documentation at http://www.voidspace.org.uk/python/odict.html
# For information about bugfixes, updates and support, please join the
# Pythonutils mailing list:
# http://groups.google.com/group/pythonutils/
# Comments, suggestions and bug reports welcome.

"""A dict that keeps keys in insertion order"""
from __future__ import generators
__author__ = ('Nicola Larosa <nico-NoSp@m-tekNico.net>,'
    'Michael Foord <fuzzyman AT voidspace DOT org DOT uk>')
__docformat__ = "restructuredtext en"
__revision__ = '$Id: odict.py 129 2005-09-12 18:15:28Z teknico $'
__version__ = '0.2.2'

# imported for backward compatibility only
from git.odict import OrderedDict, SequenceOrderedDict
__all__ = ['OrderedDict', 'SequenceOrderedDict']
