# config.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Module containing module parser implementation able to properly read and write
configuration files"""

from gitdb.config import GitConfigParser, SectionConstraint
__all__ = ('GitConfigParser', 'SectionConstraint')
