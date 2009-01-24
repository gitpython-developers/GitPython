# actor.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import re

class Actor(object):
    def __init__(self, name, email):
        self.name = name
        self.email = email

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<git.Actor "%s <%s>">' % (self.name, self.email)

    @classmethod
    def from_string(cls, string):
        """
        Create an Actor from a string.

        ``str``
            is the string, which is expected to be in regular git format

        Format
            John Doe <jdoe@example.com>

        Returns
            Actor
        """
        if re.search(r'<.+>', string):
            m = re.search(r'(.*) <(.+?)>', string)
            name, email = m.groups()
            return Actor(name, email)
        else:
            return Actor(string, None)
