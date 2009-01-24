# helper.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os

GIT_REPO = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

def fixture_path(name):
    test_dir = os.path.dirname(os.path.dirname(__file__))
    return os.path.join(test_dir, "fixtures", name)

def fixture(name):
    return open(fixture_path(name)).read()

def absolute_project_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
