# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import sys

import git


def test_git_util_attribute_is_actual_util_module():
    assert git.util is sys.modules["git.util"]


def test_git_index_util_attribute_is_git_index_util():
    """Nothing unusual is happening with git.index.util itself."""
    assert git.index.util is sys.modules["git.index.util"]


def test_separate_git_util_module_exists():
    """The real git.util and git.index.util modules really are separate.

    The real git.util module can be accessed to import a name ``...` by writing
    ``from git.util import ...``, and the module object can be accessed in sys.modules.
    """
    assert sys.modules["git.util"] is not sys.modules["git.index.util"]
