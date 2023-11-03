# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Hook for MonkeyType (see PR #1188)."""

import unittest

loader = unittest.TestLoader()
start_dir = "."
suite = loader.discover(start_dir)

runner = unittest.TextTestRunner()
runner.run(suite)
