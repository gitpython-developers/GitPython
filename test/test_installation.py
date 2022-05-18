# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import ast
import os
import subprocess
from test.lib import TestBase
from test.lib.helper import with_rw_directory


class TestInstallation(TestBase):
    def setUp_venv(self, rw_dir):
        self.venv = rw_dir
        subprocess.run(["virtualenv", self.venv], stdout=subprocess.PIPE)
        self.python = os.path.join(self.venv, "bin/python3")
        self.pip = os.path.join(self.venv, "bin/pip3")
        self.sources = os.path.join(self.venv, "src")
        self.cwd = os.path.dirname(os.path.dirname(__file__))
        os.symlink(self.cwd, self.sources, target_is_directory=True)

    @with_rw_directory
    def test_installation(self, rw_dir):
        self.setUp_venv(rw_dir)
        result = subprocess.run(
            [self.pip, "install", "-r", "requirements.txt"],
            stdout=subprocess.PIPE,
            cwd=self.sources,
        )
        self.assertEqual(
            0,
            result.returncode,
            msg=result.stderr or result.stdout or "Can't install requirements",
        )
        result = subprocess.run(
            [self.python, "setup.py", "install"],
            stdout=subprocess.PIPE,
            cwd=self.sources,
        )
        self.assertEqual(
            0,
            result.returncode,
            msg=result.stderr or result.stdout or "Can't build - setup.py failed",
        )
        result = subprocess.run([self.python, "-c", "import git"], stdout=subprocess.PIPE, cwd=self.sources)
        self.assertEqual(
            0,
            result.returncode,
            msg=result.stderr or result.stdout or "Selftest failed",
        )
        result = subprocess.run(
            [self.python, "-c", "import sys;import git; print(sys.path)"],
            stdout=subprocess.PIPE,
            cwd=self.sources,
        )
        syspath = result.stdout.decode("utf-8").splitlines()[0]
        syspath = ast.literal_eval(syspath)
        self.assertEqual(
            "",
            syspath[0],
            msg="Failed to follow the conventions for https://docs.python.org/3/library/sys.html#sys.path",
        )
        self.assertTrue(syspath[1].endswith("gitdb"), msg="Failed to add gitdb to sys.path")
