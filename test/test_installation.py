# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import ast
import functools
import os
import subprocess

from test.lib import TestBase, VirtualEnvironment, with_rw_directory


class TestInstallation(TestBase):
    @with_rw_directory
    def test_installation(self, rw_dir):
        venv, run = self._set_up_venv(rw_dir)

        result = run([venv.pip, "install", "."])
        self._check_result(result, "Can't install project")

        result = run([venv.python, "-c", "import git"])
        self._check_result(result, "Self-test failed")

        result = run([venv.python, "-c", "import gitdb; import smmap"])
        self._check_result(result, "Dependencies not installed")

        # Even IF gitdb or any other dependency is supplied during development by
        # inserting its location into PYTHONPATH or otherwise patched into sys.path,
        # make sure it is not wrongly inserted as the *first* entry.
        result = run([venv.python, "-c", "import sys; import git; print(sys.path)"])
        syspath = result.stdout.splitlines()[0]
        syspath = ast.literal_eval(syspath)
        self.assertEqual(
            "",
            syspath[0],
            msg="Failed to follow the conventions for https://docs.python.org/3/library/sys.html#sys.path",
        )

    @staticmethod
    def _set_up_venv(rw_dir):
        # Initialize the virtual environment.
        venv = VirtualEnvironment(rw_dir, with_pip=True)

        # Make its src directory a symlink to our own top-level source tree.
        os.symlink(
            os.path.dirname(os.path.dirname(__file__)),
            venv.sources,
            target_is_directory=True,
        )

        # Create a convenience function to run commands in it.
        run = functools.partial(
            subprocess.run,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=venv.sources,
            env={**os.environ, "PYTHONWARNINGS": "error"},
        )

        return venv, run

    def _check_result(self, result, failure_summary):
        self.assertEqual(
            0,
            result.returncode,
            msg=self._prepare_failure_message(result, failure_summary),
        )

    @staticmethod
    def _prepare_failure_message(result, failure_summary):
        stdout = result.stdout.rstrip()
        stderr = result.stderr.rstrip()
        return f"{failure_summary}\n\nstdout:\n{stdout}\n\nstderr:\n{stderr}"
