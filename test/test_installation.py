# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import ast
import functools
import os
import subprocess
import sys

from git import __version__, _backend
from test.lib import TestCase, requires_symlinks
from test.lib.fixtures import ROOT, writable_fixture


class TestInstallation(TestCase):
    @requires_symlinks
    def test_installation(self):
        # Virtualenv executables and its source symlink need their final location.
        with writable_fixture("installation.sh", sys.executable, sys.platform, ROOT, execute=True) as fixture:
            self._test_installation(fixture.path().resolve() / "env")

    def _test_installation(self, environment):
        executables = environment / ("Scripts" if sys.platform == "win32" else "bin")
        python = executables / ("python.exe" if sys.platform == "win32" else "python")
        pip = executables / ("pip.exe" if sys.platform == "win32" else "pip")
        run = functools.partial(
            subprocess.run,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=environment / "src",
            env={**os.environ, "PYTHONWARNINGS": "error"},
        )

        gitpython = ".[gix]" if _backend.name == "gix" else "."
        for project in ("./smmap", "./gitdb", gitpython):
            result = run([pip, "install", project])
            self._check_result(result, f"Can't install {project}")

        result = run([python, "-c", "import git"])
        self._check_result(result, "Self-test failed")

        result = run([python, "-c", "from git import _backend; print(_backend.name)"])
        self._check_result(result, "Backend selection failed")
        self.assertEqual(result.stdout.strip(), _backend.name)

        result = run([python, "-c", "import git; print(git.__version__)"])
        self._check_result(result, "Installed version import failed")
        self.assertEqual(result.stdout.strip(), __version__)

        result = run([python, "-c", "import gitdb; import smmap"])
        self._check_result(result, "Dependencies not installed")

        # Even IF gitdb or any other dependency is supplied during development by
        # inserting its location into PYTHONPATH or otherwise patched into sys.path,
        # make sure it is not wrongly inserted as the *first* entry.
        result = run([python, "-c", "import sys; import git; print(sys.path)"])
        syspath = result.stdout.splitlines()[0]
        syspath = ast.literal_eval(syspath)
        self.assertEqual(
            "",
            syspath[0],
            msg="Failed to follow the conventions for https://docs.python.org/3/library/sys.html#sys.path",
        )

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
