# -*- coding: utf-8 -*-
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from pathlib import Path
import re

import git

from .lib import (
    TestBase,
    with_rw_directory,
)


class TestClone(TestBase):
    @with_rw_directory
    def test_checkout_in_non_empty_dir(self, rw_dir):
        non_empty_dir = Path(rw_dir)
        garbage_file = non_empty_dir / "not-empty"
        garbage_file.write_text("Garbage!")

        # Verify that cloning into the non-empty dir fails while complaining about
        # the target directory not being empty/non-existent
        try:
            self.rorepo.clone(non_empty_dir)
        except git.GitCommandError as exc:
            self.assertTrue(exc.stderr, "GitCommandError's 'stderr' is unexpectedly empty")
            expr = re.compile(r"(?is).*\bfatal:\s+destination\s+path\b.*\bexists\b.*\bnot\b.*\bempty\s+directory\b")
            self.assertTrue(
                expr.search(exc.stderr),
                '"%s" does not match "%s"' % (expr.pattern, exc.stderr),
            )
        else:
            self.fail("GitCommandError not raised")
