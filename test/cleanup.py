# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Best-effort disposal of isolated test directories, including on Python 3.8.

Use these helpers only when discarding a directory owned by a test. Deleting or
moving files to exercise Git behavior, or to prepare a reusable fixture, must
still report errors.

Keep this module independent of GitPython and pytest so the local test runner
can use it before configuring the test environment.
"""

import logging
import os
import shutil
import stat
import sys
import tempfile
import weakref

_logger = logging.getLogger(__name__)


def cleanup_directory(path):
    """Try to remove an owned test directory; return False and log on filesystem errors."""
    errors = []

    def onerror(function, filename, exception):
        if isinstance(exception, FileNotFoundError):
            return
        if sys.platform == "win32" and function in (os.unlink, os.rmdir) and isinstance(exception, PermissionError):
            try:
                # Git files and test directories may be read-only. Never chmod a
                # symlink or junction target, which may be outside the owned tree.
                if not os.lstat(filename).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    os.chmod(filename, stat.S_IWUSR)
                    function(filename)
                    return
            except FileNotFoundError:
                return
            except OSError as retry_error:
                exception = retry_error
        errors.append(exception)

    try:
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=onerror)
        else:
            shutil.rmtree(path, onerror=lambda function, filename, excinfo: onerror(function, filename, excinfo[1]))
    except FileNotFoundError:
        pass
    except OSError as error:
        errors.append(error)

    if errors:
        _logger.warning("Could not fully remove temporary test directory %r: %s", os.fspath(path), errors[0])
    return not errors


class TemporaryDirectory:
    """A test-owned temporary directory whose cleanup cannot fail on file locks.

    Supports context management, ``name``, and explicit ``cleanup()``. A finalizer
    also attempts cleanup if a test drops the object without closing it. Explicit
    cleanup detaches that finalizer, but may be called again to retry later.
    """

    def __init__(self, suffix=None, prefix=None, dir=None):
        self.name = tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dir)
        self._finalizer = weakref.finalize(self, cleanup_directory, self.name)

    def __enter__(self):
        return self.name

    def __exit__(self, *args):
        self.cleanup()

    def cleanup(self):
        self._finalizer.detach()
        cleanup_directory(self.name)
