# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
# Note: This file has been modified by contributors to GitPython.
# The original state of this file may be referenced here:
# https://github.com/google/oss-fuzz/commit/f26f254558fc48f3c9bc130b10507386b94522da
###############################################################################
import atheris
import sys
import io
import os
from configparser import MissingSectionHeaderError, ParsingError

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    path_to_bundled_git_binary = os.path.abspath(os.path.join(os.path.dirname(__file__), "git"))
    os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = path_to_bundled_git_binary

with atheris.instrument_imports():
    import git


def TestOneInput(data):
    sio = io.BytesIO(data)
    sio.name = "/tmp/fuzzconfig.config"
    git_config = git.GitConfigParser(sio)
    try:
        git_config.read()
    except (MissingSectionHeaderError, ParsingError, UnicodeDecodeError):
        return -1  # Reject inputs raising expected exceptions
    except ValueError as e:
        if "embedded null byte" in str(e):
            # The `os.path.expanduser` function, which does not accept strings
            # containing null bytes might raise this.
            return -1
        else:
            raise e  # Raise unanticipated exceptions as they might be bugs


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
