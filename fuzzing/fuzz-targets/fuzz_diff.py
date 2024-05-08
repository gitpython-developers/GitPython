import sys
import os
import tempfile
from binascii import Error as BinasciiError

import atheris

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    path_to_bundled_git_binary = os.path.abspath(os.path.join(os.path.dirname(__file__), "git"))
    os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = path_to_bundled_git_binary

with atheris.instrument_imports():
    from git import Repo, Diff


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    with tempfile.TemporaryDirectory() as temp_dir:
        repo = Repo.init(path=temp_dir)
        try:
            Diff(
                repo,
                a_rawpath=fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, fdp.remaining_bytes())),
                b_rawpath=fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, fdp.remaining_bytes())),
                a_blob_id=fdp.ConsumeBytes(20),
                b_blob_id=fdp.ConsumeBytes(20),
                a_mode=fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, fdp.remaining_bytes())),
                b_mode=fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, fdp.remaining_bytes())),
                new_file=fdp.ConsumeBool(),
                deleted_file=fdp.ConsumeBool(),
                copied_file=fdp.ConsumeBool(),
                raw_rename_from=fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, fdp.remaining_bytes())),
                raw_rename_to=fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, fdp.remaining_bytes())),
                diff=fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, fdp.remaining_bytes())),
                change_type=fdp.PickValueInList(["A", "D", "C", "M", "R", "T", "U"]),
                score=fdp.ConsumeIntInRange(0, fdp.remaining_bytes()),
            )
        except BinasciiError:
            return -1
        except AssertionError as e:
            if "Require 20 byte binary sha, got" in str(e):
                return -1
            else:
                raise e


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
