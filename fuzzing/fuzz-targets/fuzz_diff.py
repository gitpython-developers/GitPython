import sys
import os
import io
import tempfile
from binascii import Error as BinasciiError

import atheris

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    path_to_bundled_git_binary = os.path.abspath(os.path.join(os.path.dirname(__file__), "git"))
    os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = path_to_bundled_git_binary

with atheris.instrument_imports():
    from git import Repo, Diff


class BytesProcessAdapter:
    """Allows bytes to be used as process objects returned by subprocess.Popen."""

    @atheris.instrument_func
    def __init__(self, input_string):
        self.stdout = io.BytesIO(input_string)
        self.stderr = io.BytesIO()

    @atheris.instrument_func
    def wait(self):
        return 0

    poll = wait


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    with tempfile.TemporaryDirectory() as temp_dir:
        repo = Repo.init(path=temp_dir)
        try:
            diff = Diff(
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

        _ = diff.__str__()
        _ = diff.a_path
        _ = diff.b_path
        _ = diff.rename_from
        _ = diff.rename_to
        _ = diff.renamed_file

        diff_index = diff._index_from_patch_format(
            repo, proc=BytesProcessAdapter(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, fdp.remaining_bytes())))
        )

        diff._handle_diff_line(
            lines_bytes=fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, fdp.remaining_bytes())), repo=repo, index=diff_index
        )


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
