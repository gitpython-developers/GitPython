import atheris
import sys
import os
import tempfile

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    path_to_bundled_git_binary = os.path.abspath(os.path.join(os.path.dirname(__file__), "git"))
    os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = path_to_bundled_git_binary

with atheris.instrument_imports():
    import git


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    with tempfile.TemporaryDirectory() as temp_dir:
        repo = git.Repo.init(path=temp_dir)
        binsha = fdp.ConsumeBytes(20)
        mode = fdp.ConsumeInt(fdp.ConsumeIntInRange(0, fdp.remaining_bytes()))
        path = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())

        try:
            blob = git.Blob(repo, binsha, mode, path)
        except AssertionError as e:
            if "Require 20 byte binary sha, got" in str(e):
                return -1
            else:
                raise e

        _ = blob.mime_type


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
