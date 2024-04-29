import atheris
import io
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

        # Generate a minimal set of files based on fuzz data to minimize I/O operations.
        file_paths = [os.path.join(temp_dir, f"File{i}") for i in range(min(3, fdp.ConsumeIntInRange(1, 3)))]
        for file_path in file_paths:
            with open(file_path, "wb") as f:
                # The chosen upperbound for count of bytes we consume by writing to these
                # files is somewhat arbitrary and may be worth experimenting with if the
                # fuzzer coverage plateaus.
                f.write(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 512)))

        repo.index.add(file_paths)
        repo.index.commit(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 80)))

        fuzz_tree = git.Tree(repo, git.Tree.NULL_BIN_SHA, 0, "")

        try:
            fuzz_tree._deserialize(io.BytesIO(data))
        except IndexError:
            return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
