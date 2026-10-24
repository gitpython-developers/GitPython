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

    with tempfile.TemporaryDirectory() as temp_dir, git.Repo.init(path=temp_dir) as repo:
        # Generate a minimal set of files based on fuzz data to minimize I/O operations.
        file_paths = [os.path.join(temp_dir, f"File{i}") for i in range(min(3, fdp.ConsumeIntInRange(1, 3)))]
        for file_path in file_paths:
            with open(file_path, "wb") as f:
                # The chosen upperbound for count of bytes we consume by writing to these
                # files is somewhat arbitrary and may be worth experimenting with if the
                # fuzzer coverage plateaus.
                f.write(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 512)))

        message = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 80))
        if "\0" in message:
            return -1
        repo.index.add(file_paths)
        actor = git.Actor("Fuzzing", "fuzzing@example.invalid")
        commit = repo.index.commit(message, author=actor, committer=actor, skip_hooks=True)
        for blob in commit.tree.blobs:
            blob.data_stream.read()


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
