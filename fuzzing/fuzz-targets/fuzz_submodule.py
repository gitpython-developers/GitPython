# ruff: noqa: E402
import atheris
import sys
import os
import traceback
import tempfile
from configparser import ParsingError
from utils import get_max_filename_length
import re

bundle_dir = os.path.dirname(os.path.abspath(__file__))

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):  # pragma: no cover
    bundled_git_binary_path = os.path.join(bundle_dir, "git")
    os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = bundled_git_binary_path

from git import Repo, GitCommandError, InvalidGitRepositoryError


def load_exception_list(file_path):
    """Load and parse the exception list from a file."""
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
        exception_list = set()
        for line in lines:
            match = re.match(r"(.+):(\d+):", line)
            if match:
                file_path = match.group(1).strip()
                line_number = int(match.group(2).strip())
                exception_list.add((file_path, line_number))
        return exception_list
    except FileNotFoundError:
        print("File not found: %s", file_path)
        return set()
    except Exception as e:
        print("Error loading exception list: %s", e)
        return set()


def check_exception_against_list(exception_list, exc_traceback):
    """Check if the exception traceback matches any entry in the exception list."""
    for filename, lineno, _, _ in traceback.extract_tb(exc_traceback):
        if (filename, lineno) in exception_list:
            return True
    return False


if not sys.warnoptions:  # pragma: no cover
    # The warnings filter below can be overridden by passing the -W option
    # to the Python interpreter command line or setting the `PYTHONWARNINGS` environment variable.
    import warnings
    import logging

    # Fuzzing data causes some modules to generate a large number of warnings
    # which are not usually interesting and make the test output hard to read, so we ignore them.
    warnings.simplefilter("ignore")
    logging.getLogger().setLevel(logging.ERROR)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    with tempfile.TemporaryDirectory() as repo_temp_dir:
        repo = Repo.init(path=repo_temp_dir)
        repo.index.commit("Initial commit")

        try:
            with tempfile.TemporaryDirectory() as submodule_temp_dir:
                sub_repo = Repo.init(submodule_temp_dir, bare=fdp.ConsumeBool())
                sub_repo.index.commit(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 512)))

                submodule_name = fdp.ConsumeUnicodeNoSurrogates(
                    fdp.ConsumeIntInRange(1, max(1, get_max_filename_length(repo.working_tree_dir)))
                )
                submodule_path = os.path.join(repo.working_tree_dir, submodule_name)

                submodule = repo.create_submodule(submodule_name, submodule_path, url=sub_repo.git_dir)
                repo.index.commit("Added submodule")

                with submodule.config_writer() as writer:
                    key_length = fdp.ConsumeIntInRange(1, max(1, fdp.remaining_bytes()))
                    value_length = fdp.ConsumeIntInRange(1, max(1, fdp.remaining_bytes()))

                    writer.set_value(
                        fdp.ConsumeUnicodeNoSurrogates(key_length), fdp.ConsumeUnicodeNoSurrogates(value_length)
                    )
                    writer.release()

                submodule.update(init=fdp.ConsumeBool(), dry_run=fdp.ConsumeBool(), force=fdp.ConsumeBool())
                submodule_repo = submodule.module()

                new_file_name = fdp.ConsumeUnicodeNoSurrogates(
                    fdp.ConsumeIntInRange(1, max(1, get_max_filename_length(submodule_repo.working_tree_dir)))
                )
                new_file_path = os.path.join(submodule_repo.working_tree_dir, new_file_name)
                with open(new_file_path, "wb") as new_file:
                    new_file.write(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 512)))
                submodule_repo.index.add([new_file_path])
                submodule_repo.index.commit("Added new file to submodule")

                repo.submodule_update(recursive=fdp.ConsumeBool())
                submodule_repo.head.reset(commit="HEAD~1", working_tree=fdp.ConsumeBool(), head=fdp.ConsumeBool())
                # Use fdp.PickValueInList to ensure at least one of 'module' or 'configuration' is True
                module_option_value, configuration_option_value = fdp.PickValueInList(
                    [(True, False), (False, True), (True, True)]
                )
                submodule.remove(
                    module=module_option_value,
                    configuration=configuration_option_value,
                    dry_run=fdp.ConsumeBool(),
                    force=fdp.ConsumeBool(),
                )
                repo.index.commit(f"Removed submodule {submodule_name}")

        except (
            ParsingError,
            GitCommandError,
            InvalidGitRepositoryError,
            FileNotFoundError,
            FileExistsError,
            IsADirectoryError,
            NotADirectoryError,
            BrokenPipeError,
        ):
            return -1
        except Exception as e:
            exc_traceback = e.__traceback__
            exception_list = load_exception_list(os.path.join(bundle_dir, "explicit-exceptions-list.txt"))
            if check_exception_against_list(exception_list, exc_traceback):
                print("Exception matches an entry in the exception list.")
                return -1
            else:
                print("Exception does not match any entry in the exception list.")
                raise e


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
