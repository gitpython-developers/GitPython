import atheris
import sys
import os
import tempfile
from configparser import ParsingError
from utils import is_expected_exception_message

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    path_to_bundled_git_binary = os.path.abspath(os.path.join(os.path.dirname(__file__), "git"))
    os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = path_to_bundled_git_binary

with atheris.instrument_imports():
    from git import Repo, GitCommandError, InvalidGitRepositoryError


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    with tempfile.TemporaryDirectory() as repo_temp_dir:
        repo = Repo.init(path=repo_temp_dir)
        repo.index.commit("Initial commit")

        try:
            with tempfile.TemporaryDirectory() as submodule_temp_dir:
                sub_repo = Repo.init(submodule_temp_dir, bare=fdp.ConsumeBool())
                sub_repo.index.commit(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 512)))

                submodule_name = f"submodule_{fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 512))}"
                submodule_path = os.path.join(repo.working_tree_dir, submodule_name)
                submodule_url = sub_repo.git_dir

                submodule = repo.create_submodule(submodule_name, submodule_path, url=submodule_url)
                repo.index.commit(f"Added submodule {submodule_name}")

                with submodule.config_writer() as writer:
                    key_length = fdp.ConsumeIntInRange(1, max(1, fdp.remaining_bytes()))
                    value_length = fdp.ConsumeIntInRange(1, max(1, fdp.remaining_bytes()))

                    writer.set_value(
                        fdp.ConsumeUnicodeNoSurrogates(key_length), fdp.ConsumeUnicodeNoSurrogates(value_length)
                    )
                    writer.release()

                submodule.update(init=fdp.ConsumeBool(), dry_run=fdp.ConsumeBool(), force=fdp.ConsumeBool())

                submodule_repo = submodule.module()
                new_file_path = os.path.join(
                    submodule_repo.working_tree_dir,
                    f"new_file_{fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 512))}",
                )
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
            BrokenPipeError,
        ):
            return -1
        except (ValueError, OSError) as e:
            expected_messages = [
                "SHA is empty",
                "Reference at",
                "embedded null byte",
                "This submodule instance does not exist anymore",
                "cmd stdin was empty",
                "File name too long",
            ]
            if is_expected_exception_message(e, expected_messages):
                return -1
            else:
                raise e


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
