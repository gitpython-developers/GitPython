import atheris  # pragma: no cover
import os  # pragma: no cover
import re  # pragma: no cover
import traceback  # pragma: no cover
import sys  # pragma: no cover
from typing import Set, Tuple, List  # pragma: no cover


@atheris.instrument_func
def is_expected_exception_message(exception: Exception, error_message_list: List[str]) -> bool:  # pragma: no cover
    """
    Checks if the message of a given exception matches any of the expected error messages, case-insensitively.

    Args:
         exception (Exception): The exception object raised during execution.
         error_message_list (List[str]): A list of error message substrings to check against the exception's message.

    Returns:
      bool: True if the exception's message contains any of the substrings from the error_message_list,
      case-insensitively, otherwise False.
    """
    exception_message = str(exception).lower()
    for error in error_message_list:
        if error.lower() in exception_message:
            return True
    return False


@atheris.instrument_func
def get_max_filename_length(path: str) -> int:  # pragma: no cover
    """
    Get the maximum filename length for the filesystem containing the given path.

    Args:
        path (str): The path to check the filesystem for.

    Returns:
        int: The maximum filename length.
    """
    return os.pathconf(path, "PC_NAME_MAX")


@atheris.instrument_func
def read_lines_from_file(file_path: str) -> list:
    """Read lines from a file and return them as a list."""
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        return []


@atheris.instrument_func
def load_exception_list(file_path: str = "explicit-exceptions-list.txt") -> Set[Tuple[str, str]]:
    """Load and parse the exception list from a default or specified file."""
    try:
        bundle_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(bundle_dir, file_path)
        lines = read_lines_from_file(full_path)
        exception_list: Set[Tuple[str, str]] = set()
        for line in lines:
            match = re.match(r"(.+):(\d+):", line)
            if match:
                file_path: str = match.group(1).strip()
                line_number: str = str(match.group(2).strip())
                exception_list.add((file_path, line_number))
        return exception_list
    except Exception as e:
        print(f"Error loading exception list: {e}")
        return set()


@atheris.instrument_func
def match_exception_with_traceback(exception_list: Set[Tuple[str, str]], exc_traceback) -> bool:
    """Match exception traceback with the entries in the exception list."""
    for filename, lineno, _, _ in traceback.extract_tb(exc_traceback):
        for file_pattern, line_pattern in exception_list:
            # Ensure filename and line_number are strings for regex matching
            if re.fullmatch(file_pattern, filename) and re.fullmatch(line_pattern, str(lineno)):
                return True
    return False


@atheris.instrument_func
def check_exception_against_list(exc_traceback, exception_file: str = "explicit-exceptions-list.txt") -> bool:
    """Check if the exception traceback matches any entry in the exception list."""
    exception_list = load_exception_list(exception_file)
    return match_exception_with_traceback(exception_list, exc_traceback)


@atheris.instrument_func
def handle_exception(e: Exception) -> int:
    """Encapsulate exception handling logic for reusability."""
    exc_traceback = e.__traceback__
    if check_exception_against_list(exc_traceback):
        return -1
    else:
        raise e


@atheris.instrument_func
def setup_git_environment() -> None:
    """Set up the environment variables for Git."""
    bundle_dir = os.path.dirname(os.path.abspath(__file__))
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):  # pragma: no cover
        bundled_git_binary_path = os.path.join(bundle_dir, "git")
        os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = bundled_git_binary_path

    if not sys.warnoptions:  # pragma: no cover
        # The warnings filter below can be overridden by passing the -W option
        # to the Python interpreter command line or setting the `PYTHONWARNINGS` environment variable.
        import warnings
        import logging

        # Fuzzing data causes some modules to generate a large number of warnings
        # which are not usually interesting and make the test output hard to read, so we ignore them.
        warnings.simplefilter("ignore")
        logging.getLogger().setLevel(logging.ERROR)
