import atheris  # pragma: no cover
from typing import List  # pragma: no cover


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
