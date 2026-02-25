import pytest

from git.cmd import Git


class _DummyProc:
    """Minimal stand-in for subprocess.Popen used to exercise AutoInterrupt.

    We deliberately raise AttributeError from terminate() to simulate interpreter
    shutdown on Windows where subprocess internals (e.g. subprocess._winapi) may
    already be torn down.
    """

    stdin = None
    stdout = None
    stderr = None

    def poll(self):
        return None

    def terminate(self):
        raise AttributeError("TerminateProcess")

    def wait(self):  # pragma: no cover - should not be reached in this test
        raise AssertionError("wait() should not be called if terminate() fails")


def test_autointerrupt_terminate_ignores_attributeerror():
    ai = Git.AutoInterrupt(_DummyProc(), args=["git", "rev-list"])

    # Should not raise, even if terminate() triggers AttributeError.
    ai._terminate()

    # Ensure the reference is cleared to avoid repeated attempts.
    assert ai.proc is None
