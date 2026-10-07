from subprocess import PIPE
import sys
import threading

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


def test_autointerrupt_terminate_closes_buffered_stdin():
    ai = Git().hash_object("--stdin", as_process=True, istream=PIPE)
    proc = ai.proc
    proc.stdin.write(b"buffered input")
    try:
        ai._terminate()
        assert proc.stdin.closed
        assert proc.stdout.closed
        assert proc.stderr.closed
    finally:
        proc.stdout.close()
        proc.stderr.close()


@pytest.mark.skipif(sys.platform == "win32", reason="requires POSIX SIGTERM handling")
def test_autointerrupt_terminate_closes_pipes_before_waiting():
    script = (
        "import signal, sys; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "print('ready', flush=True); sys.stdin.read(); sys.stdout.buffer.write(b'x' * 1000000)"
    )
    ai = Git().execute([sys.executable, "-c", script], as_process=True, istream=PIPE)
    proc = ai.proc
    assert proc.stdout.readline() == b"ready\n"
    watchdog = threading.Timer(5, proc.kill)
    watchdog.start()
    try:
        ai._terminate()
        assert proc.returncode != -9, "cleanup waited for exit with undrained output pipes"
    finally:
        watchdog.cancel()
        watchdog.join()
