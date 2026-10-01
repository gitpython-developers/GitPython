"""Run pytest with local packages, an isolated config, and a disposable fixture.

Use the Python interpreter from the installation to test, for example:
    .tox/gix/bin/python test/run-local.py --backend-report=.cache/gix-coverage.json
"""

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def main():
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="gitpython-local-tests-") as directory:
        temporary = Path(directory)
        config = temporary / "gitconfig"
        config.write_text("[user]\nname = GitPython Tests\nemail = tests@example.invalid\n", encoding="utf-8")
        env = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(config),
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_FIND_LINKS": os.environ.get("PIP_FIND_LINKS", str(root / ".cache/gix-wheels")),
            "UV_OFFLINE": "1",
        }

        def git(*args, cwd=root):
            return subprocess.check_output(["git", *map(str, args)], cwd=cwd, env=env, text=True).strip()

        git("config", "--file", config, "include.path", root / "test/fixtures/.gitconfig")
        fixture = temporary / "repo"
        git("clone", "--shared", "--no-checkout", root, fixture)
        git("checkout", "--detach", git("rev-parse", "HEAD"), cwd=fixture)
        if not git("tag", "--list", "[0-9]*", "v[0-9]*", cwd=fixture):
            raise RuntimeError("The local checkout needs version tags for the tests; no remote will be fetched")
        # This prepares only the disposable clone and cannot fetch with tags present.
        if git("tag", "--list", "__testing_point__", cwd=fixture):
            git("tag", "--delete", "__testing_point__", cwd=fixture)
        subprocess.run(
            ["sh", str(root / "init-tests-after-clone.sh")],
            cwd=fixture,
            env={**env, "GITHUB_ACTIONS": "true", "GIT_ALLOW_PROTOCOL": "file"},
            check=True,
        )
        env["GIT_PYTHON_TEST_GIT_REPO_BASE"] = str(fixture)
        # Separate CLI and gix runs can use their own localhost daemon.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            env["GIT_PYTHON_TEST_GIT_DAEMON_PORT"] = str(listener.getsockname()[1])
        return subprocess.call([sys.executable, "-m", "pytest", *sys.argv[1:]], cwd=root, env=env)


if __name__ == "__main__":
    sys.exit(main())
