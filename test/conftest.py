import os
from test.lib import fixture_path

# ensure all tests run with consistent config since some settings break tests
# we could also use pytest-env for this but it's less consistent across OSs

os.environ["GIT_CONFIG_NOSYSTEM"] = "true"
os.environ["GIT_CONFIG_GLOBAL"] = fixture_path("git_config_defaults")
os.environ.pop("GIT_CONFIG_COUNT", None)
os.environ.pop("GIT_CONFIG_SYSTEM", None)
