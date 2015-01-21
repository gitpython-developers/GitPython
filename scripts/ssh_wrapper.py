#!/usr/bin/env python

import os
import subprocess
import sys

ssh_options = ['-i', os.environ['GIT_SSH_KEY_FILE']]
ret_code = subprocess.call(['ssh'] + ssh_options + sys.argv[1:])
sys.exit(ret_code)
