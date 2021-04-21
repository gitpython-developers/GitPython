# -*- coding: utf-8 -*-
# config.py
# Copyright (C) 2021 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import sys

if sys.version_info[:2] >= (3, 8):
    from typing import Final, Literal
else:
    from typing_extensions import Final, Literal
