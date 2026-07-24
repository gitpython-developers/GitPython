#########
Changelog
#########

******
v5.0.3
******

- declare support for Python 3.13

For more, see https://github.com/gitpython-developers/smmap/compare/v5.0.3...v5.0.2

******
v5.0.2
******

- remove a usage of mktemp

******
v5.0.1
******

- Added support for Python 3.12

******
v6.0.0
******

YANKED

- Dropped support 3.6 and 3.7
- Declared support for Python 3.11 and 3.12

******
v5.0.0
******

- Dropped support 3.5
- Added support for Python 3.10

******
v4.0.0
******

- Dropped support for Python 2.7 and 3.4
- Added support for Python 3.7, 3.8, and 3.9
- Removed unused exc.MemoryManagerError and exc.RegionCollectionError

******
v3.0.5
******

- Restored Python 2 support removed in v3.0.2
- Changed release signature key to 27C50E7F590947D7273A741E85194C08421980C9.
  See https://keybase.io/byronbates for proof of ownership.

******
v3.0.4
******

- Signed release (with correct key this time)

******
v3.0.2
******

- Signed release
- Switched to GitHub Actions for CI

******
v3.0.1
******
- Switched back to the smmap package name on PyPI and fixed the smmap2 mirror package
  (`#44 <https://github.com/gitpython-developers/smmap/issues/44>`_)
- Fixed setup.py ``long_description`` rendering
  (`#40 <https://github.com/gitpython-developers/smmap/pull/40>`_)

**********
v0.9.0
**********
- Fixed issue with resources never being freed as mmaps were never closed.
- Client counting is now done manually, instead of relying on pyton's reference count

**********
v0.8.5
**********
- Fixed Python 3.0-3.3 regression, which also causes smmap to become about 3 times slower depending on the code path. It's related to this bug (http://bugs.python.org/issue15958), which was fixed in python 3.4

**********
v0.8.4
**********
- Fixed Python 3 performance regression

**********
v0.8.3
**********
- Cleaned up code and assured it works sufficiently well with python 3

**********
v0.8.1
**********
- A single bugfix

**********
v0.8.0 
**********

- Initial Release
