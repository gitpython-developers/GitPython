#########
Changelog
#########

******
4.0.12
******

- various improvements - please see the release on GitHub for details.

******
4.0.11
******

- various improvements - please see the release on GitHub for details.

******
4.0.10
******

- improvements to the way external packages are imported.

*****
4.0.9
*****

- re-release of 4.0.8 to get a valid signature.

*****
4.0.8
*****

* drop support for python 3.4 and 3.5 due to EOL
* Updated upper bound for smmap requirement in setup.py
  (`#69 <https://github.com/gitpython-developers/gitdb/issues/76>`_)

*****
4.0.7
*****

* Updated upper bound for smmap requirement in setup.py
  (`#69 <https://github.com/gitpython-developers/gitdb/issues/69>`_)

*****
4.0.6
*****

* Bumped upper bound for smmap requirement
  (`#67 <https://github.com/gitpython-developers/gitdb/issues/67>`_,
  `#68 <https://github.com/gitpython-developers/gitdb/pull/68>`_)

*****
4.0.5
*****

* Re-release of 4.0.4, with known signature

*****
4.0.4
*****

* Support for PyOxidizer

*****
4.0.2
*****

* Updated to release as Pure Python Wheel rather than Universal Wheel
  (`#62 <https://github.com/gitpython-developers/gitdb/pull/62>`_)

*****
4.0.1
*****

* Switched back to the gitdb package name on PyPI and fixed the gitdb2 mirror package
  (`#59 <https://github.com/gitpython-developers/gitdb/issues/59>`_)
* Switched back to require smmap package and fixed version requirement to >= 3.0.1, < 4
  (`#59 <https://github.com/gitpython-developers/gitdb/issues/59>`_)
* Updated smmap submodule

***********
3.0.3.post1
***********

* Fixed changelogs for v3.0.2 and v3.0.3

*****
3.0.3
*****

* Changed ``force_bytes`` to use UTF-8 encoding by default
  (`#49 <https://github.com/gitpython-developers/gitdb/pull/49>`_)
* Restricted smmap2 version requirement to < 3
* Updated requirements.txt

*****
3.0.2
*****

* Removed Python 2 compatibility shims
  (`#56 <https://github.com/gitpython-developers/gitdb/pull/56>`_)

*****
0.6.1
*****

* Fixed possibly critical error, see https://github.com/gitpython-developers/GitPython/issues/220

    - However, it only seems to occur on high-entropy data and didn't reoccour after the fix

*****
0.6.0
*****

* Added support got python 3.X
* Removed all `async` dependencies and all `*_async` versions of methods with it.

*****
0.5.4
*****
* Adjusted implementation to use the SlidingMemoryManager by default in python 2.6 for efficiency reasons. In Python 2.4, the StaticMemoryManager will be used instead.

*****
0.5.3
*****
* Added support for smmap. SmartMMap allows resources to be managed and controlled. This brings the implementation closer to the way git handles memory maps, such that unused cached memory maps will automatically be freed once a resource limit is hit. The memory limit on 32 bit systems remains though as a sliding mmap implementation is not used for performance reasons. 

*****
0.5.2
*****
* Improved performance of the c implementation, which now uses reverse-delta-aggregation to make a memory bound operation CPU bound.

*****
0.5.1
*****
* Restored most basic python 2.4 compatibility, such that gitdb can be imported within python 2.4, pack access cannot work though. This at least allows Super-Projects to provide their own workarounds, or use everything but pack support.

*****
0.5.0
*****
Initial Release
