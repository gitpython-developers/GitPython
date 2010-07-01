
################
Whats New in 0.3
################
GitPython 0.3 is the first step in creating a hybrid which uses a pure python implementations for all simple git features which can be implemented without significant performance penalties. Everything else is still performed using the git command, which is nicely integrated and easy to use.

Its biggest strength, being the support for all git features through the git command itself, is a weakness as well considering the possibly vast amount of times the git command is being started up. Depending on the actual command being performed, the git repository will be initialized on many of these invocations, causing additional overhead for possibly tiny operations.

Keeping as many major operations in the python world will result in improved caching benefits as certain data structures just have to be initialized once and can be reused multiple times. This mode of operation may improve performance when altering the git database on a low level, and is clearly beneficial on operating systems where command invocations are very slow.

****************
Object Databases
****************
An object database provides a simple interface to query object information or to write new object data. Objects are generally identified by their 20 byte binary sha1 value during query.

GitPython uses the ``gitdb`` project to provide a pure-python implementation of the git database, which includes reading and writing loose objects, reading pack files and handling alternate repositories.

The great thing about this is that ``Repo`` objects can use any object database, hence it easily supports different implementations with different performance characteristics. If you are thinking in extremes, you can implement your own database representation, which may be more efficient for what you want to do specifically, like handling big files more efficiently.

************************
Reduced Memory Footprint
************************
Objects, such as commits, tags, trees and blobs now use 20 byte sha1 signatures internally, reducing their memory demands by 20 bytes per object, allowing you to keep more objects in memory at the same time. 

The internal caches of tree objects were improved to use less memory as well.

##################
Upgrading from 0.2
##################
GitPython 0.2 essentially behaves like GitPython 0.3 with a Repository using the ``GitCmdObjectDB`` instead of the ``GitDB`` as object database backend. Additionally it can be used more conveniently through implicit conversions and provides a feature set strikingly similar to 0.3.

**************************
Why you should not upgrade
**************************
GitPython 0.3 in most cases will not run faster than GitPython 0.2, the opposite might be the case at it uses the pure python implementation by default.
There have been a few renames which will need additional adjustments in your code.

Generally, if you only read git repositories, version 0.2 is sufficient and very well performing.

**********************
Why you should upgrade
**********************
GitPython 0.2 has reached its end of line, and it is unlikely to receive more than contributed patches. 0.3 is the main development branch which will lead into the future.

GitPython 0.3 provides memory usage optimization and is very flexible in the way it uses to access the object database. With minimal effort, 0.3 will be running as fast as 0.2. It marks the first step of more versions to come, and will improve over time. 

GitPython 0.3 is especially suitable for everyone who needs not only read, but also write access to a git repository. It is optimized to keep the memory consumption as low as possible, especially when handling large data sets. GitPython 0.3 operates on streams, not on possibly huge chunks of data.


**************
Guided Upgrade
**************
This guide should help to make the upgrade as painless as possible, hence it points out where to start, and what to look out for.

* Have a look at the CHANGES log file and read all important changes about 0.3 for an overview.
* Start applying the renames, generally the ``utils`` modules are now called ``util``, ``errors`` is called ``exc``.
* Search for occurrences of the ``sha`` property of object instances. A similar value can be obtained through the new ``hexsha`` property. The native sha1 value is the ``binsha`` though.
* Search for code which instantiates objects directly. Their initializer now requires a 20 byte binary Sha1, rev-specs cannot be used anymore. For a similar effect, either convert your hexadecimal shas to binary shas beforehand ( ``binascii.unhexlify`` for instance ), or use higher level functions such as ``Object.new``, ``Repo.commit`` or ``Repo.tree``. The latter ones takes rev-specs and hexadecimal sha1 hashes.

