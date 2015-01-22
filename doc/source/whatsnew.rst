
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
