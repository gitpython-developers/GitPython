########
Overview
########

The *GitDB* project implements interfaces to allow read and write access to git repositories. In its core lies the *db* package, which contains all database types necessary to read a complete git repository. These are the ``LooseObjectDB``, the ``PackedDB`` and the ``ReferenceDB`` which are combined into the ``GitDB`` to combine every aspect of the git database.

For this to work, GitDB implements pack reading, as well as loose object reading and writing. Data is always encapsulated in streams, which allows huge files to be handled as well as small ones, usually only chunks of the stream are kept in memory for processing, never the whole stream at once.

Interfaces are used to describe the API, making it easy to provide alternate implementations.

================
Installing GitDB
================
Its easiest to install gitdb using the *pip*  program::
    
    $ pip install gitdb
    
As the command will install gitdb in your respective python distribution, you will most likely need root permissions to authorize the required changes.

If you have downloaded the source archive, the package can be installed by running the ``setup.py`` script::
    
    $ python setup.py install
    
===============
Getting Started
===============
It is advised to have a look at the :ref:`Usage Guide <tutorial-label>` for a brief introduction on the different database implementations.
    
=================
Source Repository
=================
The latest source can be cloned using git from github:

 * https://github.com/gitpython-developers/gitdb

License Information
===================
*GitDB* is licensed under the New BSD License.
