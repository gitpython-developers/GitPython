.. _tutorial-label:

###########
Usage Guide
###########
This text briefly introduces you to the basic design decisions and accompanying classes.

******
Design
******
Per application, there is *MemoryManager* which is held as static instance and used throughout the application. It can be configured to keep your resources within certain limits.

To access mapped regions, you require a cursor. Cursors point to exactly one file and serve as handles into it. As long as it exists, the respective memory region will remain available.

For convenience, a buffer implementation is provided which handles cursors and resource allocation behind its simple buffer like interface.

***************
Memory Managers
***************
There are two types of memory managers, one uses *static* windows, the other one uses *sliding* windows. A window is a region of a file mapped into memory. Although the names might be somewhat misleading as technically windows are always static, the *sliding* version will allocate relatively small windows whereas the *static* version will always map the whole file.

The *static* manager does nothing more than keeping a client count on the respective memory maps which always map the whole file, which allows to make some assumptions that can lead to simplified data access and increased performance, but reduces the compatibility to 32 bit systems or giant files.

The *sliding* memory manager therefore should be the default manager when preparing an application for handling huge amounts of data on 32 bit and 64 bit platforms::

    import smmap
    # This instance should be globally available in your application
    # It is configured to be well suitable for 32-bit or 64 bit applications.
    mman = smmap.SlidingWindowMapManager()
    
    # the manager provides much useful information about its current state
    # like the amount of open file handles or the amount of mapped memory
    mman.num_file_handles()
    mman.mapped_memory_size()
    # and many more ...


Cursors
*******
*Cursors* are handles that point onto a window, i.e. a region of a file mapped into memory. From them you may obtain a buffer through which the data of that window can actually be accessed::

    import smmap.test.lib
    fc = smmap.test.lib.FileCreator(1024*1024*8, "test_file")
    
    # obtain a cursor to access some file.
    c = mman.make_cursor(fc.path)
    
    # the cursor is now associated with the file, but not yet usable
    assert c.is_associated()
    assert not c.is_valid()
    
    # before you can use the cursor, you have to specify a window you want to 
    # access. The following just says you want as much data as possible starting
    # from offset 0.
    # To be sure your region could be mapped, query for validity
    assert c.use_region().is_valid()		# use_region returns self
    
    # once a region was mapped, you must query its dimension regularly
    # to assure you don't try to access its buffer out of its bounds
    assert c.size()
    c.buffer()[0]			# first byte
    c.buffer()[1:10]			# first 9 bytes
    c.buffer()[c.size()-1] 	# last byte
    
    # its recommended not to create big slices when feeding the buffer
    # into consumers (e.g. struct or zlib). 
    # Instead, either give the buffer directly, or use pythons buffer command.
    buffer(c.buffer(), 1, 9)	# first 9 bytes without copying them
    
    # you can query absolute offsets, and check whether an offset is included
    # in the cursor's data.
    assert c.ofs_begin() < c.ofs_end()
    assert c.includes_ofs(100)
    
    # If you are over out of bounds with one of your region requests, the 
    # cursor will be come invalid. It cannot be used in that state
    assert not c.use_region(fc.size, 100).is_valid()
    # map as much as possible after skipping the first 100 bytes
    assert c.use_region(100).is_valid()
    
    # You can explicitly free cursor resources by unusing the cursor's region
    c.unuse_region()
    assert not c.is_valid()
        

Now you would have to write your algorithms around this interface to properly slide through huge amounts of data. 
    
Alternatively you can use a convenience interface.

*******
Buffers
*******
To make first use easier, at the expense of performance, there is a Buffer implementation which uses a cursor underneath.

With it, you can access all data in a possibly huge file without having to take care of setting the cursor to different regions yourself::

    # Create a default buffer which can operate on the whole file
    buf = smmap.SlidingWindowMapBuffer(mman.make_cursor(fc.path))
    
    # you can use it right away
    assert buf.cursor().is_valid()
    
    buf[0]	# access the first byte
    buf[-1]	# access the last ten bytes on the file
    buf[-10:]# access the last ten bytes
    
    # If you want to keep the instance between different accesses, use the
    # dedicated methods
    buf.end_access()
    assert not buf.cursor().is_valid()	# you cannot use the buffer anymore
    assert buf.begin_access(offset=10)	# start using the buffer at an offset
    
    # it will stop using resources automatically once it goes out of scope
    
Disadvantages
*************
Buffers cannot be used in place of strings or maps, hence you have to slice them to have valid input for the sorts of struct and zlib. A slice means a lot of data handling overhead which makes buffers slower compared to using cursors directly. 

