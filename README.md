obj_cache: A Slab Allocator
===========================

This is a object cache based on the ideas presented in 
[Jon Bonwick's paper](http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.29.4759). 
This project will be mostly an exercise in profiling and benchmarking. The 
current implementation is pretty naive, but I'd like to see how the 
optimizations presented in Bonwick's paper chance the performance of obj_cache
under various loads.

TODO:
____

-   Benchmark against glib's gslice

-   Move freelist linkage to the end of free buffers

-   The current slab allocation algorithm might be sub-optimal. Instead of 
    allocating just a single slab whenever more memory is needed, should we 
    instead allocate double the number of slabs? Or maybe something like 
    num_slabs_to_allocate = 2 * (num_obj_allocated / obj_per_slab)

-   The current slab reaping algorithm will be problematic for two reasons:
    1. Whenever all the objects in a slab are freed the slab is released
        back to the system. This increases the time for the free operation 
        and the next allocation may be more costly if a new slab has to be 
        allocated.
    2. There is one free list for the entire object cache. This means that
        when we reap a slab we have to search through the entire freelist to
        remove any object that are in the slab we a reaping, which can slow 
        down object frees that also correspond to slab reaping. Bonwick 
        solves this by having a freelist per slab. There are pros and cons to 
        both these methods, I'd like to test and profile them.
-   How does a per-slab free list effect allocation/free time. How does it
    effect reap time

-   Add constructor and destructor, this requires an extra word in the obj
    buffer

-   Look into huge pages and how they might work for larger objects, i.e. if
    anything less than 1/8 of a page is small, then the object classification is based on the page size

-   Should I use posix_memalign rather than manual alignment and mmap?

-   Do I want to try cache coloring?

-   Should I validate pointers that are passed to obj_cache_free as part of
    slabs that I've allocated? How does this effect performance
