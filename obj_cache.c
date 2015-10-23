#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "obj_cache.h"

#define MALLOC_ALIGN (sizeof(void *))
#define ASSERT_ALIGNMENT(align, p) \
    do { \
        assert(!((uintptr_t)p & (align - 1))); \
        assert(!((uintptr_t)p & (MALLOC_ALIGN - 1))); \
    } while(0)

struct list {
    struct list *next;
};

struct slab_meta {
    struct slab_meta *next;
    unsigned int refcount;
};

struct obj_cache {
    struct list *freelist;
    struct slab_meta *slabs;
    unsigned int slab_count;
    size_t object_size;
    unsigned int objects_per_slab;
    size_t slab_size;
    size_t alignment;
    int refcount;
};

inline static int check_power_of_two(size_t x)
{
    if (x == 0) {
        return 0;
    }
    
    return !(x & (x - 1)) ? 1 : -1;
}

static void *map_page(size_t size) 
{
    void *ret = mmap(NULL, size, PROT_READ | PROT_WRITE, 
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    if ((void *)ret == MAP_FAILED) {
        return NULL;
    } 
    
    return ret;
}

inline static void *find_slab_head(size_t slab_alignment, void *obj)
{
    void *slab = (void *)((uintptr_t)obj & ~(slab_alignment - 1));
    ASSERT_ALIGNMENT(slab_alignment, slab);
    return slab;
}

inline static struct slab_meta *find_slab_meta(void *slab, size_t slab_size)
{
    /* The slab meta-data is at the end of the slab memory */
    struct slab_meta *meta = (void *)((uintptr_t)slab + slab_size - 
                                      sizeof(struct slab_meta));
    ASSERT_ALIGNMENT(MALLOC_ALIGN, meta);
    return meta;
}

static int obj_cache_increment_slab_refcount(struct obj_cache *cache, void *obj)
{
    void *slab = find_slab_head(cache->slab_size, obj);
    struct slab_meta *meta = find_slab_meta(slab, cache->slab_size);
    return ++meta->refcount;
}

static int obj_cache_decrement_slab_refcount(struct obj_cache *cache, void *obj)
{
    void *slab = find_slab_head(cache->slab_size, obj);
    struct slab_meta *meta = find_slab_meta(slab, cache->slab_size);
    return --meta->refcount;
}

static void obj_cache_init_freelist(struct obj_cache *cache, void *slab) 
{
    unsigned int i;
    struct list *freelist = slab;

    for (i = 0; i < cache->objects_per_slab - 1; i++) {
        freelist->next = (void *)((uintptr_t)freelist + 
                                            cache->object_size);
        ASSERT_ALIGNMENT(cache->alignment, freelist->next);
        freelist = freelist->next;
    }
    
    freelist->next = NULL;
    cache->freelist = ((struct list *)slab)->next;
}

static void *obj_cache_add_slab(struct obj_cache *cache)
{
    struct slab_meta *meta;
    void *slab = map_page(cache->slab_size); 

    if (!slab) {
        return NULL;
    }

    meta = find_slab_meta(slab, cache->slab_size);
    meta->refcount = 0;

    if (cache->slabs) {
        meta->next = cache->slabs;
    } else {
        meta->next = NULL;
    }

    cache->slabs = meta;

    obj_cache_init_freelist(cache, slab);

    cache->slab_count++;

    return slab;
}

void obj_cache_reap_slab(struct obj_cache *cache, void *obj)
{
    int stat;
    struct list *curr_obj;
    struct list *prev_obj;
    void *slab_to_free = find_slab_head(cache->slab_size, obj);
    struct slab_meta *meta_to_free = 
                      find_slab_meta(slab_to_free, cache->slab_size);

    if (meta_to_free == cache->slabs) {
        /* We are trying to free the first slab in the slab list */
        cache->slabs = meta_to_free->next;
    } else {
        struct slab_meta *prev_slab = cache->slabs;
        struct slab_meta *curr_slab = cache->slabs->next;

        /* Search for the slab prev to the slab we are trying to free */
        while (curr_slab) {
            if (curr_slab == meta_to_free) {
                prev_slab->next = curr_slab->next;
                break;
            }

            prev_slab = curr_slab;
            curr_slab = curr_slab->next;
        }

        assert(curr_slab == meta_to_free);
    }

    /* Search through evey element in the freelist and remove any object that is
     * in the slab we are reaping */
    prev_obj = cache->freelist;
    curr_obj = cache->freelist->next;

    assert(prev_obj);

    while (curr_obj) {
        if ((uintptr_t)curr_obj >= (uintptr_t)slab_to_free && 
            (uintptr_t)curr_obj < (uintptr_t)meta_to_free) {
            prev_obj->next = curr_obj->next; 
            curr_obj = curr_obj->next;
        } else {
            prev_obj = curr_obj;
            curr_obj = curr_obj->next;
        }
    }

    /* The loop above does not check the first element in the freelist check it
     * here */
    if ((uintptr_t)cache->freelist >= (uintptr_t)slab_to_free && 
        (uintptr_t)cache->freelist < (uintptr_t)meta_to_free) {
        cache->freelist = cache->freelist->next;
    }

    stat = munmap(slab_to_free, cache->slab_size);

    assert(stat == 0);

    cache->slab_count--;
}

struct obj_cache *obj_cache_create(size_t size, size_t align)
{

    if (!size) {
        return NULL;
    }

    if (check_power_of_two(align) == -1 || (align % MALLOC_ALIGN)) {
        return NULL;
    }

    /* TODO: Is there a possible overflow on size? */
    struct obj_cache *ret = mmap(NULL, sizeof(struct obj_cache), 
                                 PROT_READ | PROT_WRITE, 
                                 MAP_PRIVATE | MAP_ANON, -1, 0);
    if ((void *)ret == MAP_FAILED) {
        return NULL;
    }
   
    ret->slab_size = getpagesize();
    /* Don't set the aligment to anything less than the MALLOC alignment */
    ret->alignment = (align > MALLOC_ALIGN ? align : MALLOC_ALIGN);
    if (ret->alignment > size) {
        ret->object_size = ret->alignment;
    } else {
        ret->object_size = (size + ret->alignment - 1) & ~(ret->alignment - 1);
    }

    ret->objects_per_slab = (ret->slab_size - sizeof(struct list)) / 
                            ret->object_size;

    ret->freelist = NULL;
    ret->slabs = NULL;

    /**
     * TODO: Temporary size and alignment restrictions till I figure out the
     * rest of the implementation
     */
    assert(size < (ret->slab_size / 2));
    assert(align < ret->slab_size);
    assert(!(ret->object_size % ret->alignment));

    return ret;
}

void *obj_cache_alloc(struct obj_cache * cache)
{
    void *ret = NULL;

    if (!cache) {
        return ret;
    }

    if (cache->freelist) {
        ret = cache->freelist;
        cache->freelist = cache->freelist->next;
    } else {
        ret = obj_cache_add_slab(cache); 
    }

    ASSERT_ALIGNMENT(cache->alignment, ret);
    
    if (ret) {
        obj_cache_increment_slab_refcount(cache, ret);
    }

    return ret;
} 

void obj_cache_free(struct obj_cache *cache, void *obj)
{
    int refcount;

    if (!cache) {
      return;
    }

    if (cache->freelist) {
        struct list *freelist = obj;
        freelist->next = cache->freelist;
        cache->freelist = freelist;
    } else {
        cache->freelist = obj;
        cache->freelist->next = NULL;
    }

    refcount = obj_cache_decrement_slab_refcount(cache, obj);
    
    if (!refcount) {
        obj_cache_reap_slab(cache, obj);
    }
}

void obj_cache_destroy(struct obj_cache *cache) 
{
    int stat;
    void *data;
    struct slab_meta *slab_to_free;

    if (!cache) {
        return;
    }

    if (cache->slabs) {
        slab_to_free = cache->slabs->next;

        while (slab_to_free) {
            data = (void *)((uintptr_t)slab_to_free - 
                                       (cache->slab_size - 
                                        sizeof(struct slab_meta)));
            ASSERT_ALIGNMENT(cache->slab_size, data);
            slab_to_free = slab_to_free->next;
            stat = munmap(data, cache->slab_size);
            assert(stat == 0);
        }

        data = (void *)((uintptr_t)cache->slabs - (cache->slab_size - 
                                                   sizeof(struct slab_meta)));
        ASSERT_ALIGNMENT(cache->slab_size, data);

        stat = munmap(data, cache->slab_size);
        assert(stat == 0);
    }

    stat = munmap(cache, sizeof(struct obj_cache));
    assert(stat == 0);
}

