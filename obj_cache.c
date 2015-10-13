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


enum slab_state {
    SLAB_EMPTY,
    SLAB_PARTIAL,
};

struct obj {
    struct obj *next_obj;
};

struct slab {
    struct slab *next_slab;
};

struct obj_cache {
    struct slab *slabs;
    struct obj *freelist;
    size_t object_size;
    unsigned int objects_per_slab;
    size_t slab_size;
    size_t alignment;
    int refcount;
    void (*ctor)(void *);
    void (*dtor)(void *);
};

static void *map_page(size_t size) 
{
    void *ret = mmap(NULL, size, PROT_READ | PROT_WRITE, 
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    if ((void *)ret == MAP_FAILED) {
        return NULL;
    } 
    
    return ret;
}

static void obj_cache_init_freelist(struct obj_cache *cache, void *slab) 
{
    int i;
    struct obj *freelist = slab;

    for (i = 0; i < cache->objects_per_slab - 1; i++) {
        freelist->next_obj = (struct obj *)((uintptr_t)freelist + 
                                            cache->object_size);
        ASSERT_ALIGNMENT(cache->alignment, freelist->next_obj);
        freelist = freelist->next_obj;
    }
    
    freelist->next_obj = NULL;
    cache->freelist = ((struct obj *)slab)->next_obj;
}

static void obj_cache_add_slab(struct obj_cache *cache, void *slab)
{
    /* The slab meta-data is at the end of the slab memory */
    struct slab *new_slab = (struct slab *)((uintptr_t)slab + cache->slab_size - 
                                       sizeof(struct slab));
    new_slab->next_slab = NULL;
    assert(!((uintptr_t)new_slab & (MALLOC_ALIGN - 1)));

    if (cache->slabs) {
        struct slab *last_slab = cache->slabs;
        while (last_slab->next_slab) {
            last_slab = last_slab->next_slab;
        }

    } else {
        cache->slabs = new_slab;
    }
}

struct obj_cache *obj_cache_create(size_t size, size_t align, 
                                   void (*ctor)(void *), 
                                   void (*dtor)(void *))
{
    if ((align & 0x1) || (align % MALLOC_ALIGN)) {
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
    ret->object_size = size + (size % ret->alignment); 
    ret->objects_per_slab = (ret->slab_size - sizeof(struct slab)) / 
                           ret->object_size;

    printf("Objects per slab: %u\n", ret->objects_per_slab);
    ret->ctor = ctor;
    ret->dtor = dtor;
    ret->freelist = NULL;
    ret->slabs = NULL;

    /**
     * TODO: Temporary size and alignment restrictions till I figure out the
     * rest of the implementation
     */
    assert(size < (ret->slab_size / 2));
    assert(align < ret->slab_size);

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
        cache->freelist = cache->freelist->next_obj;
    } else {
        printf("Adding a page!\n");
        ret = map_page(cache->slab_size); 

        if (ret) {
            obj_cache_add_slab(cache, ret);
            obj_cache_init_freelist(cache, ret);
        }
    }
    
    ASSERT_ALIGNMENT(cache->alignment, ret);
    return ret;
} 

struct obj_cache *obj_cache_free(struct obj_cache *cache)
{
    return NULL;
}

void obj_cache_destroy(struct obj_cache *cache) 
{
}
