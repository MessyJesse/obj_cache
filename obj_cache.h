#include <stddef.h>

struct obj_cache;

struct obj_cache *obj_cache_create(size_t size, size_t align, 
                                   void (*ctor)(void *), 
                                   void (*dtor)(void *));
void *obj_cache_alloc(struct obj_cache * cache); 
struct obj_cache *obj_cache_free(struct obj_cache *cache);
void obj_cache_destroy(struct obj_cache *cache);
