#include <stdio.h>
#include "obj_cache.h"

int main(void)
{
    double *store[1000];
    int i;
    struct obj_cache *cache = obj_cache_create(sizeof(double), 0);

    for (i = 0; i < 1000; i++) {
        store[i] = obj_cache_alloc(cache);
    }

    for (i = 0; i < 1000; i++) {
        obj_cache_free(cache, store[i]);
    }

    return 0;
}
