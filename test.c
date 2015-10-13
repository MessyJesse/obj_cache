#include <stdio.h>
#include "obj_cache.h"

int main(void)
{
    struct obj_cache *cache = obj_cache_create(sizeof(double), 0, NULL, NULL);
    
    int i = 0;
    for (; i < 10000; i++) {
        double *d = obj_cache_alloc(cache);
        *d = 1000.0;
        printf("%f\n", *d);
        printf("%p\n", d);
        obj_cache_free(cache, d);
    }

    return 0;
}
