#include <stdio.h>
#include <stdint.h>
#include "minunit.h"
#include "obj_cache.h"

/**
 * TODO:
 *  - Run with very permissive gcc settings
 */

int tests_run = 0;

struct test_struct {
        long int m0;
        char m1;
        void *m2;
        int  m3;
        double m4;
};

int test_alignment(size_t align, void *p)
{
    return !((uintptr_t)p & (align - 1));
}

static char *test_object_create_destroy()
{
    /**
     * TODO:
     *  - Refactor
     *  - Swizzle
     */
    int i;
    int *objects[10000];
    struct obj_cache *cache = obj_cache_create(2000, 0);
    
    for (i = 0; i < 10000; i++) {
        objects[i] = obj_cache_alloc(cache);
        *objects[i] = i * 2;
    }

    for (i = 0; i < 10000; i++) {
        obj_cache_free(cache, objects[9999 - i]);
    }

    obj_cache_destroy(cache);

    return NULL;
}

static char *test_user_alignment()
{
    /**
     * TODO: 
     *  - Negative alignments
     *  - Huge alignments
     */
    {
        struct obj_cache *cache = (struct obj_cache *)0xDEADBEEF;
        cache = obj_cache_create(sizeof(struct test_struct), 7);
        mu_assert("obj_cache_create did not return NULL for invalid user alignment\n", 
                  cache == NULL);
    }

    {
        struct obj_cache *cache = (struct obj_cache *)0xDEADBEEF;
        cache = obj_cache_create(sizeof(struct test_struct), sizeof(void *));
        mu_assert("obj_cache_create failed on valid user alignment\n", cache);
    }

    {
        static const int user_alignment = 128;
        struct obj_cache *cache = obj_cache_create(sizeof(struct test_struct), 
                                                   user_alignment);
        struct test_struct *p_s;
        int i;
        
        for (i = 0; i < 10; i++) { 
            p_s = obj_cache_alloc(cache);
            mu_assert("obj_cache_alloc object is not aligned to void * for \
                       valid user alignment\n", 
                      test_alignment(sizeof(void *), p_s)); 
        }

        obj_cache_destroy(cache);
    }

    {
        int i;
        struct test_struct *p_s;
        static const int user_alignment = 128;
        struct obj_cache *cache = obj_cache_create(sizeof(struct test_struct), 
                                                   user_alignment);
        for (i = 0; i < 10; i++) {
            p_s = obj_cache_alloc(cache);
            mu_assert("obj_cache_alloc object is not aligned to valid user \
                       alignment\n", 
                      test_alignment(user_alignment, p_s)); 
        }

        obj_cache_destroy(cache);
    }

    return NULL;
}

static char *test_default_alignment()
{
    /**
     * TODO:
     *  - Negative sizes
     *  - Huge sizes
     */
    {
        struct obj_cache *cache;
        int *p_i;
        int i;

        cache = obj_cache_create(sizeof(int), 0);

        for (i = 0; i < 10; i++) {
            p_i = obj_cache_alloc(cache);
            mu_assert("Integer cache object is not aligned to void *\n", 
                      test_alignment(sizeof(void *), p_i)); 
        }

        obj_cache_destroy(cache);
    }


    {
        struct obj_cache *cache;
        struct test_struct *p_s;
        int i;

        cache = obj_cache_create(sizeof(struct test_struct), 0);

        for (i = 0; i < 10; i++) {
            p_s = obj_cache_alloc(cache);
            mu_assert("Structure cache object is not aligned to void *\n", 
                      test_alignment(sizeof(void *), p_s)); 
        }

        obj_cache_destroy(cache);
    }
   
    return NULL;
}

static char *test_obj_cache_create()
{
    {
        struct obj_cache *cache = (struct obj_cache*)0xDEADBEEF;
        cache = obj_cache_create(0, 0);
        mu_assert("cache is non-NULL on 0 size\n", cache == NULL);
    }

    {
        struct obj_cache *cache = NULL;
        cache = obj_cache_create(4, 0);
        mu_assert("cache is NULL on valid input\n", cache != NULL);
    }

    return NULL;
}

static char *run_all_tests() 
{
    mu_run_test(test_obj_cache_create);
    mu_run_test(test_default_alignment);
    mu_run_test(test_user_alignment);
    mu_run_test(test_object_create_destroy);
    return NULL;
}

int main(void)
{
    char *result = run_all_tests();
    
    if (result != 0) {
        printf("%s\n", result);
    } else {
        printf("ALL TESTS PASSED\n");
    }

    printf("Tests run: %d\n", tests_run);

    return result != 0;
}
