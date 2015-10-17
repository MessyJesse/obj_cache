test: test.c obj_cache.c obj_cache.h
	gcc -o test test.c obj_cache.c -Wall -Wextra -g

clean:
	rm -f test
