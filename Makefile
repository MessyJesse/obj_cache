test: test.c obj_cache.c obj_cache.h
	gcc -o test test.c obj_cache.c -Wall -Wextra -g -fsanitize=undefined -fsanitize=address

clean:
	rm -f test
