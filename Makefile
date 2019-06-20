CC = clang++
CCFLAGS = -Wall -Wextra -Werror -g -O0

dlexplore: dlexplore.o
	$(CC) -o dlexplore $^ -ldl

%.o : %.cc
	$(CC) $(CCFLAGS) -c -o $@ $^

clean:
	rm -f dlexplore *.o
