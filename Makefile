CC = clang++

dlexplore: dlexplore.o
	$(CC) -o dlexplore $^ -ldl

%.o : %.cc
	$(CC) -c -o $@ $^ -g -O0

clean:
	rm -f dlexplore *.o
