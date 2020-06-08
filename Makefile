#FLAGS=
FLAGS=-DNDEBUG

all: src/main.c
	gcc ${FLAGS} src/main.c -lpcap -o bin/nids

clean: bin/nids
	rm bin/nids
