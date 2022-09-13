QJSPATH=../../quickjs-2021-03-27

CC=gcc
LD=ld
CFLAGS=-I$(QJSPATH) $(shell pkg-config --cflags libssl libcrypto)
LDFLAGS=$(QJSPATH)/libquickjs.a $(shell pkg-config --libs libssl libcrypto) -lm -ldl

hash.so: quickjs-hash.o
	$(LD) $(LDFLAGS) -shared -soname hash -o hash.so quickjs-hash.o
	ln -s hash.so libhash.so

quickjs-hash.o: quickjs-hash.c
	$(CC) $(CFLAGS) -c -o quickjs-hash.o quickjs-hash.c

test: test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o test test.c -L. -L$(QJSPATH) -lhash -lquickjs

clean:
	rm hash.so quickjs-hash.o libhash.so

all: hash.so test
