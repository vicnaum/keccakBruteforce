CC=gcc
INSTALL=install
prefix=/usr/local
CFLAGS=-Wall -ggdb -O2 -I.
LDFLAGS=

.PHONY : all test clean 

all: sha3run

sha3.o: sha3.c
	$(CC) -c $(CFLAGS) -o $@ $<

sha3run.o : sha3run.c
	$(CC) -c $(CFLAGS) -o $@ $<

sha3run: sha3.o sha3run.o 
	$(CC) -o $@ $^ ${LDFLAGS}

clean:
	-rm -f *.o sha3run
