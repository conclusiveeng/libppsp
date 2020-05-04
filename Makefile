CC = gcc
#CFLAGS = -pthread -Wall -Wextra -ggdb3 -std=c11 -D_DEFAULT_SOURCE
CFLAGS = -pthread -Wall -ggdb3 -std=c11 -D_DEFAULT_SOURCE

all: ppspp

%.o: %.c %.h
	$(CC) $< -o $@ -c $(CFLAGS)

ppspp: mt.o sha1.o ppspp_protocol.o net.o peer.o
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	rm -f ppspp *.o
