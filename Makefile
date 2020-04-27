

CFLAGS = -pthread -Wall
#CFLAGS = -pthread

all: mt

mt: mt.c sha1.c ppspp_protocol.c net.c peer.c
	$(CC) $^ -o $@ -ggdb3 $(CFLAGS)

clean:
	rm mt
