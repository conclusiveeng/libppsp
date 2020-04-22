

all: mt

mt: mt.c sha1.c ppspp_protocol.c net.c
	$(CC) $^ -o $@ -ggdb3

clean:
	rm mt
