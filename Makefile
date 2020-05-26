CC = cc
LIB_CFLAGS = -pthread -Wall -std=c11 -D_DEFAULT_SOURCE -fPIC
LIB_CFLAGS += -ggdb3
#LIB_CFLAGS += -Wextra
#LIB_CFLAGS += -Wpedantic
EXE_CFLAGS = -L. -lppspp -lpthread -ggdb3

LDFLAGS = -shared
all: libppspp.so ppspp

%.o: %.c %.h
	$(CC) $< -o $@ -c $(LIB_CFLAGS)

libppspp.so: mt.o sha1.o ppspp_protocol.o net.o peer.o
	$(CC) $^ -o $@  $(LDFLAGS)

ppspp:
	$(CC) main.c -o $@ $(EXE_CFLAGS)


clean:
	rm -f ppspp *.o libppspp.so
