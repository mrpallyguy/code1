all: client server

CFLAGS=-lssl -lcrypto -std=c99

client: client.c
    gcc client.c -lssl -lcrypto -std=c99

server: server.c
    gcc server.c -lssl -lcrypto -std=c99

clean:
	rm -f server client client.o server.o


