all: pbproxy

pbproxy: pbproxy.c
	gcc utils.c server.c client.c pbproxy.c -o pbproxy  -lpthread -lcrypto

clean:
	rm -f pbproxy
