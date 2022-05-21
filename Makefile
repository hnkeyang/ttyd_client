
build:
	gcc -o ttyd_client ttyd_client.c websocket_common.c console.c -lssl -lcrypto -D_GNU_SOURCE

debug:
	gcc -o ttyd_client ttyd_client.c websocket_common.c console.c -lssl -lcrypto -D_GNU_SOURCE -g