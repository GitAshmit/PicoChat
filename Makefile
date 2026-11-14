CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g
LDLIBS  = -lssl -lcrypto

all: server server_fork client

server: server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

# the same source, built as a fork()-per-client server (pipes between processes)
server_fork: server.c
	$(CC) $(CFLAGS) -DFORK_MODE -o $@ $< $(LDLIBS)

client: client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

# Self-signed certificate for the server. The private key is chmod 600 so
# only the owner can read it. Skipped if the files already exist.
certs:
	@if [ ! -f certs/server.crt ] || [ ! -f certs/server.key ]; then \
		echo "generating TLS certificate..."; \
		mkdir -p certs && \
		openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
			-subj "/CN=localhost" \
			-keyout certs/server.key -out certs/server.crt 2>/dev/null && \
		chmod 600 certs/server.key && chmod 644 certs/server.crt; \
	fi

# every test runs once against ./server and once against ./server_fork
test: all certs
	python3 test_cipherchat.py
	CIPHERCHAT_SERVER=./server_fork python3 test_cipherchat.py

clean:
	rm -f server server_fork client

# also forgets accounts, logs and the certificate
distclean: clean
	rm -rf certs logs users.db downloads

.PHONY: all certs test clean distclean
