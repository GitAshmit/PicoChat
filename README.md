# CipherChat

A command-line chat app for Linux. Every connection uses TLS (OpenSSL), users log in with a password, private messages and files are end-to-end encrypted, and everything is plain C on UNIX system calls: sockets, `select()`, `fork()`, pipes, signals, file permissions.

## Quick start

```
sudo apt install build-essential libssl-dev    # once
tar xzf cipherchat.tar.gz && cd cipherchat

./run_server.sh                                # terminal 1: builds, makes a TLS key, starts the server
./client 127.0.0.1 5000                        # terminal 2
./client 127.0.0.1 5000                        # terminal 3
```

The first login with a new username creates the account (you choose a password, which is not shown while you type). To chat from another machine, copy `certs/server.crt` to it and run `./client <server-ip> 5000 server.crt`. The client only trusts that exact certificate.

## Commands

| command | what it does |
|---|---|
| `text` | message to everyone in your room |
| `/join <room>` | join (or create) a room; everyone starts in `#main` |
| `/rooms`, `/users` | list rooms with member counts, list who is online |
| `/msg <user> <text>` | private message, end-to-end encrypted |
| `/fingerprint <user>` | safety code; both users must see the same code |
| `/send <user> <file>` | send a file (up to 1 MB), end-to-end encrypted; saved in the receiver's `downloads/` |
| `/nick <name>`, `/help`, `/quit` | change display name, help, leave (Ctrl+D also leaves) |

## Two kinds of encryption

1. **TLS, client to server.** Protects everything on the network, including logins and group chat. The server can read group chat.
2. **End-to-end, user to user.** On start each client makes a fresh X25519 key pair and gives the server only the public key. Two users combine their keys (Diffie-Hellman), hash the result with SHA-256 and use it as an AES-256-GCM key. The server relays `/emsg` and `/efile` lines it cannot read. If the server tried to swap a key, `/fingerprint` would show different codes to the two users.

## Select server and fork server

The same `server.c` is built two ways: `./server` (one process, `select()`) and `./server_fork` (compiled with `-DFORK_MODE`). Both pass the same 18 tests.

| | `./server` | `./server_fork` |
|---|---|---|
| per client | an entry in a table | its own child process (`fork()`) |
| who does TLS | the one server process | the child; the parent never sees TLS |
| passing messages | a function call | two pipes per child: child to parent (what the user typed), parent to child (what to send) |
| chat state (rooms, names) | one process | parent process only |
| slow TLS handshake | blocks everyone up to 5 s | blocks only that child |
| cleanup | `close()` | `SIGCHLD` handler calls `waitpid()` so there are no zombies |
| cost | very low | one process (and its memory) per client, plus pipe copies |

Try it: start `./server_fork`, connect three clients, then run `pstree -p $(pgrep -f server_fork | head -1)` to see one child per client.

## Files

| file | purpose |
|---|---|
| `server.c` | the server (select mode, or fork mode with `-DFORK_MODE`) |
| `client.c` | the client: TLS, end-to-end crypto, commands, file transfer |
| `Makefile` | `make` builds all, `make test` runs the tests against both servers, `make clean` |
| `run_server.sh` | builds, creates `certs/` and `logs/` if missing, starts the server |
| `test_cipherchat.py` | 18 end-to-end tests; `python3 test_cipherchat.py rooms file` runs a subset |

Created at run time: `certs/server.key` (mode 600), `certs/server.crt`, `users.db` (600), `logs/cipherchat.log` (600), and `downloads/` (700) next to the client.

## Where each UNIX topic is used

| topic | where |
|---|---|
| sockets | `socket`, `bind`, `listen`, `accept`, `connect` in both programs |
| many clients | `select()` + client table (`server`), `fork()` per client (`server_fork`) |
| pipes (IPC) | `pipe()` pairs between the parent and each child in `server_fork` |
| signals | `sigaction`: SIGINT/SIGTERM shut down cleanly, SIGPIPE ignored, SIGCHLD reaps children |
| files and permissions | `open`, `umask(077)`, mode 600 on key, user database and log; `O_EXCL`/`O_NOFOLLOW` for downloads |
| password storage | salted PBKDF2-SHA256, never plain text |
| terminal control | `termios` in `client.c` turns echo off for passwords |
| build and scripts | `Makefile`, `run_server.sh` |

## Demo: show that the traffic is encrypted

Terminal A (needs root): `sudo tcpdump -i lo -A -nn port 5000`. Chat from two clients in other terminals: tcpdump shows only unreadable bytes. `nc 127.0.0.1 5000` gets no service because the server expects a TLS handshake first.

```
openssl s_client -connect 127.0.0.1:5000 -CAfile certs/server.crt   # handshake and certificate
tail -f logs/cipherchat.log                                          # events only, never message text
valgrind --leak-check=full ./server 5000                             # memory check
```

## Limits (worth mentioning in the report)

- Group chat is protected by TLS only: the server can read it. Only `/msg` and `/send` are end-to-end.
- Keys are fresh each session, so safety codes change every session and must be compared again. Messages can be replayed by the server (no message counters).
- A client that stalls during the TLS handshake can delay others by up to 5 s in `./server`.
- IPv4 only. No chat history, no password change, files up to 1 MB.
