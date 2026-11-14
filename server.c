/*
 * server.c - CipherChat server
 *
 * One process, one select() loop, TLS on every connection.
 *
 *   socket/bind/listen/accept  -> TCP connections        (section 3.1)
 *   select() + client table    -> many users at once     (section 3.2)
 *   OpenSSL                    -> TLS + password hashing (section 3.3)
 *   sigaction                  -> clean shutdown         (section 3.4)
 *   open/chmod/umask           -> users.db, log, key     (section 3.5)
 *
 * Build:  make          Run:  ./run_server.sh   (or ./server [port])
 *
 * Compiled with -DFORK_MODE (make builds it as ./server_fork) the same
 * logic runs as a fork()-per-client server: every child process does only
 * TLS for its client and passes the bytes to the parent through pipes; the
 * parent keeps all chat state. Compare the two in README.md.
 *
 * Private messages and files are end-to-end encrypted by the clients. The
 * server only relays them (/pubkey, /getkey, /emsg, /efile) and cannot read them.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <poll.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#define PORT_DEFAULT  5000
#define MAX_CLIENTS   32
#define NAME_LEN      15          /* longest username / nickname */
#define LINE_LEN      4096        /* longest line a client may send (file chunks are ~3000) */
#define ROOM_DEFAULT  "main"
#define PUBKEY_LEN    44          /* base64 of a 32-byte X25519 public key */
#define LOGIN_TIMEOUT 60          /* seconds a client may sit before logging in */
#define IO_TIMEOUT    5           /* seconds a single read/write may block */
#define MAX_TRIES     3           /* wrong passwords / bad names per connection */

#define SALT_LEN      16
#define HASH_LEN      32
#define PBKDF2_ITER   100000

#define USERS_FILE    "users.db"
#define LOG_FILE      "logs/cipherchat.log"
#define CERT_FILE     "certs/server.crt"
#define KEY_FILE      "certs/server.key"

/* Control bytes the server sends so the client can hide a typed password.
 * Chat text can never contain them because sanitize() strips every
 * control character from what users send. */
#define SECRET_ON     "\x01"
#define SECRET_OFF    "\x02"

#ifdef FORK_MODE
#define MODE_TXT " (fork mode)"
#else
#define MODE_TXT ""
#endif

enum { ST_FREE = 0, ST_USER, ST_PASS, ST_NEWPASS, ST_CHAT };

struct Client {
    int   state;                  /* ST_FREE = unused slot */
    int   fd;                     /* the socket (FORK_MODE: pipe from the child) */
    SSL  *ssl;                    /* TLS state (FORK_MODE: lives in the child) */
    int   out_fd;                 /* FORK_MODE: pipe to the child */
    pid_t pid;                    /* FORK_MODE: the child process */
    int   dead;                   /* set when the client must be dropped */
    int   tries;                  /* failed login attempts so far */
    time_t since;                 /* when the connection was accepted */
    char  ip[INET_ADDRSTRLEN];
    char  user[NAME_LEN + 1];     /* account name typed at login */
    char  name[NAME_LEN + 1];     /* display name (changed by /nick) */
    char  room[NAME_LEN + 1];     /* current chat room */
    char  pub[PUBKEY_LEN + 1];    /* client's public key (base64), for end-to-end encryption */
    int   inlen;
    char  inbuf[LINE_LEN];        /* bytes received but not yet a full line */
};

static struct Client cl[MAX_CLIENTS];
static volatile sig_atomic_t running = 1;
static int log_fd = -1;

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void on_signal(int sig)
{
    (void)sig;
    running = 0;                  /* the select() loop notices and exits */
}

#ifdef FORK_MODE
static void on_sigchld(int sig)
{
    (void)sig;
    int saved = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) {}   /* reap finished children: no zombies */
    errno = saved;
}
#endif

static void put(int fd, const char *s, size_t n)
{
    ssize_t r = write(fd, s, n);
    (void)r;
}

/* Timestamped event log: file + terminal. Events only, never chat text. */
static void logmsg(const char *fmt, ...)
{
    char line[512], ts[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    int n = snprintf(line, sizeof(line), "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line + n, sizeof(line) - n - 1, fmt, ap);
    va_end(ap);

    size_t len = strlen(line);
    line[len++] = '\n';
    if (log_fd >= 0) put(log_fd, line, len);
    put(1, line, len);
}

static int valid_name(const char *s)
{
    size_t n = strlen(s);
    if (n < 1 || n > NAME_LEN) return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && *s != '_') return 0;
    return 1;
}

static int is_b64(const char *s)
{
    if (!*s) return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && *s != '+' && *s != '/' && *s != '=') return 0;
    return 1;
}

#ifdef FORK_MODE
/* Write everything to a pipe. If the pipe is full, wait a few seconds for the reader. */
static int pipe_write_all(int fd, const char *s, int n)
{
    while (n > 0) {
        ssize_t w = write(fd, s, n);
        if (w > 0) { s += w; n -= (int)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && errno == EAGAIN) {
            struct pollfd p = { fd, POLLOUT, 0 };
            if (poll(&p, 1, IO_TIMEOUT * 1000) > 0) continue;
        }
        return 0;
    }
    return 1;
}
#endif

/* Remove control characters (ESC, our 0x01/0x02 markers, ...) so one user
 * can never mess with another user's terminal. */
static void sanitize(char *s)
{
    char *d = s;
    for (; *s; s++)
        if ((unsigned char)*s >= 0x20 && *s != 0x7f) *d++ = *s;
    *d = '\0';
}

/* ------------------------------------------------------------------ */
/* user database: "name:salt_hex:hash_hex" per line                    */
/* ------------------------------------------------------------------ */

static void to_hex(const unsigned char *in, int n, char *out)
{
    for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", in[i]);
}

static int from_hex(const char *hex, unsigned char *out, int n)
{
    for (int i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (unsigned char)v;
    }
    return 0;
}

/* Salted, slow hash: PBKDF2-HMAC-SHA256. Slow on purpose, so guessing
 * passwords from a stolen users.db is expensive. */
static int hash_password(const char *pw, const unsigned char *salt, unsigned char *out)
{
    return PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw), salt, SALT_LEN, PBKDF2_ITER,
                             EVP_sha256(), HASH_LEN, out) == 1 ? 0 : -1;
}

static int find_user(const char *name, unsigned char *salt, unsigned char *hash)
{
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return 0;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *u = strtok(line, ":\n");
        char *s = strtok(NULL, ":\n");
        char *h = strtok(NULL, ":\n");
        if (!u || !s || !h) continue;
        if (strcasecmp(u, name) == 0 &&
            strlen(s) == SALT_LEN * 2 && strlen(h) == HASH_LEN * 2 &&
            from_hex(s, salt, SALT_LEN) == 0 && from_hex(h, hash, HASH_LEN) == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int add_user(const char *name, const char *pw)
{
    unsigned char salt[SALT_LEN], hash[HASH_LEN];
    char sh[SALT_LEN * 2 + 1], hh[HASH_LEN * 2 + 1], line[256];

    if (RAND_bytes(salt, SALT_LEN) != 1) return -1;
    if (hash_password(pw, salt, hash) != 0) return -1;
    to_hex(salt, SALT_LEN, sh);
    to_hex(hash, HASH_LEN, hh);

    /* 0600: only the owner can read the password hashes */
    int fd = open(USERS_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return -1;
    int n = snprintf(line, sizeof(line), "%s:%s:%s\n", name, sh, hh);
    int ok = (write(fd, line, n) == n);
    close(fd);
    return ok ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* sending                                                             */
/* ------------------------------------------------------------------ */

static void send_to(int i, const char *msg)
{
    if (cl[i].state == ST_FREE || cl[i].dead) return;
    int len = (int)strlen(msg);
#ifdef FORK_MODE
    if (!pipe_write_all(cl[i].out_fd, msg, len)) cl[i].dead = 1;
#else
    if (SSL_write(cl[i].ssl, msg, len) != len) cl[i].dead = 1;
#endif
}

/* Read from the client: TLS in the normal server, the child's pipe in FORK_MODE. */
static int raw_read(struct Client *c, char *buf, int n)
{
#ifdef FORK_MODE
    return (int)read(c->fd, buf, n);
#else
    return SSL_read(c->ssl, buf, n);
#endif
}

static int more_pending(struct Client *c)
{
#ifdef FORK_MODE
    (void)c;
    return 0;
#else
    return SSL_pending(c->ssl) > 0;   /* OpenSSL may hold decrypted bytes select() cannot see */
#endif
}

/* Send to everyone in 'room' (NULL = every room), except slot 'except' (-1 = nobody). */
static void broadcast(int except, const char *room, const char *msg)
{
    for (int j = 0; j < MAX_CLIENTS; j++)
        if (j != except && cl[j].state == ST_CHAT && (!room || strcmp(cl[j].room, room) == 0))
            send_to(j, msg);
}

static int find_chat(const char *name)
{
    for (int j = 0; j < MAX_CLIENTS; j++)
        if (cl[j].state == ST_CHAT && strcasecmp(cl[j].name, name) == 0) return j;
    return -1;
}

static int name_in_use(const char *n, int self)
{
    for (int j = 0; j < MAX_CLIENTS; j++) {
        if (j == self) continue;
        struct Client *o = &cl[j];
        if ((o->state == ST_NEWPASS || o->state == ST_CHAT) && strcasecmp(o->user, n) == 0)
            return 1;
        if (o->state == ST_CHAT && strcasecmp(o->name, n) == 0)
            return 1;
    }
    return 0;
}

/* Free a slot. Always do this through here so TLS state is cleaned up. */
static void drop_client(int i, int announce)
{
    struct Client *c = &cl[i];
    char name[NAME_LEN + 1], room[NAME_LEN + 1], out[64];
    int was_chat = (c->state == ST_CHAT);

    strcpy(name, c->name);
    strcpy(room, c->room);
    if (was_chat) logmsg("%s left (%s)", name, c->ip);
    else          logmsg("connection from %s closed before login", c->ip);

    if (c->ssl) {
        SSL_shutdown(c->ssl);     /* send TLS close_notify */
        SSL_free(c->ssl);
        ERR_clear_error();
    }
#ifdef FORK_MODE
    close(c->out_fd);             /* the child sees EOF, sends what is queued and exits */
#endif
    close(c->fd);
    memset(c, 0, sizeof(*c));     /* state back to ST_FREE */

    if (was_chat && announce) {
        snprintf(out, sizeof(out), "* %s left the chat\n", name);
        broadcast(-1, room, out);
    }
}

/* Drop everyone flagged dead. Dropping can flag more clients (failed
 * broadcast), so repeat until nothing is left. */
static void sweep(void)
{
    int again;
    do {
        again = 0;
        for (int i = 0; i < MAX_CLIENTS; i++)
            if (cl[i].state != ST_FREE && cl[i].dead) {
                drop_client(i, 1);
                again = 1;
            }
    } while (again);
}

/* ------------------------------------------------------------------ */
/* login and chat logic                                                */
/* ------------------------------------------------------------------ */

static int bad_try(int i)
{
    if (++cl[i].tries >= MAX_TRIES) {
        send_to(i, SECRET_OFF "Too many failed attempts. Bye.\n");
        logmsg("too many failed attempts from %s", cl[i].ip);
        cl[i].dead = 1;
        return 1;
    }
    return 0;
}

static void enter_chat(int i)
{
    struct Client *c = &cl[i];
    char out[160];

    if (name_in_use(c->user, i)) {       /* logged in elsewhere meanwhile */
        c->state = ST_USER;
        send_to(i, SECRET_OFF "That name is already online.\nUsername: ");
        return;
    }
    c->state = ST_CHAT;
    c->tries = 0;
    strcpy(c->name, c->user);
    strcpy(c->room, ROOM_DEFAULT);

    snprintf(out, sizeof(out), SECRET_OFF "\nWelcome, %s! Type /help for commands.\n", c->name);
    send_to(i, out);
    send_to(i, "\x03" "READY\n");      /* tells the client to send its public key */
    snprintf(out, sizeof(out), "* %s joined the chat\n", c->name);
    broadcast(i, c->room, out);
    logmsg("login ok: %s from %s", c->user, c->ip);
}

static void handle_login(int i, char *line)
{
    struct Client *c = &cl[i];
    unsigned char salt[SALT_LEN], stored[HASH_LEN], hash[HASH_LEN];

    switch (c->state) {
    case ST_USER:
        if (!valid_name(line)) {
            if (!bad_try(i)) send_to(i, "Names are 1-15 letters, digits or _.\nUsername: ");
            return;
        }
        if (name_in_use(line, i)) {
            if (!bad_try(i)) send_to(i, "That name is already online.\nUsername: ");
            return;
        }
        strcpy(c->user, line);
        if (find_user(line, salt, stored)) {
            c->state = ST_PASS;
            send_to(i, "Password: " SECRET_ON);
        } else {
            c->state = ST_NEWPASS;
            send_to(i, "New user. Choose a password (6-64 chars): " SECRET_ON);
        }
        break;

    case ST_PASS:
        if (find_user(c->user, salt, stored) &&
            hash_password(line, salt, hash) == 0 &&
            CRYPTO_memcmp(hash, stored, HASH_LEN) == 0) {   /* constant-time compare */
            enter_chat(i);
        } else {
            logmsg("login failed for %s from %s", c->user, c->ip);
            c->state = ST_USER;
            if (!bad_try(i)) send_to(i, SECRET_OFF "Wrong username or password.\nUsername: ");
        }
        break;

    case ST_NEWPASS:
        if (strlen(line) < 6 || strlen(line) > 64) {
            if (!bad_try(i)) send_to(i, "Password must be 6-64 characters.\nPassword: " SECRET_ON);
            return;
        }
        if (find_user(c->user, salt, stored)) {   /* taken while we were typing */
            c->state = ST_USER;
            send_to(i, SECRET_OFF "That name was just taken.\nUsername: ");
            return;
        }
        if (add_user(c->user, line) != 0) {
            send_to(i, SECRET_OFF "Could not create the account. Bye.\n");
            logmsg("could not write %s", USERS_FILE);
            c->dead = 1;
            return;
        }
        logmsg("new account: %s from %s", c->user, c->ip);
        enter_chat(i);
        break;
    }
}

static int room_size(const char *room)
{
    int n = 0;
    for (int j = 0; j < MAX_CLIENTS; j++)
        if (cl[j].state == ST_CHAT && strcmp(cl[j].room, room) == 0) n++;
    return n;
}

static void handle_chat(int i, char *line)
{
    struct Client *c = &cl[i];
    char out[LINE_LEN + 128];
    unsigned char s[SALT_LEN], h[HASH_LEN];

    if (line[0] == '\0') return;

    if (line[0] != '/') {                    /* normal message: your room only */
        snprintf(out, sizeof(out), "%s: %s\n", c->name, line);
        broadcast(i, c->room, out);
        return;
    }

    /* split "/cmd args" */
    char *arg = strchr(line, ' ');
    if (arg) { *arg++ = '\0'; while (*arg == ' ') arg++; }
    else     { arg = line + strlen(line); }

    if (strcmp(line, "/help") == 0) {
        send_to(i, "commands:\n"
                   "  /join <room>         join (or create) a room\n"
                   "  /rooms               list rooms\n"
                   "  /users               who is online\n"
                   "  /msg <user> <text>   private message (end-to-end encrypted)\n"
                   "  /fingerprint <user>  safety code to verify that encryption\n"
                   "  /send <user> <file>  send a file (end-to-end encrypted)\n"
                   "  /nick <name>         change your display name\n"
                   "  /quit                leave\n");

    } else if (strcmp(line, "/users") == 0) {
        char list[LINE_LEN] = "online:";
        for (int j = 0; j < MAX_CLIENTS; j++)
            if (cl[j].state == ST_CHAT) {
                size_t used = strlen(list);
                snprintf(list + used, sizeof(list) - used, " %s(#%s)", cl[j].name, cl[j].room);
            }
        size_t used = strlen(list);
        snprintf(list + used, sizeof(list) - used, "\n");
        send_to(i, list);

    } else if (strcmp(line, "/rooms") == 0) {
        char list[LINE_LEN] = "rooms:";
        for (int j = 0; j < MAX_CLIENTS; j++) {
            if (cl[j].state != ST_CHAT) continue;
            int seen = 0;
            for (int k = 0; k < j; k++)
                if (cl[k].state == ST_CHAT && strcmp(cl[k].room, cl[j].room) == 0) seen = 1;
            if (seen) continue;
            size_t used = strlen(list);
            snprintf(list + used, sizeof(list) - used, " #%s(%d)", cl[j].room, room_size(cl[j].room));
        }
        size_t used = strlen(list);
        snprintf(list + used, sizeof(list) - used, "\n");
        send_to(i, list);

    } else if (strcmp(line, "/join") == 0) {
        if (!valid_name(arg)) {
            send_to(i, "usage: /join <room>   (1-15 letters, digits or _)\n");
        } else {
            char room[NAME_LEN + 1];
            strcpy(room, arg);
            for (char *p = room; *p; p++) *p = (char)tolower((unsigned char)*p);
            if (strcmp(room, c->room) == 0) {
                send_to(i, "you are already in that room\n");
            } else {
                snprintf(out, sizeof(out), "* %s moved to #%s\n", c->name, room);
                broadcast(i, c->room, out);
                strcpy(c->room, room);
                snprintf(out, sizeof(out), "* %s joined #%s\n", c->name, c->room);
                broadcast(i, c->room, out);
                snprintf(out, sizeof(out), "you are now in #%s\n", c->room);
                send_to(i, out);
                logmsg("%s joined room %s", c->name, c->room);
            }
        }

    } else if (strcmp(line, "/pubkey") == 0) {
        /* the client's end-to-end public key; other clients fetch it with /getkey */
        if (strlen(arg) == PUBKEY_LEN && is_b64(arg)) strcpy(c->pub, arg);
        else send_to(i, "invalid public key\n");

    } else if (strcmp(line, "/getkey") == 0) {
        int j = valid_name(arg) ? find_chat(arg) : -1;
        if (j >= 0 && cl[j].pub[0])
            snprintf(out, sizeof(out), "\x03" "KEY %s %s\n", cl[j].name, cl[j].pub);
        else
            snprintf(out, sizeof(out), "\x03" "KEY %s -\n", valid_name(arg) ? arg : "invalid");
        send_to(i, out);

    } else if (strcmp(line, "/emsg") == 0 || strcmp(line, "/efile") == 0) {
        /* Opaque, already-encrypted payload: relay it, never look inside. */
        char *sp = strchr(arg, ' ');
        if (!sp) { send_to(i, "bad request\n"); return; }
        *sp++ = '\0';
        int j = find_chat(arg);
        if (!c->pub[0] || !is_b64(sp))        send_to(i, "bad request\n");
        else if (j < 0 || j == i)             send_to(i, "no such user online\n");
        else {
            snprintf(out, sizeof(out), "\x03" "%s %s %s %s\n",
                     strcmp(line, "/emsg") == 0 ? "EMSG" : "EFILE", c->name, c->pub, sp);
            send_to(j, out);
        }

    } else if (strcmp(line, "/msg") == 0 || strcmp(line, "/send") == 0 ||
               strcmp(line, "/fingerprint") == 0) {
        send_to(i, "that command needs the cipherchat client (end-to-end encryption)\n");

    } else if (strcmp(line, "/nick") == 0) {
        if (!valid_name(arg))
            send_to(i, "usage: /nick <name>   (1-15 letters, digits or _)\n");
        else if (name_in_use(arg, i))
            send_to(i, "that name is taken\n");
        else if (strcasecmp(arg, c->user) != 0 && find_user(arg, s, h))
            send_to(i, "that name belongs to a registered user\n");
        else {
            char old[NAME_LEN + 1];
            strcpy(old, c->name);
            strcpy(c->name, arg);
            snprintf(out, sizeof(out), "* %s is now known as %s\n", old, c->name);
            broadcast(-1, c->room, out);
            logmsg("nick change: %s -> %s", old, c->name);
        }

    } else if (strcmp(line, "/quit") == 0) {
        send_to(i, "Bye!\n");
        c->dead = 1;

    } else {
        send_to(i, "unknown command, try /help\n");
    }
}

/* ------------------------------------------------------------------ */
/* receiving: TCP is a byte stream, so we cut it into lines ourselves  */
/* ------------------------------------------------------------------ */

static void read_client(int i)
{
    struct Client *c = &cl[i];

    do {
        int room = LINE_LEN - c->inlen;
        if (room <= 0) {                         /* a "line" with no end */
            send_to(i, "* line too long, disconnecting\n");
            c->dead = 1;
            return;
        }
        int n = raw_read(c, c->inbuf + c->inlen, room);
        if (n <= 0) { c->dead = 1; return; }     /* closed or error */
        c->inlen += n;

        char *start = c->inbuf, *nl;
        while (!c->dead &&
               (nl = memchr(start, '\n', c->inbuf + c->inlen - start)) != NULL) {
            *nl = '\0';
            if (nl > start && nl[-1] == '\r') nl[-1] = '\0';
            sanitize(start);
            if (c->state == ST_CHAT) handle_chat(i, start);
            else                     handle_login(i, start);
            start = nl + 1;
        }
        int left = (int)(c->inbuf + c->inlen - start);
        memmove(c->inbuf, start, left);          /* keep the unfinished tail */
        c->inlen = left;

        /* OpenSSL may already hold decrypted bytes that select() cannot
         * see, so keep reading until it is empty. */
    } while (!c->dead && more_pending(c));
}

#ifdef FORK_MODE
/* Runs in the child process: TLS to one client on one side, two pipes to the
 * parent on the other. It never looks at what is being said. */
static void child_main(int sock, SSL_CTX *ctx, int from_parent, int to_parent, const char *ip)
{
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_accept(ssl) != 1) {
        logmsg("TLS handshake failed from %s", ip);
        _exit(1);
    }
    logmsg("TLS session from %s (%s, %s)", ip, SSL_get_version(ssl), SSL_get_cipher_name(ssl));

    char buf[LINE_LEN];
    int alive = 1;
    while (alive) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        FD_SET(from_parent, &rfds);
        int maxfd = sock > from_parent ? sock : from_parent;
        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (FD_ISSET(sock, &rfds)) {                 /* client -> parent */
            do {
                int n = SSL_read(ssl, buf, sizeof(buf));
                if (n <= 0 || !pipe_write_all(to_parent, buf, n)) { alive = 0; break; }
            } while (SSL_pending(ssl) > 0);
        }
        if (alive && FD_ISSET(from_parent, &rfds)) { /* parent -> client */
            int n = (int)read(from_parent, buf, sizeof(buf));
            if (n <= 0 || SSL_write(ssl, buf, n) != n) break;   /* n == 0: parent closed the pipe */
        }
    }
    SSL_shutdown(ssl);
    _exit(0);
}
#endif

static void accept_client(int lfd, SSL_CTX *ctx)
{
    struct sockaddr_in a;
    socklen_t al = sizeof(a);
    int fd = accept(lfd, (struct sockaddr *)&a, &al);
    if (fd < 0) return;

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a.sin_addr, ip, sizeof(ip));

    int slot = -1;
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (cl[i].state == ST_FREE) { slot = i; break; }
    if (slot < 0) {
        logmsg("rejected %s: server full", ip);
        close(fd);
        return;
    }

    /* A client that stalls must not freeze the whole server. */
    struct timeval tv = { IO_TIMEOUT, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct Client *c = &cl[slot];
#ifdef FORK_MODE
    int up[2], down[2];                              /* up: child -> parent, down: parent -> child */
    if (pipe(up) < 0) { close(fd); return; }
    if (pipe(down) < 0) { close(up[0]); close(up[1]); close(fd); return; }
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(up[0]); close(up[1]); close(down[0]); close(down[1]); close(fd);
        return;
    }
    if (pid == 0) {                                  /* ---- child ---- */
        signal(SIGINT, SIG_IGN);                     /* only the parent decides when to stop */
        signal(SIGTERM, SIG_IGN);
        signal(SIGCHLD, SIG_DFL);
        close(lfd); close(up[0]); close(down[1]);
        for (int j = 0; j < MAX_CLIENTS; j++)        /* the parent's ends of the other clients' pipes */
            if (cl[j].state != ST_FREE) { close(cl[j].fd); close(cl[j].out_fd); }
        child_main(fd, ctx, down[0], up[1], ip);     /* never returns */
    }
    close(fd); close(up[1]); close(down[0]);         /* ---- parent ---- */
    fcntl(down[1], F_SETFL, O_NONBLOCK);
    memset(c, 0, sizeof(*c));
    c->fd = up[0];
    c->out_fd = down[1];
    c->pid = pid;
    logmsg("connection from %s (child process %d)", ip, (int)pid);
#else
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1) {                      /* TLS handshake */
        logmsg("TLS handshake failed from %s", ip);
        ERR_clear_error();
        SSL_free(ssl);
        close(fd);
        return;
    }
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->ssl = ssl;
    logmsg("connection from %s (%s, %s)", ip, SSL_get_version(ssl), SSL_get_cipher_name(ssl));
#endif
    c->state = ST_USER;
    c->since = time(NULL);
    strcpy(c->ip, ip);
    send_to(slot, "Welcome to CipherChat. Your connection is encrypted.\nUsername: ");
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    int port = (argc > 1) ? atoi(argv[1]) : PORT_DEFAULT;
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "usage: %s [port]\n", argv[0]);
        return 1;
    }

    umask(077);                                  /* new files: owner only */
    mkdir("logs", 0700);
    log_fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (log_fd < 0) perror("warning: cannot open log file");

    /* No SA_RESTART: we want select() to return EINTR so the loop can
     * see that 'running' became 0. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = SIG_IGN;                     /* writing to a closed socket must not kill us */
    sigaction(SIGPIPE, &sa, NULL);
#ifdef FORK_MODE
    sa.sa_handler = on_sigchld;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
#endif

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "cannot load %s / %s - run ./run_server.sh or 'make certs'\n",
                CERT_FILE, KEY_FILE);
        return 1;
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return 1; }
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(lfd, 8) < 0) { perror("listen"); return 1; }
    logmsg("server listening on port %d%s", port, MODE_TXT);

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lfd, &rfds);
        int maxfd = lfd;
        for (int i = 0; i < MAX_CLIENTS; i++)
            if (cl[i].state != ST_FREE) {
                FD_SET(cl[i].fd, &rfds);
                if (cl[i].fd > maxfd) maxfd = cl[i].fd;
            }

        struct timeval tv = { 1, 0 };            /* wake up every second for timeouts */
        int r = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR) continue;        /* a signal arrived */
            perror("select");
            break;
        }

        if (r > 0) {
            if (FD_ISSET(lfd, &rfds)) accept_client(lfd, ctx);
            for (int i = 0; i < MAX_CLIENTS; i++)
                if (cl[i].state != ST_FREE && !cl[i].dead && FD_ISSET(cl[i].fd, &rfds))
                    read_client(i);
        }

        time_t now = time(NULL);
        for (int i = 0; i < MAX_CLIENTS; i++)
            if (cl[i].state != ST_FREE && cl[i].state != ST_CHAT &&
                !cl[i].dead && now - cl[i].since > LOGIN_TIMEOUT) {
                send_to(i, SECRET_OFF "Login timed out.\n");
                logmsg("login timeout for %s", cl[i].ip);
                cl[i].dead = 1;
            }

        sweep();
    }

    logmsg("shutting down");
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (cl[i].state != ST_FREE) {
            send_to(i, "* server is shutting down\n");
            drop_client(i, 0);
        }
#ifdef FORK_MODE
    while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) {}   /* let the children flush and exit */
#endif
    close(lfd);
    SSL_CTX_free(ctx);
    if (log_fd >= 0) close(log_fd);
    return 0;
}
