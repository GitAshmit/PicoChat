/*
 * client.c - CipherChat client
 *
 * Usage: ./client <host> <port> [server.crt]
 *
 * Layers of protection:
 *   1. TLS to the server. The certificate is pinned: only the server that
 *      owns the matching private key is accepted.
 *   2. End-to-end encryption for /msg and /send. Each client makes a fresh
 *      X25519 key pair per session and registers the public half with the
 *      server. Two users derive the same AES-256-GCM key from their key
 *      pair (Diffie-Hellman), so the server only relays ciphertext.
 *      /fingerprint <user> shows a safety code; if both users see the same
 *      code, the server did not swap the keys.
 *
 * select() watches the keyboard (fd 0) and the TLS socket at the same time.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SECRET_ON   0x01     /* server: "hide what the user types now"  */
#define SECRET_OFF  0x02     /* server: "echo is fine again"            */
#define CTL         0x03     /* server: start of a control line         */
#define CTL_MAX     8192
#define NAME_LEN    15
#define MAX_TEXT    1000     /* longest line we send */
#define MAX_FILE    (1024 * 1024)
#define CHUNK       2048     /* file bytes per encrypted message */
#define MAX_PEND    8
#define MAX_XFER    4
#define LINE_LEN_CLIENT 4096

static SSL *ssl;
static struct termios saved_tio;
static int have_tty = 0;
static volatile sig_atomic_t quit_flag = 0;
static int lost = 0;         /* connection broke */
static int quitting = 0;     /* we asked to leave */
static int in_chat = 0;      /* server sent READY: typed lines are now commands */

static EVP_PKEY *mykey;
static unsigned char mypub[32];

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void on_sigint(int sig) { (void)sig; quit_flag = 1; }

static void restore_tty(void) { if (have_tty) tcsetattr(0, TCSANOW, &saved_tio); }

static void set_echo(int on)
{
    if (!have_tty) return;
    struct termios t = saved_tio;
    if (on) t.c_lflag |= ECHO;
    else    t.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(0, TCSANOW, &t);
}

static void put(int fd, const char *s, size_t n)
{
    ssize_t r = write(fd, s, n);
    (void)r;
}

static void say(const char *fmt, ...)
{
    char b[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    if (n > (int)sizeof(b) - 1) n = (int)sizeof(b) - 1;
    if (n > 0) put(1, b, (size_t)n);
}

static void send_line(const char *s)
{
    int n = (int)strlen(s);
    if (SSL_write(ssl, s, n) != n) lost = 1;
}

/* Text that came from another user must never reach the terminal raw:
 * escape sequences and our own 0x01/0x02/0x03 markers are replaced. */
static void clean(char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || *s == 0x7f) *s = '?';
}

static int name_ok(const char *s)
{
    size_t n = strlen(s);
    if (n < 1 || n > NAME_LEN) return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && *s != '_') return 0;
    return 1;
}

/* file name -> safe name with only letters, digits . _ - */
static void safe_name(const char *in, char *out)
{
    const char *base = strrchr(in, '/');
    base = base ? base + 1 : in;
    int n = 0;
    for (; *base && n < 60; base++, n++)
        out[n] = (isalnum((unsigned char)*base) || *base == '.' || *base == '_' || *base == '-') ? *base : '_';
    out[n] = '\0';
    if (n == 0) strcpy(out, "file");
    if (out[0] == '.') out[0] = '_';
}

static int b64enc(const unsigned char *in, int n, char *out)
{
    return EVP_EncodeBlock((unsigned char *)out, in, n);
}

/* out must have room for 3*strlen(in)/4 bytes. Returns the decoded length or -1. */
static int b64dec(const char *in, unsigned char *out)
{
    int n = (int)strlen(in);
    if (n == 0 || n % 4) return -1;
    int pad = (in[n - 1] == '=') + (n > 1 && in[n - 2] == '=');
    int r = EVP_DecodeBlock(out, (const unsigned char *)in, n);
    return r < 0 ? -1 : r - pad;
}

/* ------------------------------------------------------------------ */
/* end-to-end crypto                                                   */
/* ------------------------------------------------------------------ */

static void gen_keys(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!c || EVP_PKEY_keygen_init(c) != 1 || EVP_PKEY_keygen(c, &mykey) != 1) {
        fprintf(stderr, "cannot create encryption keys\n");
        exit(1);
    }
    EVP_PKEY_CTX_free(c);
    size_t l = sizeof(mypub);
    EVP_PKEY_get_raw_public_key(mykey, mypub, &l);
}

/* key = SHA-256("cipherchat-e2e-v1" || DH secret || lower pub || higher pub) */
static int shared_key(const unsigned char *peer, unsigned char key[32])
{
    int ok = 0;
    unsigned char secret[32];
    size_t sl = sizeof(secret);
    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
    if (!pk) return -1;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(mykey, NULL);
    if (c && EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, pk) == 1 &&
        EVP_PKEY_derive(c, secret, &sl) == 1 && sl == 32) {
        int mine_first = memcmp(mypub, peer, 32) < 0;
        const unsigned char *lo = mine_first ? mypub : peer, *hi = mine_first ? peer : mypub;
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        unsigned int dl = 0;
        if (m && EVP_DigestInit_ex(m, EVP_sha256(), NULL) == 1 &&
            EVP_DigestUpdate(m, "cipherchat-e2e-v1", 17) == 1 &&
            EVP_DigestUpdate(m, secret, 32) == 1 &&
            EVP_DigestUpdate(m, lo, 32) == 1 &&
            EVP_DigestUpdate(m, hi, 32) == 1 &&
            EVP_DigestFinal_ex(m, key, &dl) == 1) ok = 1;
        EVP_MD_CTX_free(m);
    }
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(pk);
    return ok ? 0 : -1;
}

/* out = nonce(12) | ciphertext | tag(16). Returns its length or -1. */
static int seal(const unsigned char *key, const unsigned char *aad, int aadl,
                const unsigned char *in, int n, unsigned char *out)
{
    int l = 0, total = 0, ok = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c || RAND_bytes(out, 12) != 1) { EVP_CIPHER_CTX_free(c); return -1; }
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, out) == 1 &&
        EVP_EncryptUpdate(c, NULL, &l, aad, aadl) == 1 &&
        EVP_EncryptUpdate(c, out + 12, &l, in, n) == 1) {
        total = l;
        if (EVP_EncryptFinal_ex(c, out + 12 + total, &l) == 1) {
            total += l;
            if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out + 12 + total) == 1) ok = 1;
        }
    }
    EVP_CIPHER_CTX_free(c);
    return ok ? 12 + total + 16 : -1;
}

/* Returns the plaintext length, or -1 if the message was altered or the key is wrong. */
static int unseal(const unsigned char *key, const unsigned char *aad, int aadl,
                  const unsigned char *in, int n, unsigned char *out)
{
    if (n < 12 + 16) return -1;
    int ct = n - 28, l = 0, total = 0, ok = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, in) == 1 &&
        EVP_DecryptUpdate(c, NULL, &l, aad, aadl) == 1 &&
        EVP_DecryptUpdate(c, out, &l, in + 12, ct) == 1) {
        total = l;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void *)(in + 12 + ct)) == 1 &&
            EVP_DecryptFinal_ex(c, out + total, &l) == 1) { total += l; ok = 1; }
    }
    EVP_CIPHER_CTX_free(c);
    return ok ? total : -1;
}

/* Encrypt 'plain' for 'peer' and send it as "<cmd> <to> <base64>". The
 * additional authenticated data (sender pub | receiver pub) ties the
 * message to this pair of users. */
static int send_encrypted(const char *cmd, const char *to, const unsigned char *peer,
                          const unsigned char *key, const unsigned char *plain, int n)
{
    unsigned char aad[64], ct[CHUNK + 256];
    char line[8192];
    memcpy(aad, mypub, 32);
    memcpy(aad + 32, peer, 32);
    int m = seal(key, aad, 64, plain, n, ct);
    if (m < 0) return -1;
    int k = snprintf(line, sizeof(line), "%s %s ", cmd, to);
    k += b64enc(ct, m, line + k);
    line[k++] = '\n';
    return SSL_write(ssl, line, k) == k ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* things waiting for the other user's public key                      */
/* ------------------------------------------------------------------ */

enum { P_MSG, P_FILE, P_FP };
struct Pend {
    int used, kind, len;
    char to[NAME_LEN + 1];
    char fname[64];
    unsigned char *data;
};
static struct Pend pend[MAX_PEND];

static void want_key(int kind, const char *to, const char *fname, unsigned char *data, int len)
{
    for (int i = 0; i < MAX_PEND; i++)
        if (!pend[i].used) {
            pend[i].used = 1;
            pend[i].kind = kind;
            pend[i].len = len;
            pend[i].data = data;
            snprintf(pend[i].to, sizeof(pend[i].to), "%s", to);
            snprintf(pend[i].fname, sizeof(pend[i].fname), "%s", fname ? fname : "");
            char req[64];
            snprintf(req, sizeof(req), "/getkey %s\n", to);
            send_line(req);
            return;
        }
    free(data);
    say("[too many requests waiting, try again in a moment]\n");
}

static void do_pending(struct Pend *p, const unsigned char *peer)
{
    unsigned char key[32];

    if (p->kind == P_FP) {                  /* same code on both sides, if no key was swapped */
        unsigned char d[32], both[64];
        int mine_first = memcmp(mypub, peer, 32) < 0;
        memcpy(both, mine_first ? mypub : peer, 32);
        memcpy(both + 32, mine_first ? peer : mypub, 32);
        unsigned int dl = 0;
        EVP_Digest(both, 64, d, &dl, EVP_sha256(), NULL);
        char code[64];
        int k = 0;
        for (int i = 0; i < 12; i++) k += sprintf(code + k, "%02x%s", d[i], (i % 2 && i < 11) ? " " : "");
        say("safety code with %s: %s\n(compare it with %s over another channel; it must be identical)\n",
            p->to, code, p->to);
        return;
    }

    if (shared_key(peer, key) < 0) { say("[could not set up encryption with %s]\n", p->to); return; }

    if (p->kind == P_MSG) {
        if (send_encrypted("/emsg", p->to, peer, key, p->data, p->len) < 0) lost = 1;
        else say("[pm to %s] %s\n", p->to, (char *)p->data);
        return;
    }

    /* P_FILE: cut into chunks, each one encrypted and numbered */
    int total = (p->len + CHUNK - 1) / CHUNK;
    if (total == 0) total = 1;
    unsigned char r[4];
    char id[9];
    RAND_bytes(r, 4);
    snprintf(id, sizeof(id), "%02x%02x%02x%02x", r[0], r[1], r[2], r[3]);
    say("[sending %s to %s: %d bytes]\n", p->fname, p->to, p->len);
    for (int idx = 0; idx < total; idx++) {
        int off = idx * CHUNK, n = p->len - off < CHUNK ? p->len - off : CHUNK;
        unsigned char plain[CHUNK + 128];
        int h = snprintf((char *)plain, 128, "%s\n%s\n%d\n%d\n", id, p->fname, idx, total);
        memcpy(plain + h, p->data + off, (size_t)n);
        if (send_encrypted("/efile", p->to, peer, key, plain, h + n) < 0) { lost = 1; return; }
    }
    say("[sent %s to %s]\n", p->fname, p->to);
}

static void on_key(const char *name, const char *val)
{
    for (int i = 0; i < MAX_PEND; i++) {
        struct Pend *p = &pend[i];
        if (!p->used || strcasecmp(p->to, name) != 0) continue;
        unsigned char peer[64];
        if (strcmp(val, "-") == 0)
            say("[%s is not online, or has no encryption key yet]\n", p->to);
        else if (strlen(val) != 44 || b64dec(val, peer) != 32)
            say("[the server sent a bad key for %s]\n", p->to);
        else
            do_pending(p, peer);
        free(p->data);
        p->used = 0;
    }
}

/* ------------------------------------------------------------------ */
/* receiving encrypted messages and files                              */
/* ------------------------------------------------------------------ */

struct Xfer {
    int used, fd, next, total;
    long bytes;
    char from[NAME_LEN + 1], id[9], path[160];
};
static struct Xfer xfer[MAX_XFER];

static void xfer_abort(struct Xfer *x)
{
    if (x->fd >= 0) close(x->fd);
    unlink(x->path);
    say("[file transfer from %s failed]\n", x->from);
    x->used = 0;
}

static struct Xfer *xfer_start(const char *from, const char *id, const char *fname)
{
    for (int i = 0; i < MAX_XFER; i++)
        if (!xfer[i].used) {
            struct Xfer *x = &xfer[i];
            char base[64];
            safe_name(fname, base);
            mkdir("downloads", 0700);
            for (int n = 0; n < 100; n++) {      /* never overwrite an existing file */
                if (n == 0) snprintf(x->path, sizeof(x->path), "downloads/%s", base);
                else        snprintf(x->path, sizeof(x->path), "downloads/%s.%d", base, n);
                x->fd = open(x->path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
                if (x->fd >= 0 || errno != EEXIST) break;
            }
            if (x->fd < 0) return NULL;
            x->used = 1;
            x->next = 0;
            x->bytes = 0;
            snprintf(x->from, sizeof(x->from), "%s", from);
            snprintf(x->id, sizeof(x->id), "%s", id);
            return x;
        }
    return NULL;
}

static void on_efile(const char *from, unsigned char *pt, int m)
{
    /* header: id \n filename \n index \n total \n, then the file bytes */
    char *f[4];
    int pos = 0;
    for (int k = 0; k < 4; k++) {
        unsigned char *nl = m > pos ? memchr(pt + pos, '\n', (size_t)(m - pos)) : NULL;
        if (!nl || nl - (pt + pos) > 80) return;
        *nl = '\0';
        f[k] = (char *)pt + pos;
        pos = (int)(nl - pt) + 1;
    }
    int idx = atoi(f[2]), total = atoi(f[3]), dlen = m - pos;
    if (strlen(f[0]) != 8 || total < 1 || total > MAX_FILE / CHUNK + 1 ||
        idx < 0 || idx >= total || dlen < 0 || dlen > CHUNK) return;

    struct Xfer *x = NULL;
    for (int i = 0; i < MAX_XFER; i++)
        if (xfer[i].used && strcmp(xfer[i].from, from) == 0 && strcmp(xfer[i].id, f[0]) == 0) x = &xfer[i];
    if (!x) {
        if (idx != 0 || !(x = xfer_start(from, f[0], f[1]))) { say("[file from %s refused]\n", from); return; }
        x->total = total;
        say("[receiving a file from %s ...]\n", from);
    }
    if (idx != x->next || total != x->total || x->bytes + dlen > MAX_FILE ||
        write(x->fd, pt + pos, (size_t)dlen) != dlen) { xfer_abort(x); return; }
    x->bytes += dlen;
    x->next++;
    if (x->next == x->total) {
        close(x->fd);
        say("[file received from %s: %s (%ld bytes)]\n", from, x->path, x->bytes);
        x->used = 0;
    }
}

/* EMSG/EFILE <from> <sender pub> <payload> */
static void on_encrypted(int is_file, const char *from, const char *pubb64, const char *payload)
{
    unsigned char peer[64], key[32], aad[64], ct[8192], pt[8192];
    int n;
    if (strlen(pubb64) != 44 || b64dec(pubb64, peer) != 32) return;
    if ((n = b64dec(payload, ct)) < 0 || shared_key(peer, key) < 0) {
        say("[could not read a message from %s]\n", from);
        return;
    }
    memcpy(aad, peer, 32);
    memcpy(aad + 32, mypub, 32);
    int m = unseal(key, aad, 64, ct, n, pt);
    if (m < 0) { say("[could not decrypt a message from %s: altered or wrong key]\n", from); return; }
    if (is_file) { on_efile(from, pt, m); return; }
    pt[m] = '\0';
    clean((char *)pt);
    say("[pm from %s] %s\n", from, (char *)pt);
}

/* ------------------------------------------------------------------ */
/* lines from the server that start with 0x03                          */
/* ------------------------------------------------------------------ */

static void handle_ctl(char *l)
{
    char *save = NULL, *cmd = strtok_r(l, " ", &save);
    if (!cmd) return;
    if (strcmp(cmd, "READY") == 0) {
        in_chat = 1;
        char line[96];
        int k = snprintf(line, sizeof(line), "/pubkey ");
        k += b64enc(mypub, 32, line + k);
        line[k++] = '\n';
        line[k] = '\0';
        send_line(line);
    } else if (strcmp(cmd, "KEY") == 0) {
        char *name = strtok_r(NULL, " ", &save), *val = strtok_r(NULL, " ", &save);
        if (name && val) on_key(name, val);
    } else if (strcmp(cmd, "EMSG") == 0 || strcmp(cmd, "EFILE") == 0) {
        char *from = strtok_r(NULL, " ", &save), *pub = strtok_r(NULL, " ", &save),
             *data = strtok_r(NULL, " ", &save);
        if (from && pub && data) on_encrypted(cmd[1] == 'F', from, pub, data);
    }
}

/* Bytes from the server: plain text goes to the screen, 0x01/0x02 switch
 * password hiding, 0x03 starts a control line (handled, never shown). */
static int secret = 0;

static void on_server_bytes(const char *buf, int n)
{
    static char ctl[CTL_MAX];
    static int ctl_len = -1;
    char out[4096];
    int m = 0;
    for (int k = 0; k < n; k++) {
        unsigned char b = (unsigned char)buf[k];
        if (ctl_len >= 0) {
            if (b == '\n') { ctl[ctl_len] = '\0'; handle_ctl(ctl); ctl_len = -1; }
            else if (ctl_len < CTL_MAX - 1) ctl[ctl_len++] = (char)b;
        } else if (b == CTL)        ctl_len = 0;
        else if (b == SECRET_ON)  { secret = 1; set_echo(0); }
        else if (b == SECRET_OFF) { secret = 0; set_echo(1); }
        else {
            out[m++] = (char)b;
            if (m == (int)sizeof(out)) { put(1, out, (size_t)m); m = 0; }
        }
    }
    if (m) put(1, out, (size_t)m);
}

/* ------------------------------------------------------------------ */
/* what the user types                                                 */
/* ------------------------------------------------------------------ */

static unsigned char *read_file(const char *path, int *len)
{
    int fd = open(path, O_RDONLY);
    struct stat st;
    if (fd < 0) { say("[cannot open %s: %s]\n", path, strerror(errno)); return NULL; }
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) { say("[%s is not a regular file]\n", path); close(fd); return NULL; }
    if (st.st_size > MAX_FILE) { say("[%s is too big (limit %d bytes)]\n", path, MAX_FILE); close(fd); return NULL; }
    unsigned char *buf = malloc((size_t)st.st_size + 1);
    int got = 0;
    while (buf && got < st.st_size) {
        ssize_t r = read(fd, buf + got, (size_t)(st.st_size - got));
        if (r <= 0) break;
        got += (int)r;
    }
    close(fd);
    if (!buf || got != st.st_size) { say("[could not read %s]\n", path); free(buf); return NULL; }
    *len = got;
    return buf;
}

static void handle_typed(char *line)
{
    if (!in_chat) {                          /* login prompts: send exactly what was typed */
        char out[LINE_LEN_CLIENT];
        snprintf(out, sizeof(out), "%s\n", line);
        send_line(out);
        if (secret) put(1, "\n", 1);         /* echo is off, so print the Enter ourselves */
        return;
    }
    if (strlen(line) > MAX_TEXT) {
        say("[line too long (max %d characters), not sent]\n", MAX_TEXT);
        return;
    }

    char *save = NULL;
    if (strncmp(line, "/msg ", 5) == 0 || strncmp(line, "/send ", 6) == 0 ||
        strncmp(line, "/fingerprint ", 13) == 0 || strcmp(line, "/fingerprint") == 0) {
        int kind = line[1] == 'm' ? P_MSG : line[1] == 's' ? P_FILE : P_FP;
        char *rest = strchr(line, ' ');
        while (rest && *rest == ' ') rest++;
        char *to = rest ? strtok_r(rest, " ", &save) : NULL;
        char *arg = to ? save : NULL;                       /* text or path */
        while (arg && *arg == ' ') arg++;
        if (!to || !name_ok(to) || (kind != P_FP && (!arg || !*arg))) {
            say(kind == P_MSG ? "usage: /msg <user> <text>\n" :
                kind == P_FILE ? "usage: /send <user> <file>\n" : "usage: /fingerprint <user>\n");
            return;
        }
        if (kind == P_MSG) {
            unsigned char *t = (unsigned char *)strdup(arg);
            if (t) want_key(P_MSG, to, NULL, t, (int)strlen(arg));
        } else if (kind == P_FILE) {
            int len = 0;
            unsigned char *d = read_file(arg, &len);
            if (!d) return;
            char fn[64];
            safe_name(arg, fn);
            want_key(P_FILE, to, fn, d, len);
        } else {
            want_key(P_FP, to, NULL, NULL, 0);
        }
        return;
    }

    char out[MAX_TEXT + 8];
    snprintf(out, sizeof(out), "%s\n", line);
    if (strcmp(line, "/quit") == 0) quitting = 1;
    send_line(out);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <host> <port> [server.crt]\n", argv[0]);
        return 1;
    }
    const char *ca = (argc > 3) ? argv[3] : "certs/server.crt";

    have_tty = isatty(0) && tcgetattr(0, &saved_tio) == 0;
    atexit(restore_tty);                         /* never leave the terminal with echo off */

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    gen_keys();

    /* --- TLS setup: trust only the server certificate we were given --- */
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
        fprintf(stderr, "cannot read certificate %s (copy it from the server)\n", ca);
        return 1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* --- plain TCP connect first --- */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(argv[1], argv[2], &hints, &res) != 0) {
        fprintf(stderr, "cannot resolve %s:%s\n", argv[1], argv[2]);
        return 1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        return 1;
    }
    freeaddrinfo(res);

    /* --- then wrap the socket in TLS --- */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "TLS handshake failed: %s\n",
                X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        ERR_print_errors_fp(stderr);
        return 1;
    }
    say("[secure connection: %s, %s]\n", SSL_get_version(ssl), SSL_get_cipher_name(ssl));

    char buf[4096], kbuf[LINE_LEN_CLIENT];
    int klen = 0;

    while (!quit_flag && !lost) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(0, &rfds);                        /* keyboard */
        FD_SET(fd, &rfds);                       /* server   */
        int r = select(fd + 1, &rfds, NULL, NULL, NULL);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(0, &rfds)) {                /* keyboard: collect whole lines */
            int n = (int)read(0, kbuf + klen, sizeof(kbuf) - 1 - (size_t)klen);
            if (n <= 0) {                        /* Ctrl+D */
                send_line("/quit\n");
                quitting = 1;
                break;
            }
            klen += n;
            char *start = kbuf, *nl;
            while ((nl = memchr(start, '\n', (size_t)(kbuf + klen - start))) != NULL) {
                *nl = '\0';
                handle_typed(start);
                start = nl + 1;
            }
            klen = (int)(kbuf + klen - start);
            memmove(kbuf, start, (size_t)klen);
            if (klen >= (int)sizeof(kbuf) - 1) { klen = 0; say("[line too long, dropped]\n"); }
        }

        if (!lost && FD_ISSET(fd, &rfds)) {      /* the server sent something */
            int closed = 0;
            do {
                int n = SSL_read(ssl, buf, sizeof(buf));
                if (n <= 0) { closed = 1; break; }
                on_server_bytes(buf, n);
            } while (SSL_pending(ssl) > 0);      /* data already decrypted inside OpenSSL */
            if (closed) {
                if (!quitting) fprintf(stderr, "\n[connection closed by server]\n");
                break;
            }
        }
    }
    if (lost) fprintf(stderr, "\n[connection lost]\n");

    for (int i = 0; i < MAX_XFER; i++)           /* half-received files are removed */
        if (xfer[i].used) { close(xfer[i].fd); unlink(xfer[i].path); }
    for (int i = 0; i < MAX_PEND; i++)
        if (pend[i].used) free(pend[i].data);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    EVP_PKEY_free(mykey);
    return 0;
}
