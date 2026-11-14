#!/usr/bin/env python3
"""End-to-end tests for CipherChat.  Run:  make test   (or python3 test_cipherchat.py)

Every test starts its own server in a temporary directory, so accounts and
logs never leak between tests (or into your real users.db).
"""
import base64
import hashlib
import os
import pty
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.abspath(os.environ.get("CIPHERCHAT_SERVER") or os.path.join(HERE, "server"))
SLOW = float(os.environ.get("CIPHERCHAT_SLOW", "1"))   # raise when running under valgrind
IS_FORK = SERVER.endswith("server_fork")


class Skip(Exception):
    pass
CLIENT = os.path.abspath(os.environ.get("CIPHERCHAT_CLIENT") or os.path.join(HERE, "client"))
CERT = os.path.join(HERE, "certs", "server.crt")
KEY = os.path.join(HERE, "certs", "server.key")
PORT = 5611
PROXY_PORT = 5612


# --------------------------------------------------------------------------
# test helpers
# --------------------------------------------------------------------------
class Server:
    """Runs ./server in a throw-away directory."""

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="cipherchat_test_")
        os.makedirs(os.path.join(self.dir, "certs"))
        shutil.copy(CERT, os.path.join(self.dir, "certs", "server.crt"))
        shutil.copy(KEY, os.path.join(self.dir, "certs", "server.key"))
        os.chmod(os.path.join(self.dir, "certs", "server.key"), 0o600)
        self.p = subprocess.Popen([SERVER, str(PORT)], cwd=self.dir,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        # wait until the server says it is listening (poll its log file)
        end = time.time() + 5 * SLOW
        while time.time() < end:
            if "listening" in self.log():
                return self
            time.sleep(0.05)
        raise AssertionError("server did not start: " + str(self.p.poll()))

    def log(self):
        try:
            with open(os.path.join(self.dir, "logs", "cipherchat.log")) as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def path(self, name):
        return os.path.join(self.dir, name)

    def alive(self):
        return self.p.poll() is None

    def __exit__(self, *exc):
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
            try:
                self.p.wait(timeout=5 * SLOW)
            except subprocess.TimeoutExpired:
                self.p.kill()
        err = self.p.stderr.read().decode(errors='replace') if self.p.stderr else ''
        shutil.rmtree(self.dir, ignore_errors=True)
        if exc[0] is None and re.search(r'Invalid (read|write)|definitely lost|uninitialised', err):
            raise AssertionError('valgrind reported problems:\n' + err[:1500])


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.load_verify_locations(CERT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    return ctx


class Chat:
    """A scripted chat client speaking TLS to the server."""

    def __init__(self, port=PORT):
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.s = tls_context().wrap_socket(raw)
        self.buf = bytearray()

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.s.sendall(data)

    def expect(self, needle, timeout=5):
        if isinstance(needle, str):
            needle = needle.encode()
        end = time.time() + timeout * SLOW
        while needle not in self.buf:
            left = end - time.time()
            if left <= 0:
                raise AssertionError("timed out waiting for %r, got %r" % (needle, bytes(self.buf)))
            self.s.settimeout(left)
            try:
                d = self.s.recv(4096)
            except (socket.timeout, TimeoutError):
                continue
            except (ssl.SSLError, OSError) as e:
                raise AssertionError("connection error (%s) waiting for %r, got %r" % (e, needle, bytes(self.buf)))
            if not d:
                raise AssertionError("connection closed waiting for %r, got %r" % (needle, bytes(self.buf)))
            self.buf += d
        i = self.buf.index(needle) + len(needle)
        got = bytes(self.buf[:i])
        del self.buf[:i]
        return got

    def drain(self, wait=0.5):
        """Collect whatever arrives during `wait` seconds."""
        end = time.time() + wait
        while True:
            left = end - time.time()
            if left <= 0:
                break
            self.s.settimeout(left)
            try:
                d = self.s.recv(4096)
            except (socket.timeout, TimeoutError, ssl.SSLError, OSError):
                break
            if not d:
                break
            self.buf += d
        out = bytes(self.buf)
        self.buf.clear()
        return out

    def wait_closed(self, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            self.s.settimeout(max(0.1, end - time.time()))
            try:
                d = self.s.recv(4096)
            except (socket.timeout, TimeoutError):
                continue
            except (ssl.SSLError, OSError):
                return True
            if not d:
                return True
            self.buf += d
        return False

    def quit(self):
        self.send("/quit\n")
        assert self.wait_closed(), "server did not close after /quit"

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def login(name, pw="secret-pw-1", new=True, port=PORT):
    c = Chat(port)
    c.expect("Username: ")
    c.send(name + "\n")
    c.expect("Choose a password" if new else "Password: ")
    c.send(pw + "\n")
    c.expect("Welcome, %s!" % name)
    return c


class SniffProxy:
    """Sits between client and server and records every byte, like tcpdump."""

    def __init__(self, listen_port, target_port):
        self.data = bytearray()
        self.target = target_port
        self.stop = False
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", listen_port))
        self.lsock.listen(5)
        self.lsock.settimeout(0.3)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.stop:
            try:
                c, _ = self.lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = socket.create_connection(("127.0.0.1", self.target))
            threading.Thread(target=self._pipe, args=(c, t), daemon=True).start()
            threading.Thread(target=self._pipe, args=(t, c), daemon=True).start()

    def _pipe(self, src, dst):
        try:
            while True:
                d = src.recv(4096)
                if not d:
                    break
                self.data += d
                dst.sendall(d)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def close(self):
        self.stop = True
        self.lsock.close()


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------
def test_traffic_is_encrypted():
    """What a sniffer on the wire sees: TLS records, no readable text."""
    with Server():
        proxy = SniffProxy(PROXY_PORT, PORT)
        try:
            bob = login("bob")
            alice = login("alice", pw="pw-sniff-123", port=PROXY_PORT)
            alice.send("top-secret-message-xyz\n")
            bob.expect("alice: top-secret-message-xyz")
            time.sleep(0.3)
            wire = bytes(proxy.data)
            assert len(wire) > 500, "proxy saw too little traffic (%d bytes)" % len(wire)
            assert wire[0] == 0x16 and wire[1] == 0x03, "stream does not start with a TLS handshake"
            for secret in (b"top-secret-message-xyz", b"pw-sniff-123", b"alice", b"Username", b"Welcome"):
                assert secret not in wire, "plaintext %r visible on the wire!" % secret
            print("      wire capture: %d bytes, first bytes %s, no plaintext" % (len(wire), wire[:6].hex(" ")))
            alice.close(); bob.close()
        finally:
            proxy.close()


def test_accounts_and_password_storage():
    with Server() as srv:
        c = login("carol", pw="correct-horse-9")
        c.quit()
        time.sleep(0.2)

        # right password works
        c = login("carol", pw="correct-horse-9", new=False)
        c.quit()
        time.sleep(0.2)

        # wrong password is refused
        c = Chat()
        c.expect("Username: "); c.send("carol\n")
        c.expect("Password: "); c.send("wrong-pass\n")
        c.expect("Wrong username or password")
        c.close()

        db = open(srv.path("users.db")).read()
        assert db.startswith("carol:") and db.count("\n") == 1
        assert "correct-horse-9" not in db, "password stored in plain text!"
        name, salt, h = db.strip().split(":")
        assert len(salt) == 32 and len(h) == 64
        for f in ("users.db", "logs/cipherchat.log", "certs/server.key"):
            mode = os.stat(srv.path(f)).st_mode & 0o777
            assert mode == 0o600, "%s has mode %o" % (f, mode)
        print("      users.db line: %s:%s...:%s..." % (name, salt[:8], h[:8]))


def test_group_chat_private_msgs_and_nick():
    with Server() as srv:
        alice = login("alice")
        bob = login("bob")
        carol = login("carol")
        alice.expect("* bob joined the chat")
        alice.drain(0.3); bob.drain(0.3); carol.drain(0.3)

        alice.send("hello everyone\n")
        bob.expect("alice: hello everyone")
        carol.expect("alice: hello everyone")
        assert b"alice:" not in alice.drain(0.4), "sender got own message back"

        bob.send("/users\n")
        bob.expect("online:")
        rest = bob.drain(0.4).decode()
        for n in ("alice", "bob", "carol"):
            assert n in rest, "/users missing %s: %r" % (n, rest)

        alice.send("/msg bob plain-text-attempt\n")      # raw TLS clients cannot do private chat
        alice.expect("needs the cipherchat client")

        bob.send("/nick bobby\n")
        alice.expect("* bob is now known as bobby")
        carol.send("/nick alice\n")
        carol.expect("that name is taken")
        carol.send("/frobnicate\n")
        carol.expect("unknown command")

        bobby = bob
        bobby.send("/quit\n")
        alice.expect("* bobby left the chat")

        # the log records events but never what people said
        log = srv.log()
        for event in ("new account: alice", "login ok: bob", "nick change: bob -> bobby", "bobby left"):
            assert event in log, "log is missing %r" % event
        assert "TLSv1.3" in log or "TLSv1.2" in log
        for text in ("hello everyone", "plain-text-attempt"):
            assert text not in log, "message content leaked into the log: %r" % text
        alice.close(); carol.close()


def test_registered_names_are_protected():
    with Server():
        c = login("dave"); c.quit(); time.sleep(0.2)
        erin = login("erin")
        erin.send("/nick dave\n")
        erin.expect("belongs to a registered user")
        erin.close()


def test_duplicate_login_rejected():
    with Server():
        a = login("alice")
        b = Chat()
        b.expect("Username: "); b.send("alice\n")
        b.expect("already online")
        b.close(); a.close()


def test_login_limits_and_bad_names():
    with Server():
        c = login("zed", pw="zed-password"); c.quit(); time.sleep(0.2)
        c = Chat()
        c.expect("Username: ")
        c.send("bad name!\n")
        c.expect("Names are 1-15 letters")          # failed attempt 1 of 3
        c.send("zed\n"); c.expect("Password: ")
        c.send("nope-nope\n")                        # failed attempt 2 of 3
        c.expect("Wrong username or password")
        c.send("zed\n"); c.expect("Password: ")
        c.send("nope-nope\n")                        # failed attempt 3 of 3
        c.expect("Too many failed attempts")
        assert c.wait_closed(), "server did not hang up after too many failures"


def test_short_password_refused():
    with Server() as srv:
        c = Chat()
        c.expect("Username: "); c.send("shorty\n")
        c.expect("Choose a password"); c.send("abc\n")
        c.expect("Password must be 6-64")
        c.close()
        assert not os.path.exists(srv.path("users.db"))


def test_framing_burst_and_sanitizing():
    with Server():
        alice = login("alice"); bob = login("bob")
        alice.expect("* bob joined the chat"); alice.drain(0.2); bob.drain(0.2)

        # one message split across three TCP/TLS writes
        alice.send(b"hel"); time.sleep(0.2)
        alice.send(b"lo wor"); time.sleep(0.2)
        alice.send(b"ld\n")
        bob.expect("alice: hello world\n")

        # many messages in a single write arrive separately and in order
        alice.send("".join("line %02d\n" % i for i in range(50)))
        for i in range(50):
            bob.expect("alice: line %02d\n" % i)
        bob.drain(0.2)

        # control characters (ESC sequences, our 0x01/0x02 markers) are stripped
        alice.send(b"\x01\x1b[31mevil\x02\n")
        got = bob.expect("evil")
        tail = got[got.index(b"alice:"):]
        assert b"\x01" not in tail and b"\x02" not in tail and b"\x1b" not in tail, repr(tail)

        # a "line" that never ends gets the client dropped
        alice.send(b"A" * 6000)
        alice.expect("line too long")
        bob.expect("* alice left the chat")
        bob.close()


def test_abrupt_disconnect_and_garbage_connections():
    with Server() as srv:
        alice = login("alice"); bob = login("bob")
        alice.expect("* bob joined the chat")

        # bob's connection is torn down with a TCP reset, no goodbye
        bob.s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        bob.close()
        alice.expect("* bob left the chat")

        # a plain-text (non-TLS) client and a silent client
        raw = socket.create_connection(("127.0.0.1", PORT))
        raw.sendall(b"GET / HTTP/1.0\r\n\r\n")
        raw.settimeout(6)
        try:
            data = raw.recv(1000)
        except OSError:
            data = b""
        raw.close()
        assert b"Welcome" not in data and b"Username" not in data, "plaintext client got service"
        socket.create_connection(("127.0.0.1", PORT)).close()
        time.sleep(0.3)

        assert srv.alive(), "server died"
        alice.send("still here?\n")
        carol = login("carol")
        assert "TLS handshake failed" in srv.log()
        alice.close(); carol.close()


def test_sigint_shuts_down_cleanly():
    with Server() as srv:
        alice = login("alice")
        srv.p.send_signal(signal.SIGINT)
        alice.expect("server is shutting down")
        assert srv.p.wait(timeout=5) == 0, "non-zero exit status"
        assert "shutting down" in srv.log()


def test_real_client_hides_password_and_restores_echo():
    with Server():
        pid, fd = pty.fork()
        if pid == 0:
            os.execv(CLIENT, [CLIENT, "127.0.0.1", str(PORT), CERT])

        def read_until(needle, timeout=6):
            import select
            buf = b""
            end = time.time() + timeout
            while needle not in buf:
                left = end - time.time()
                if left <= 0:
                    raise AssertionError("pty: timed out waiting for %r, got %r" % (needle, buf))
                if select.select([fd], [], [], left)[0]:
                    try:
                        d = os.read(fd, 4096)
                    except OSError:
                        break
                    if not d:
                        break
                    buf += d
            return buf

        def echo_on():
            return bool(termios.tcgetattr(fd)[3] & termios.ECHO)

        out = read_until(b"Username: ")
        assert b"secure connection" in out
        os.write(fd, b"pty_user\n")
        read_until(b"Choose a password")
        time.sleep(0.2)
        assert not echo_on(), "terminal echo is still on at the password prompt"
        os.write(fd, b"hunter2-pty\n")
        out = read_until(b"Welcome, pty_user")
        assert b"hunter2-pty" not in out, "password was echoed to the screen"
        time.sleep(0.2)
        assert echo_on(), "echo was not restored after login"
        os.write(fd, b"/quit\n")
        end = time.time() + 5
        status = None
        while time.time() < end:
            p, st = os.waitpid(pid, os.WNOHANG)
            if p:
                status = st
                break
            time.sleep(0.1)
        assert status is not None and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, \
            "client did not exit cleanly (%r)" % status
        os.close(fd)


def test_client_rejects_unknown_certificate():
    """A different (e.g. attacker's) certificate must not be trusted."""
    with Server() as srv:
        other = srv.path("other.crt")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", srv.path("other.key"), "-out", other],
                       check=True, capture_output=True)
        r = subprocess.run([CLIENT, "127.0.0.1", str(PORT), other], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=10)
        assert r.returncode != 0 and b"TLS handshake failed" in r.stderr, r.stderr


class ClientProc:
    """The real ./client program driven through pipes."""

    def __init__(self, cwd, port=PORT):
        self.cwd = cwd
        self.p = subprocess.Popen([CLIENT, "127.0.0.1", str(port), CERT], cwd=cwd,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, bufsize=0)
        self.buf = bytearray()
        self.lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        while True:
            d = os.read(self.p.stdout.fileno(), 65536)
            if not d:
                break
            with self.lock:
                self.buf += d

    def text(self):
        with self.lock:
            return bytes(self.buf).decode(errors="replace")

    def send(self, line):
        self.p.stdin.write((line + "\n").encode())
        self.p.stdin.flush()

    def expect(self, needle, timeout=8):
        end = time.time() + timeout * SLOW
        while time.time() < end:
            if needle in self.text():
                return self.text()
            time.sleep(0.03)
        raise AssertionError("client: timed out waiting for %r, got %r" % (needle, self.text()))

    def login(self, name, pw="secret-pw-1"):
        self.expect("Username: ")
        self.send(name)
        self.expect("Choose a password")
        self.send(pw)
        self.expect("Welcome, %s!" % name)
        time.sleep(0.4)          # let the client register its public key
        return self

    def quit(self):
        try:
            self.send("/quit")
            self.p.wait(timeout=5 * SLOW)
        except Exception:
            self.p.kill()
        time.sleep(0.2)
        if re.search(r"Invalid (read|write)|definitely lost|uninitialised", self.text()):
            raise AssertionError("valgrind reported problems in the client:\n" + self.text()[-1500:])


def clients(srv, *names):
    dirs = {n: tempfile.mkdtemp(prefix="cc_client_%s_" % n) for n in names}
    procs = [ClientProc(dirs[n]).login(n) for n in names]
    return procs, dirs


def test_rooms():
    with Server():
        alice = login("alice"); bob = login("bob")
        alice.expect("* bob joined the chat")
        alice.send("/join dev\n")
        alice.expect("you are now in #dev")
        bob.expect("* alice moved to #dev")
        bob.drain(0.2)

        bob.send("hello main room\n")                       # alice is in #dev now
        assert b"hello main room" not in alice.drain(0.5), "message crossed rooms"

        carol = login("carol")
        carol.send("/join DEV\n")                           # room names ignore case
        alice.expect("* carol joined #dev")
        carol.send("hi dev\n")
        alice.expect("carol: hi dev")
        assert b"hi dev" not in bob.drain(0.4), "message crossed rooms"

        alice.send("/rooms\n")
        alice.expect("rooms:")
        rest = alice.drain(0.4).decode()
        assert "#main(1)" in rest and "#dev(2)" in rest, rest
        alice.send("/users\n")
        alice.expect("online:")
        rest = alice.drain(0.4).decode()
        assert "alice(#dev)" in rest and "bob(#main)" in rest, rest
        alice.send("/join dev\n")
        alice.expect("already in that room")
        alice.send("/join bad!room\n")
        alice.expect("usage: /join")
        carol.send("/quit\n")
        alice.expect("* carol left the chat")                # the leave notice goes to carol's room
        assert b"carol left" not in bob.drain(0.4)
        alice.close(); bob.close()


def test_e2e_private_messages_with_real_clients():
    with Server() as srv:
        (alice, bob, carol), _ = clients(srv, "alice", "bob", "carol")
        alice.send("/msg bob e2e-secret-text-777")
        alice.expect("[pm to bob] e2e-secret-text-777")
        bob.expect("[pm from alice] e2e-secret-text-777")
        bob.send("/msg alice reply with spaces   and  more")
        alice.expect("[pm from bob] reply with spaces   and  more")
        time.sleep(0.4)
        assert "e2e-secret" not in carol.text(), "a third user saw a private message"
        alice.send("/msg ghost hello")
        alice.expect("[ghost is not online")
        alice.send("/msg bob")
        alice.expect("usage: /msg <user> <text>")
        assert "e2e-secret-text-777" not in srv.log() and "reply with spaces" not in srv.log()
        for c in (alice, bob, carol):
            c.quit()


def test_fingerprints_match_and_differ():
    with Server() as srv:
        (alice, bob, carol), _ = clients(srv, "alice", "bob", "carol")
        alice.send("/fingerprint bob")
        bob.send("/fingerprint alice")
        carol.send("/fingerprint alice")
        pat = r"safety code with (\w+): ([0-9a-f ]{29})"
        alice.expect("safety code with bob"); bob.expect("safety code with alice"); carol.expect("safety code with alice")
        ab = re.search(pat, alice.text()).group(2)
        ba = re.search(pat, bob.text()).group(2)
        ca = re.search(pat, carol.text()).group(2)
        assert ab == ba, "alice and bob see different codes: %r vs %r" % (ab, ba)
        assert ca != ab, "carol's code must differ from alice+bob's"
        print("      safety code alice<->bob: %s" % ab)
        for c in (alice, bob, carol):
            c.quit()


def test_file_transfer():
    with Server() as srv:
        (alice, bob, carol), dirs = clients(srv, "alice", "bob", "carol")
        files = {"small.txt": b"hello file\n", "multi.bin": os.urandom(5000),
                 "empty.dat": b"", "big.bin": os.urandom(300 * 1024), "we ird$name.txt": b"odd name"}
        for name, data in files.items():
            with open(os.path.join(dirs["alice"], name), "wb") as f:
                f.write(data)
        for name in files:
            alice.send("/send bob " + name.replace(" ", " "))
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
            if name == "we ird$name.txt":
                continue            # a space splits the path in the command; covered by test_file_name_safety
            bob.expect("[file received from alice: downloads/%s (%d bytes)]" % (safe, len(files[name])), timeout=30)
            got = open(os.path.join(dirs["bob"], "downloads", safe), "rb").read()
            assert got == files[name], "%s differs after transfer" % name
        alice.expect("[sent big.bin to bob]", timeout=30)

        alice.send("/send bob small.txt")                  # same name again: never overwrite
        bob.expect("downloads/small.txt.1 (11 bytes)")
        assert open(os.path.join(dirs["bob"], "downloads", "small.txt"), "rb").read() == files["small.txt"]

        with open(os.path.join(dirs["alice"], "toobig.bin"), "wb") as f:
            f.write(b"x" * (1024 * 1024 + 1))
        alice.send("/send bob toobig.bin"); alice.expect("too big")
        alice.send("/send bob nosuchfile"); alice.expect("cannot open nosuchfile")
        alice.send("/send bob ."); alice.expect("not a regular file")
        alice.send("/send ghost small.txt"); alice.expect("[ghost is not online")
        assert not os.path.exists(os.path.join(dirs["carol"], "downloads")), "carol received something"
        assert "hello file" not in srv.log()
        for c in (alice, bob, carol):
            c.quit()


def _crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:
        raise Skip("python 'cryptography' is not installed (pip install cryptography)")
    return X25519PrivateKey, X25519PublicKey, AESGCM, Encoding, PublicFormat


class Peer:
    """An independent Python implementation of the end-to-end protocol."""

    def __init__(self, chat):
        X, self.XP, self.AES, enc, fmt = _crypto()
        self.chat = chat
        self.priv = X.generate()
        self.pub = self.priv.public_key().public_bytes(enc.Raw, fmt.Raw)
        chat.expect(b"\x03READY\n")
        chat.send("/pubkey " + base64.b64encode(self.pub).decode() + "\n")
        time.sleep(0.3)

    def key(self, peer_pub):
        shared = self.priv.exchange(self.XP.from_public_bytes(peer_pub))
        lo, hi = sorted([self.pub, peer_pub])
        return hashlib.sha256(b"cipherchat-e2e-v1" + shared + lo + hi).digest()

    def seal(self, peer_pub, plain):
        nonce = os.urandom(12)
        return base64.b64encode(nonce + self.AES(self.key(peer_pub)).encrypt(nonce, plain, self.pub + peer_pub)).decode()

    def open_envelope(self, line):
        _, frm, pub, payload = line.decode().split()
        peer = base64.b64decode(pub)
        blob = base64.b64decode(payload)
        return frm, self.AES(self.key(peer)).decrypt(blob[:12], blob[12:], peer + self.pub)

    def getkey(self, name):
        self.chat.send("/getkey %s\n" % name)
        self.chat.expect(b"\x03KEY %s " % name.encode())
        val = self.chat.expect(b"\n").decode().strip()
        return base64.b64decode(val)


def test_e2e_interop_with_independent_implementation():
    """The C client and a separate Python implementation must agree on the format."""
    _crypto()
    with Server() as srv:
        (alice,), dirs = clients(srv, "alice")
        mal = Peer(login("mallory", pw="mallory-pw-1"))

        # C client -> Python: the server relays only ciphertext
        alice.send("/msg mallory hello-from-c-client")
        mal.chat.expect(b"\x03EMSG ")
        line = b"\x03EMSG " + mal.chat.expect(b"\n")
        assert b"hello-from-c-client" not in line, "plaintext in what the server relays"
        frm, plain = mal.open_envelope(line)
        assert frm == "alice" and plain == b"hello-from-c-client", (frm, plain)

        # Python -> C client; control characters from the other side are neutralised
        apub = mal.getkey("alice")
        mal.chat.send("/emsg alice %s\n" % mal.seal(apub, b"hi \x1b[31mred\x01\x02\x03 end"))
        out = alice.expect("[pm from mallory] hi ")
        seg = out[out.index("[pm from mallory]"):]
        assert "\x1b" not in seg and "\x01" not in seg and "\x02" not in seg, repr(seg)
        assert "red" in seg and "end" in seg

        # tampered / wrong-key messages are rejected, never shown
        blob = bytearray(base64.b64decode(mal.seal(apub, b"genuine")))
        blob[20] ^= 1
        mal.chat.send("/emsg alice %s\n" % base64.b64encode(bytes(blob)).decode())
        alice.expect("could not decrypt a message from mallory")
        mal.chat.send("/emsg alice %s\n" % mal.seal(os.urandom(32), b"wrong key"))
        end = time.time() + 5 * SLOW
        while alice.text().count("could not decrypt") < 2 and time.time() < end:
            time.sleep(0.05)
        assert alice.text().count("could not decrypt") == 2, alice.text()
        assert "[pm from mallory] genuine" not in alice.text()
        assert "[pm from mallory] wrong key" not in alice.text()

        # file with a hostile name ends up inside downloads/ under a harmless name
        hdr = b"deadbeef\n../../etc/evil\n0\n1\n"
        mal.chat.send("/efile alice %s\n" % mal.seal(apub, hdr + b"payload"))
        alice.expect("[file received from mallory: downloads/")
        names = os.listdir(os.path.join(dirs["alice"], "downloads"))
        assert len(names) == 1 and "/" not in names[0] and not names[0].startswith("."), names
        assert open(os.path.join(dirs["alice"], "downloads", names[0]), "rb").read() == b"payload"
        assert sorted(os.listdir(dirs["alice"])) == ["downloads"]
        print("      hostile file name saved as downloads/%s" % names[0])
        alice.quit()
        mal.chat.close()


def test_fork_server_uses_one_process_per_client():
    if not IS_FORK:
        raise Skip("only meaningful for ./server_fork")
    with Server() as srv:
        a = login("alice"); b = login("bob"); c = login("carol")
        kids = subprocess.run(["pgrep", "-P", str(srv.p.pid)], capture_output=True, text=True).stdout.split()
        assert len(kids) == 3, "expected 3 child processes, found %r" % kids
        print("      3 clients -> 3 child processes of the server (%s)" % ",".join(kids))
        a.close(); b.close()
        time.sleep(0.8)
        st = subprocess.run(["ps", "--ppid", str(srv.p.pid), "-o", "stat="], capture_output=True, text=True).stdout.split()
        assert len(st) == 1 and "Z" not in "".join(st), "children not reaped (zombies?): %r" % st
        c.close()


# --------------------------------------------------------------------------
def main():
    for needed in (SERVER, CLIENT):
        if not os.path.exists(needed):
            sys.exit("build first: make")
    subprocess.run(["make", "-s", "certs"], cwd=HERE, check=True)

    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    if len(sys.argv) > 1:                        # python3 test_cipherchat.py rooms file
        tests = [(n, f) for n, f in tests if any(k in n for k in sys.argv[1:])]
    print("server under test: %s" % os.path.basename(SERVER))
    failed = 0
    for name, fn in tests:
        t0 = time.time()
        try:
            fn()
            print("PASS  %-52s %.1fs" % (name, time.time() - t0))
        except Skip as e:
            print("SKIP  %-52s %s" % (name, e))
        except Exception:
            failed += 1
            print("FAIL  %s" % name)
            traceback.print_exc()
    print("\n%d/%d tests passed" % (len(tests) - failed, len(tests)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
