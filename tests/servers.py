"""HTTP fixture servers for the gitleak end-to-end harness (stdlib only).

Each server exposes a local directory under a URL prefix (default /app) and can
behave like one of the hostile/broken servers the tool must survive:

  static    plain static file server, directory listing disabled (404 on dirs)
  soft404   every path returns 200 text/html "not found <path>" (scan trap)
  blocks    listed path prefixes return 403 (e.g. .git/index or .git/objects/)
  overrides exact paths return canned responses (e.g. HTML head/config)

All servers bind 127.0.0.1:0 (ephemeral port) and are always stopped via the
context manager / atexit registry.
"""

from __future__ import annotations

import atexit
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

TEXT_TYPES = {
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".json": "application/json",
    ".css": "text/css",
    ".js": "application/javascript",
}

_LIVE = set()
_LIVE_LOCK = threading.Lock()


def _stop_all():
    with _LIVE_LOCK:
        servers = list(_LIVE)
    for srv in servers:
        try:
            srv.stop()
        except Exception:
            pass


atexit.register(_stop_all)


class FixtureConfig:
    """Routing rules for one fixture server."""

    def __init__(self, root_dir, prefix="/app", mode="static", overrides=None, blocks=None):
        self.root_dir = Path(root_dir)
        self.prefix = prefix.rstrip("/") if prefix else ""
        self.mode = mode
        self.overrides = {}
        for key, value in (overrides or {}).items():
            self.overrides[key.lstrip("/")] = value
        self.blocks = [(p.lstrip("/"), status) for p, status in (blocks or [])]
        self.log = []
        self.lock = threading.Lock()

    def record(self, method, raw_path, status, length):
        with self.lock:
            self.log.append((method, raw_path, status, length))

    def log_snapshot(self):
        with self.lock:
            return list(self.log)

    def resolve(self, raw_path):
        """Return (status, content_type, body_bytes) for a request path."""
        path = urlsplit(raw_path).path
        try:
            path = unquote(path)
        except Exception:
            pass

        if self.mode == "soft404":
            # Trap server: every path (even outside the mount) is a 200 HTML page.
            body = ("<!doctype html><html><head><title>not found</title></head>"
                    "<body>not found " + path + "</body></html>").encode("utf-8")
            return 200, "text/html; charset=utf-8", body

        if self.prefix and not (path == self.prefix or path.startswith(self.prefix + "/")):
            return 404, "text/plain; charset=utf-8", b"outside fixture mount"
        rel = path[len(self.prefix):].lstrip("/")

        override = self.overrides.get(rel)
        if override is not None:
            return override

        for pfx, status in self.blocks:
            if rel == pfx or rel.startswith(pfx):
                return status, "text/plain; charset=utf-8", ("blocked: " + rel).encode("utf-8")

        if rel == "" or rel.endswith("/"):
            return 404, "text/plain; charset=utf-8", b"not found"

        parts = [p for p in rel.split("/") if p]
        if any(p in (".", "..") for p in parts):
            return 400, "text/plain; charset=utf-8", b"bad path"

        target = self.root_dir.joinpath(*parts)
        try:
            root_resolved = self.root_dir.resolve()
            if not target.resolve().is_relative_to(root_resolved):
                return 404, "text/plain; charset=utf-8", b"not found"
        except OSError:
            return 404, "text/plain; charset=utf-8", b"not found"

        if target.is_dir():
            # directory listing disabled on purpose
            return 404, "text/plain; charset=utf-8", b"not found"
        if not target.is_file():
            return 404, "text/plain; charset=utf-8", b"not found"
        try:
            data = target.read_bytes()
        except OSError:
            return 500, "text/plain; charset=utf-8", b"unreadable"
        ctype = TEXT_TYPES.get(target.suffix.lower(), "application/octet-stream")
        return 200, ctype, data


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "gitleak-e2e-fixture/1.0"

    def log_message(self, fmt, *args):  # silence per-request stderr logging
        pass

    def do_GET(self):
        self._respond("GET")

    def do_HEAD(self):
        self._respond("HEAD")

    def do_POST(self):
        self._respond("POST")

    def _respond(self, method):
        cfg = self.server.fixture_config
        status, ctype, body = cfg.resolve(self.path)
        cfg.record(method, self.path, status, len(body))
        try:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if method != "HEAD" and body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, fixture_config):
        self.fixture_config = fixture_config
        super().__init__(addr, handler)


class FixtureServer:
    """A stoppable local HTTP fixture server."""

    def __init__(self, root_dir, prefix="/app", mode="static", overrides=None, blocks=None, name=""):
        self.config = FixtureConfig(root_dir, prefix=prefix, mode=mode, overrides=overrides, blocks=blocks)
        self.name = name or mode
        self.port = None
        self._httpd = None
        self._thread = None

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        if self._httpd is not None:
            return self
        self._httpd = _Server(("127.0.0.1", 0), _Handler, self.config)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="fixture-" + self.name,
            daemon=True,
        )
        self._thread.start()
        with _LIVE_LOCK:
            _LIVE.add(self)
        return self

    def stop(self):
        httpd, thread = self._httpd, self._thread
        self._httpd = None
        self._thread = None
        with _LIVE_LOCK:
            _LIVE.discard(self)
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception:
                pass
            try:
                httpd.server_close()
            except Exception:
                pass
        if thread is not None:
            thread.join(timeout=5.0)

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    # -- addressing --------------------------------------------------------
    @property
    def base_url(self):
        if self.port is None:
            raise RuntimeError("fixture server not started")
        return "http://127.0.0.1:" + str(self.port)

    def url(self, suffix=""):
        base = self.base_url + self.config.prefix
        if not suffix:
            return base
        return base + "/" + suffix.lstrip("/")

    # -- introspection -----------------------------------------------------
    def log_snapshot(self):
        return self.config.log_snapshot()

    def request_paths(self):
        return [entry[1] for entry in self.config.log_snapshot()]

    def summary(self):
        entries = self.config.log_snapshot()
        statuses = {}
        for _m, _p, status, _n in entries:
            statuses[status] = statuses.get(status, 0) + 1
        return {
            "name": self.name,
            "port": self.port,
            "requests": len(entries),
            "by_status": statuses,
        }


def dead_port(host="127.0.0.1"):
    """Return a port on which nothing is listening (best effort)."""
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, 0))
        return s.getsockname()[1]
    finally:
        s.close()


# ---------------------------------------------------------------------------
# self test
# ---------------------------------------------------------------------------

def _selftest():
    import tempfile
    import urllib.error
    import urllib.request

    root = Path(__file__).resolve().parent / "_tmp" / "selftest-servers"
    if root.exists():
        import shutil
        shutil.rmtree(str(root))
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "HEAD").write_bytes(b"ref: refs/heads/main\n")
    (root / ".git" / "config").write_bytes(b"[core]\n\tbare = false\n")
    (root / "nested").mkdir()
    (root / "nested" / "file.txt").write_bytes(b"hello\n")

    def fetch(url, method="GET"):
        req = urllib.request.Request(url, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    try:
        with FixtureServer(root, name="static") as srv:
            status, body = fetch(srv.url(".git/HEAD"))
            assert status == 200 and body == b"ref: refs/heads/main\n", (status, body)
            status, _body = fetch(srv.url("does-not-exist"))
            assert status == 404, status
            status, _body = fetch(srv.url("nested"))
            assert status == 404, "directory listing must be disabled: " + str(status)
            status, _body = fetch(srv.url(".git/HEAD"), method="HEAD")
            assert status == 200, status

        with FixtureServer(root, mode="soft404", name="soft404") as srv:
            status, body = fetch(srv.base_url + "/.git/HEAD")
            assert status == 200 and b"not found" in body, (status, body[:80])

        with FixtureServer(root, blocks=[(".git/objects/", 403)], name="objects") as srv:
            assert fetch(srv.url(".git/HEAD"))[0] == 200
            assert fetch(srv.url(".git/objects/ab/cdef"))[0] == 403

        with FixtureServer(
            root,
            overrides={
                ".git/HEAD": (200, "text/html; charset=utf-8", b"<html>login</html>"),
                ".git/config": (200, "text/html; charset=utf-8", b"<html>generic</html>"),
            },
            name="fakehead",
        ) as srv:
            status, body = fetch(srv.url(".git/HEAD"))
            assert status == 200 and b"login" in body, (status, body)
            assert fetch(srv.url(".git/config"))[1] == b"<html>generic</html>"

        port = dead_port()
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            connected = s.connect_ex(("127.0.0.1", port))
        finally:
            s.close()
        assert connected != 0, "dead_port returned a live port"
        print("SELFTEST PASS: static/soft404/blocks/overrides + dead_port ok")
        return 0
    finally:
        import shutil
        if root.exists():
            shutil.rmtree(str(root), ignore_errors=True)


if __name__ == "__main__":
    import sys

    sys.exit(_selftest())
