import base64
import json
import socket
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pyotp
import pytest

from valet.broker import Broker

TOKEN = "tok_test_123"
PASSWORD = "P@ss-test-456"
OUTSIDE = "outside-secret-789"
SEED = pyotp.random_base32()
COLLECTION = "col-agent"


def all_secrets():
    otp = pyotp.TOTP(SEED)
    codes = {otp.at(time.time() + d) for d in (-30, 0, 30)}
    b64 = {base64.b64encode(f"{u}:{PASSWORD}".encode()).decode() for u in ("svc-user", "web-user", "plain-user")}
    return [TOKEN, PASSWORD, "P%40ss-test-456", OUTSIDE, SEED, *codes, *b64]


def assert_clean(obj):
    text = obj if isinstance(obj, str) else json.dumps(obj)
    for s in all_secrets():
        assert s not in text, f"secret leaked: {text[:300]}"


def item(name, uris, password, username="svc-user", totp="", fields=None, collections=(COLLECTION,)):
    return {"id": f"id-{name}", "name": name, "type": 1, "collectionIds": list(collections),
            "fields": [{"name": k, "value": v, "type": 0} for k, v in (fields or {}).items()],
            "login": {"username": username, "password": password, "totp": totp,
                      "uris": [{"match": None, "uri": u} for u in uris]}}


class FakeVault:
    def __init__(self, items):
        self._items = items

    def sync(self):
        pass

    def collection_id(self):
        return COLLECTION

    def items(self, collection_id):
        return self._items  # ignores the filter on purpose: the broker must scope by itself


class Approver:
    def __init__(self, answer="once"):
        self.answer, self.calls = answer, []

    def __call__(self, name, operation, host):
        self.calls.append((name, operation, host))
        return self.answer


# --- local test server: echo endpoint plus a small login site -----------------------------------

LOGIN = """<title>Sign in</title><input type=text name=q placeholder=search>
<form method=post action=/login><input type=text name=user><input type=password name=pass>
<button type=button>show</button><button type=submit>Sign in</button></form>"""
OTP_PAGE = """<title>Code</title><form method=post action=/otp>
<input name=code autocomplete=one-time-code><button type=submit>Verify</button></form>"""


class Handler(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *args):
        pass

    def send(self, code, body, ctype="application/json", **headers):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers.items():
            self.send_header(k.replace("_", "-"), v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, to, cookie=None):
        extra = {"Set_Cookie": f"session={cookie}; Path=/"} if cookie else {}
        self.send(302, "", Location=to, **extra)

    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def route(self):
        path = urlsplit(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        form = {k: v[0] for k, v in parse_qs(body).items()}
        Handler.seen.append({"path": self.path, "headers": dict(self.headers), "body": body})
        cookie = self.headers.get("Cookie") or ""
        html = "text/html"
        if (self.command, path) == ("GET", "/login"):
            return self.send(200, LOGIN, html)
        if (self.command, path) == ("POST", "/login"):
            if form.get("pass") != PASSWORD or form.get("user") not in ("web-user", "plain-user"):
                return self.send(200, LOGIN, html)
            return self.redirect("/otp", "half") if form["user"] == "web-user" else self.redirect("/welcome", "ok")
        if (self.command, path) == ("GET", "/otp"):
            return self.send(200, OTP_PAGE, html)
        if (self.command, path) == ("POST", "/otp"):
            if "session=half" in cookie and pyotp.TOTP(SEED).verify(form.get("code", ""), valid_window=1):
                return self.redirect("/welcome", "ok")
            return self.send(200, OTP_PAGE, html)
        if path == "/welcome":
            if "session=ok" not in cookie:
                return self.redirect("/login")
            return self.send(200, "<title>Welcome</title><h1>Welcome</h1>", html)
        if path == "/elsewhere":
            return self.redirect(f"http://localhost:{self.server.server_port}/login")
        if path == "/slow":
            time.sleep(2)
        if path == "/big":
            return self.send(200, "x" * 50_000, "text/plain")
        self.send(200, json.dumps({"path": self.path, "headers": dict(self.headers), "body": body}))


@pytest.fixture(scope="session")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def cdp(tmp_path_factory):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        exe = p.chromium.executable_path
    port = free_port()
    proc = subprocess.Popen([exe, "--headless=new", f"--remote-debugging-port={port}", "--no-first-run",
                             f"--user-data-dir={tmp_path_factory.mktemp('profile')}", "about:blank"])
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(url + "/json/version", timeout=1)
            break
        except OSError:
            time.sleep(0.1)
    yield url
    proc.kill()


@pytest.fixture
def items(server):
    base = server
    return [
        item("api-bearer", [base], TOKEN),  # no broker_auth: http_request defaults to bearer
        item("api-basic", [base], PASSWORD, fields={"broker_auth": "basic"}),
        item("api-header", [base], TOKEN, fields={"broker_auth": "header:X-Api-Key"}),
        item("api-query", [base], TOKEN, fields={"broker_auth": "query:api_key"}),
        item("api-daily", [base], TOKEN, fields={"broker_approval": "daily"}),
        item("api-always", [base], TOKEN, fields={"broker_approval": "always"}),
        item("remote", ["https://api.example.com", "https://*.example.org/x"], TOKEN),
        item("web", [base + "/login"], PASSWORD, username="web-user", totp=SEED),
        item("web-plain", [base + "/login"], PASSWORD, username="plain-user", fields={"broker_auth": "form"}),
        item("outside", [base], OUTSIDE, collections=("col-other",)),
    ]


@pytest.fixture
def approver():
    return Approver()


@pytest.fixture
def broker(items, approver, tmp_path, request):
    cdp_url = request.getfixturevalue("cdp") if "cdp" in request.fixturenames else "http://127.0.0.1:1"
    return Broker(FakeVault(items), tmp_path, approver=approver, cdp=cdp_url)
