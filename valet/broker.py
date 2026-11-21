"""Broker core: item policy, host allowlist, approval, redaction, audit, and the operations."""
import asyncio
import base64
import ctypes
import datetime as dt
import json
import re
import socket
import subprocess
import time
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit

import httpx
import pyotp
from httpx_ntlm import HttpNtlmAuth
from playwright.async_api import TimeoutError as PWTimeout, async_playwright

MAX_BODY = 20_000
KEEP_HEADERS = {"content-type", "content-length", "location", "www-authenticate", "retry-after",
                "etag", "last-modified", "x-request-id", "x-ratelimit-remaining"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
AUTH = {"http_request": "bearer", "browser_login": "form"}  # default broker_auth per tool
APPROVAL = {"http_request": "never", "browser_login": "daily", "ssh_exec": "daily", "win_exec": "daily",
            "sql_query": "daily", "rdp_open": "never", "run": "daily"}  # default broker_approval per tool
PORTS = {"ssh": 22, "rdp": 3389, "winrm": 5985, "winrms": 5986, "mssql": 1433}  # non-web URI schemes
SCHEME_TOOLS = {"ssh": "ssh_exec", "rdp": "rdp_open", "winrm": "win_exec", "winrms": "win_exec", "mssql": "sql_query"}
BROWSER_AUTH = {"form", "ntlm"}  # ntlm = Windows sign-in (Negotiate/NTLM challenge), answered by the browser

PASS_SEL = "input[type=password]"
USER_SEL = ("input[autocomplete=username], input[type=email], input[name*=user i], input[id*=user i], "
            "input[name*=login i], input[name*=email i], input[type=text]")
BEFORE_PASS = "xpath=preceding::input[@type='text' or @type='email' or not(@type)]"
SUBMIT_SEL = "button[type=submit], input[type=submit]"
OTP_SEL = ("input[autocomplete=one-time-code], input[name*=otp i], input[id*=otp i], input[name*=totp i], "
           "input[name*=code i], input[id*=code i], input[inputmode=numeric]")


class Refused(Exception):
    """Policy refusal. The message never contains secrets."""


class Denied(Refused):
    """The user said no in the approval dialog."""


@dataclass
class Cred:
    id: str
    name: str
    username: str
    password: str
    totp: str
    uris: list
    fields: dict

    @classmethod
    def from_item(cls, item):
        login = item.get("login") or {}
        return cls(item["id"], item["name"], login.get("username") or "", login.get("password") or "",
                   login.get("totp") or "", [u["uri"] for u in login.get("uris") or [] if u.get("uri")],
                   {f["name"].strip().lower(): (f.get("value") or "").strip()
                    for f in item.get("fields") or [] if f.get("name")})

    @property
    def hosts(self):
        """Hosts of the web (http/https or scheme-less) URIs: where http_request and browser_login may go."""
        out = []
        for u in self.uris:
            p = urlsplit(u if "://" in u else "https://" + u)
            if p.hostname and p.scheme.lower() not in PORTS:
                out.append(p.hostname.lower())
        return out

    @property
    def endpoints(self):
        """(scheme, host, port) of the ssh://, rdp://, winrm://, winrms:// and mssql:// URIs."""
        out = []
        for u in self.uris:
            p = urlsplit(u)
            if p.scheme.lower() in PORTS and p.hostname:
                out.append((p.scheme.lower(), p.hostname.lower(), p.port or PORTS[p.scheme.lower()]))
        return out

    def endpoint(self, schemes, host=None):
        """The item's endpoint for one of schemes (and host, if given). Credentials only go there."""
        found = [e for e in self.endpoints if e[0] in schemes and (not host or e[1] == host.lower())]
        if not found:
            listed = ", ".join(f"{s}://{h}:{p}" for s, h, p in self.endpoints) or "none"
            raise Refused(f"credential {self.name!r} has no {'/'.join(schemes)}:// URI"
                          f"{f' for host {host!r}' if host else ''} (its endpoints: {listed})")
        return found[0]

    def auth(self, tool):
        return self.fields.get("broker_auth") or AUTH[tool]

    def approval(self, tool):
        return self.fields.get("broker_approval") or APPROVAL[tool]

    def flag(self, name):
        return self.fields.get(name, "").lower() in ("yes", "true", "1")

    def otp(self):
        if not self.totp:
            return None
        if self.totp.startswith("otpauth://"):
            return pyotp.parse_uri(self.totp)
        return pyotp.TOTP(self.totp.replace(" ", "").upper())

    def secrets(self):
        s = {self.password, self.totp}
        if self.password:
            s.add(base64.b64encode(f"{self.username}:{self.password}".encode()).decode())
        try:
            otp = self.otp()
            if otp:
                s.add(otp.secret)
                s |= {otp.at(time.time() + d) for d in (-30, 0, 30)}
        except Exception:
            pass  # a malformed seed is still redacted as the raw string above
        for v in list(s):
            s |= {quote(v, safe=""), quote_plus(v), json.dumps(v)[1:-1]}
        return sorted((v for v in s if v), key=len, reverse=True)


def redactor(named):
    """named: [(name, [secret, ...])]. Returns a str -> str function that replaces each secret with
    [REDACTED:<name>], longest first so a secret containing another one is caught whole."""
    pairs = sorted(((s, n) for n, secrets in named for s in secrets if s), key=lambda p: len(p[0]), reverse=True)
    if not pairs:
        return lambda text: text
    tags = {s.lower(): f"[REDACTED:{n}]" for s, n in reversed(pairs)}
    pattern = re.compile("|".join(re.escape(s) for s, _ in pairs), re.I)
    return lambda text: pattern.sub(lambda m: tags[m.group(0).lower()], text)


def scrub(obj, cred):
    """Replace every secret of cred in every string inside obj with [REDACTED:<name>]."""
    if not cred:
        return obj
    redact = redactor([(cred.name, cred.secrets())])

    def walk(o):
        if isinstance(o, str):
            return redact(o)
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o
    return walk(obj)


def not_allowed(cred, url):
    """Return why url may not receive cred, or None if it may."""
    if not url:
        return "no URL given and the item has no login URI"
    u = httpx.URL(url)  # same parser that sends the request, so the checked host is the contacted host
    host = u.host.lower()
    http_ok = host in LOCAL_HOSTS or cred.flag("broker_allow_http")
    if u.scheme != "https" and not (u.scheme == "http" and http_ok):
        return (f"{u.scheme or 'no'} scheme not allowed; use https (http only for localhost, "
                "or items with broker_allow_http=yes)")
    if not any(host == h or (h.startswith("*.") and host.endswith(h[1:])) for h in cred.hosts):
        return f"host {host!r} is not allowed for credential {cred.name!r} (allowed: {', '.join(cred.hosts) or 'none'})"
    return None


def check_url(cred, url):
    if reason := not_allowed(cred, url):
        raise Refused(reason)
    return httpx.URL(url).host


def messagebox_approver(cred_name, operation, host):
    text = (f"Credential: {cred_name}\nOperation: {operation}\nTarget: {host}\n\n"
            "Yes = allow until midnight\nNo = allow once\nCancel = deny")
    # MB_YESNOCANCEL | MB_ICONWARNING | MB_DEFBUTTON3 (Enter = deny) | MB_SETFOREGROUND | MB_TOPMOST
    r = ctypes.windll.user32.MessageBoxW(None, text, "valet approval", 0x3 | 0x30 | 0x200 | 0x10000 | 0x40000)
    return {6: "today", 7: "once"}.get(r, "deny")


class Broker:
    def __init__(self, backend, home, approver=messagebox_approver, cdp="http://127.0.0.1:9333"):
        self.backend, self.approver, self.cdp = backend, approver, cdp
        self.home = Path(home)
        self.home.mkdir(parents=True, exist_ok=True)
        self.approved = {}  # (cred id, tool) -> date of "allow today"
        self.synced = False

    def creds(self):
        if not self.synced:
            self.backend.sync()
            self.synced = True
        cid = self.backend.collection_id()
        return [Cred.from_item(i) for i in self.backend.items(cid)
                if i.get("type") == 1 and cid in (i.get("collectionIds") or [])]

    def find(self, ref):
        for _ in range(2):
            found = [c for c in self.creds() if ref in (c.id, c.name)]
            if len(found) > 1:
                raise Refused(f"{len(found)} credentials are named {ref!r}; pass the id instead")
            if found:
                return found[0]
            self.synced = False  # maybe added since the last sync: sync once and retry
        raise Refused(f"no credential {ref!r} in the broker collection; call list_credentials")

    def audit(self, entry):
        entry = {"ts": dt.datetime.now().astimezone().isoformat(timespec="seconds"), **entry}
        with open(self.home / "audit.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    async def approve(self, cred, tool, host):
        policy = cred.approval(tool)
        if policy not in ("never", "daily", "always"):
            raise Refused(f"credential {cred.name!r} has unknown broker_approval {policy!r}")
        key, today = (cred.id, tool), dt.date.today()
        if policy == "never" or (policy == "daily" and self.approved.get(key) == today):
            return
        answer = await asyncio.to_thread(self.approver, cred.name, tool, host)
        if answer not in ("today", "once"):
            raise Denied(f"the user denied {tool} with credential {cred.name!r} on {host}")
        if answer == "today" and policy == "daily":
            self.approved[key] = today

    async def _run(self, tool, ref, method, url, fn):
        """Resolve the credential, run fn(cred, url), audit, and redact whatever goes back."""
        cred, entry = None, {"tool": tool, "credential": ref, "method": method}
        try:
            cred = self.find(ref)
            entry["credential"] = cred.name
            url = url or (cred.uris[0] if cred.uris else "")
            parts = urlsplit(url)
            entry["target"] = f"{parts.hostname or ''}{parts.path}"
            result = await fn(cred, url, entry)
            entry["result"] = result.get("status")
            return scrub(result, cred)
        except Denied as e:
            entry["result"], err = "denied", str(e)
        except Refused as e:
            entry["result"], err = "refused", str(e)
        except Exception as e:  # first line only: browser errors carry long call logs
            entry["result"] = f"error:{type(e).__name__}"
            err = f"{type(e).__name__}: {(str(e).splitlines() or [''])[0]}"[:500]
        finally:
            self.audit(entry)
        return scrub({"error": err}, cred)

    async def _remote(self, tool, ref, schemes, host, call):
        """Approve, then run call(cred, scheme, host, port) in a thread against the item's endpoint."""
        async def go(cred, _, entry):
            scheme, h, port = cred.endpoint(schemes, host)
            entry["target"] = f"{scheme}://{h}:{port}"
            await self.approve(cred, tool, h)
            return await asyncio.to_thread(call, cred, scheme, h, port)
        return await self._run(tool, ref, schemes[0].upper(), None, go)

    def list_credentials(self):
        try:
            out = []
            for c in self.creds():
                tools = {}
                if c.hosts:
                    tools = {t: {"auth": c.auth(t), "approval": c.approval(t)} for t in AUTH}
                    if c.auth("browser_login") not in BROWSER_AUTH:
                        del tools["browser_login"]
                    if c.auth("http_request") == "form":
                        del tools["http_request"]
                for scheme, host, port in c.endpoints:
                    t = SCHEME_TOOLS[scheme]
                    tools.setdefault(t, {"approval": c.approval(t), "targets": []})["targets"].append(
                        f"{scheme}://{host}:{port}")
                out.append({"name": c.name, "id": c.id, "hosts": c.hosts, "tools": tools, "totp": bool(c.totp)})
            return {"credentials": out}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {(str(e).splitlines() or [''])[0]}"[:500]}

    async def http_request(self, credential, method, url, headers=None, body=None, json_body=None, timeout=30):
        async def go(cred, url, entry):
            return await self._http(cred, method, url, headers, body, json_body, timeout)
        return await self._run("http_request", credential, method.upper(), url, go)

    async def _http(self, cred, method, url, headers=None, body=None, json_body=None, timeout=30, approve=True):
        host = check_url(cred, url)
        auth, target = cred.auth("http_request"), httpx.URL(url)
        hdrs, ntlm = httpx.Headers(headers or {}), None
        if auth == "ntlm":
            ntlm = HttpNtlmAuth(cred.username, cred.password)
        elif auth == "bearer":
            hdrs["Authorization"] = f"Bearer {cred.password}"
        elif auth == "basic":
            hdrs["Authorization"] = "Basic " + base64.b64encode(f"{cred.username}:{cred.password}".encode()).decode()
        elif auth.startswith("header:"):
            hdrs[auth[7:].strip()] = cred.password
        elif auth.startswith("query:"):
            target = target.copy_set_param(auth[6:].strip(), cred.password)
        else:
            raise Refused(f"credential {cred.name!r} has broker_auth={auth!r}, which http_request cannot use")
        if approve:
            await self.approve(cred, "http_request", host)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            r = await client.request(method.upper(), target, headers=hdrs, content=body, json=json_body,
                                     auth=ntlm or httpx.USE_CLIENT_DEFAULT)
        text = r.text
        out = {"status": r.status_code,
               "headers": {k: v for k, v in r.headers.items() if k.lower() in KEEP_HEADERS},
               "body": text[:MAX_BODY]}
        if len(text) > MAX_BODY:
            out["truncated"] = f"body truncated to {MAX_BODY} of {len(text)} characters"
        return out

    async def ssh_exec(self, credential, command, host=None, timeout=60):
        return await self._remote("ssh_exec", credential, ("ssh",), host,
                                  lambda c, s, h, p: ssh_run(c, h, p, command, timeout))

    async def win_exec(self, credential, command, host=None, timeout=60):
        return await self._remote("win_exec", credential, ("winrm", "winrms"), host,
                                  lambda c, s, h, p: winrm_run(c, s, h, p, command, timeout))

    async def sql_query(self, credential, query, database=None, host=None, max_rows=200, timeout=60):
        return await self._remote("sql_query", credential, ("mssql",), host,
                                  lambda c, s, h, p: sql_run(c, h, p, query, database, timeout, max_rows))

    async def rdp_open(self, credential, host=None):
        return await self._remote("rdp_open", credential, ("rdp",), host, lambda c, s, h, p: rdp_run(c, h, p))

    async def check_credentials(self, names=None, concurrency=8):
        """Try each item's sign-in on each of its URIs (one approval for the whole batch); report ok/failed."""
        creds = [c for c in self.creds() if not names or c.name in names or c.id in names]
        if not creds:
            return {"error": "no matching credentials in the broker collection"}
        answer = await asyncio.to_thread(self.approver, f"{len(creds)} credentials", "check_credentials",
                                         "the hosts listed on each item")
        if answer not in ("today", "once"):
            return {"error": "the user denied check_credentials"}
        gate = asyncio.Semaphore(concurrency)

        async def one(cred, uri):
            async with gate:
                try:
                    result, detail = await self._check(cred, uri)
                except Exception as e:
                    result, detail = "failed", f"{type(e).__name__}: {(str(e).splitlines() or [''])[0]}"[:300]
            self.audit({"tool": "check_credentials", "credential": cred.name, "target": uri.split("?")[0],
                        "result": result})
            return scrub({"credential": cred.name, "uri": uri, "result": result, "detail": detail}, cred)

        checks = [one(c, u) for c in creds for u in c.uris] + [
            asyncio.sleep(0, {"credential": c.name, "uri": "", "result": "skipped", "detail": "item has no URI"})
            for c in creds if not c.uris]
        results = await asyncio.gather(*checks)
        counts = {k: sum(r["result"] == k for r in results) for k in ("ok", "failed", "skipped")}
        return {"summary": counts, "results": results}

    async def _check(self, cred, uri):
        if "://" not in uri:  # bare host, e.g. from an import: see which sign-in services answer
            host = urlsplit("//" + uri).hostname
            found = [s for s, port in (("ssh", 22), ("winrm", 5985), ("mssql", 1433), ("rdp", 3389))
                     if await asyncio.to_thread(port_open, host, port)]
            if not found:
                return "skipped", "no ssh, winrm, mssql or rdp port open; give the URI a scheme"
            parts, ok = [], False
            for s in found:
                if s == "rdp":
                    parts.append("rdp port open (not testable)")
                    continue
                try:
                    detail = await asyncio.to_thread(login_probe, cred, s, host, PORTS[s])
                    ok = True
                    parts.append(f"{s} ok ({detail})")
                except Exception as e:
                    parts.append(f"{s} failed ({type(e).__name__}: {(str(e).splitlines() or [''])[0][:120]})")
            hint = "; set the URI to e.g. ssh://" + host if ok else ""
            return ("ok" if ok else "failed"), "; ".join(parts) + hint
        scheme = urlsplit(uri).scheme.lower()
        if scheme in ("http", "https"):
            if cred.auth("http_request") == "form":
                return "skipped", "web form login (check it with browser_login)"
            code = (await self._http(cred, "GET", uri, timeout=15, approve=False))["status"]
            return ("failed" if code in (401, 403) else "ok"), f"HTTP {code}"
        if scheme == "rdp":
            return "skipped", "RDP sign-in cannot be tested without opening a session"
        if scheme in PORTS:
            _, host, port = cred.endpoint((scheme,), urlsplit(uri).hostname)
            return "ok", await asyncio.to_thread(login_probe, cred, scheme, host, port)
        return "skipped", f"unknown scheme {scheme!r}"

    async def resolve(self, refs, what):
        """For scripts: refs maps NAME -> "valet://<item>/<field>" (field: password, username, totp, uri or a
        custom field name). Asks approval once per item (tool "run", target `what`), audits, and returns
        ({NAME: value}, redact) where redact(text) removes every resolved secret from text."""
        values, named, creds, result = {}, [], {}, "error"
        try:
            for env, ref in refs.items():
                item, _, field = ref[len("valet://"):].rpartition("/")
                if not ref.startswith("valet://") or not item or not field:
                    raise Refused(f"{env}: expected valet://<item>/<field>, got {ref!r}")
                if item not in creds:
                    creds[item] = self.find(item)
                    await self.approve(creds[item], "run", what)
                cred, f = creds[item], field.lower()
                if f == "password":
                    value = cred.password
                elif f == "username":
                    value = cred.username
                elif f == "uri":
                    value = cred.uris[0] if cred.uris else ""
                elif f == "totp":
                    value = cred.otp().now() if cred.totp else ""
                elif f in cred.fields:
                    value = cred.fields[f]
                else:
                    raise Refused(f"{env}: item {cred.name!r} has no field {field!r}")
                values[env] = value
                named.append((cred.name, cred.secrets() + ([] if f in ("username", "uri") else [value])))
            result = "ok"
            return values, redactor(named)
        except Refused as e:
            result = "denied" if isinstance(e, Denied) else "refused"
            raise
        finally:
            self.audit({"tool": "run", "credential": ", ".join(c.name for c in creds.values()) or "-",
                        "target": what[:200], "result": result})

    async def browser_login(self, credential, url=None):
        explicit = url

        async def go(cred, url, entry):
            auth = cred.auth("browser_login")
            if auth not in BROWSER_AUTH:
                raise Refused(f"credential {cred.name!r} has broker_auth={auth!r}; "
                              "only form or ntlm items can be used with browser_login")
            host = check_url(cred, url)
            await self.approve(cred, "browser_login", host)
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(self.cdp)
                pages = [pg for ctx in browser.contexts for pg in ctx.pages if not not_allowed(cred, pg.url)]
                if pages:
                    page = pages[0]
                else:
                    ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
                    page = await ctx.new_page()
                await page.bring_to_front()
                if auth == "ntlm":
                    return await windows_login(page, cred, explicit or url)
                if not pages or (explicit and page.url != explicit):
                    await page.goto(explicit or url)
                return await fill_login(page, cred)
        return await self._run("browser_login", credential, "LOGIN", url, go)


async def windows_login(page, cred, url, max_answers=3):
    """Navigate to url and answer the browser's Windows sign-in (Negotiate/NTLM) challenges for allowed
    hosts via CDP. The browser keeps the credentials in its auth cache for the rest of the session."""
    cdp = await page.context.new_cdp_session(page)
    answered = 0

    async def on_auth(ev):
        nonlocal answered
        ok = not not_allowed(cred, ev["request"]["url"]) and answered < max_answers
        answered += ok
        resp = ({"response": "ProvideCredentials", "username": cred.username, "password": cred.password}
                if ok else {"response": "CancelAuth"})
        await cdp.send("Fetch.continueWithAuth", {"requestId": ev["requestId"], "authChallengeResponse": resp})

    async def on_paused(ev):
        await cdp.send("Fetch.continueRequest", {"requestId": ev["requestId"]})

    cdp.on("Fetch.authRequired", lambda ev: asyncio.ensure_future(on_auth(ev)))
    cdp.on("Fetch.requestPaused", lambda ev: asyncio.ensure_future(on_paused(ev)))
    await cdp.send("Fetch.enable", {"handleAuthRequests": True})
    try:
        resp = await page.goto(url, wait_until="load")
        code = resp.status if resp else None
    finally:
        await cdp.send("Fetch.disable")
        await cdp.detach()
    status = "signed in" if code and code < 400 else f"sign-in failed (HTTP {code})"
    return {"status": status, "url": page.url, "title": await page.title()}


async def fill_login(page, cred):
    f = cred.fields

    def visible(sel):
        return page.locator(sel).filter(visible=True).first

    async def result(status):
        return {"status": status, "url": page.url, "title": await page.title()}

    async def fill(field, value):
        if reason := not_allowed(cred, page.url):  # never type into a page that moved to a foreign host
            raise Refused(f"login page is on a host this credential may not use: {reason}")
        await field.fill(value)

    async def submit(field):
        btn = visible(f["submit_selector"]) if f.get("submit_selector") else \
            field.locator("xpath=ancestor::form[1]").locator(SUBMIT_SEL).filter(visible=True).first
        if await btn.count():
            await btn.click()
        else:
            await field.press("Enter")

    async def gone(field, timeout=15_000):
        try:
            await field.wait_for(state="hidden", timeout=timeout)
            return True
        except PWTimeout:
            return False

    pass_sel, user_sel = f.get("pass_selector") or PASS_SEL, f.get("user_selector") or USER_SEL
    try:
        await page.locator(f"{pass_sel}, {user_sel}").filter(visible=True).first.wait_for(timeout=10_000)
    except PWTimeout:
        return await result("no login form found on the page")
    pw = visible(pass_sel)
    if not await pw.count():  # username-first flow: submit username, then wait for the password field
        user = visible(user_sel)
        await fill(user, cred.username)
        await submit(user)
        try:
            await pw.wait_for(timeout=10_000)
        except PWTimeout:
            return await result("username submitted but no password field appeared")
    else:
        user = visible(f["user_selector"]) if f.get("user_selector") else \
            pw.locator(BEFORE_PASS).filter(visible=True).last
        if cred.username and await user.count():
            await fill(user, cred.username)
    await fill(pw, cred.password)
    await submit(pw)
    if not await gone(pw):
        if await pw.count():
            await pw.fill("")  # don't leave the password sitting in the shared browser
        return await result("password field still visible after submit (wrong credentials or blocked?)")
    if otp := cred.otp():
        code = visible(OTP_SEL)
        try:
            await code.wait_for(timeout=5_000)
        except PWTimeout:
            return await result("submitted (no TOTP field appeared)")
        await fill(code, otp.now())
        await submit(code)
        if not await gone(code):
            return await result("TOTP field still visible after submit")
    return await result("submitted")


# --- sign-in drivers for non-web endpoints (blocking; called in a thread) ------------------------

def _out(text):
    return text[:MAX_BODY] + (f"\n[truncated to {MAX_BODY} of {len(text)} characters]" if len(text) > MAX_BODY else "")


def port_open(host, port, timeout=2):
    try:
        socket.create_connection((host, port), timeout).close()
        return True
    except OSError:
        return False


def ssh_run(cred, host, port, command, timeout):
    """Password SSH. The host key must already be in ~/.ssh/known_hosts: the password is never sent to a
    server that cannot be verified. command=None only signs in."""
    import paramiko
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        try:
            client.connect(host, port, cred.username, cred.password, timeout=timeout, auth_timeout=timeout,
                           banner_timeout=timeout, allow_agent=False, look_for_keys=False)
        except paramiko.SSHException as e:
            if "known_hosts" in str(e):
                raise Refused(f"the host key of {host} is not in ~/.ssh/known_hosts; "
                              "connect once with ssh to check and trust it") from None
            raise
        if command is None:
            return {"status": "signed in"}
        _, out, err = client.exec_command(command, timeout=timeout)
        stdout, stderr = out.read().decode(errors="replace"), err.read().decode(errors="replace")
        code = out.channel.recv_exit_status()
        return {"status": code, "exit_code": code, "stdout": _out(stdout), "stderr": _out(stderr)}
    finally:
        client.close()


def winrm_run(cred, scheme, host, port, command, timeout):
    """PowerShell over WinRM with NTLM (messages are encrypted even on plain http), like Invoke-Command."""
    import winrm
    session = winrm.Session(f"{'https' if scheme == 'winrms' else 'http'}://{host}:{port}/wsman",
                            auth=(cred.username, cred.password), transport="ntlm",
                            server_cert_validation="ignore" if cred.flag("broker_trust_cert") else "validate",
                            operation_timeout_sec=timeout, read_timeout_sec=timeout + 10)
    try:
        r = session.run_ps(command)
    except winrm.exceptions.InvalidCredentialsError:  # WinRM answers 401 for a bad password AND for no rights
        raise RuntimeError(f"WinRM on {host} refused the sign-in: wrong password, or the account may not use "
                           "WinRM there (by default only local Administrators may)") from None
    return {"status": r.status_code, "exit_code": r.status_code,
            "stdout": _out(r.std_out.decode(errors="replace")), "stderr": _out(r.std_err.decode(errors="replace"))}


@contextmanager
def net_logon(cred):
    """Use cred for outgoing network sign-ins from this thread only (what `runas /netonly` does)."""
    domain, _, user = cred.username.rpartition("\\")
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    token = wintypes.HANDLE()
    if not adv.LogonUserW(user, domain, cred.password, 9, 3, ctypes.byref(token)):  # NEW_CREDENTIALS, WINNT50
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not adv.ImpersonateLoggedOnUser(token):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            yield
        finally:
            adv.RevertToSelf()
    finally:
        ctypes.windll.kernel32.CloseHandle(token)


def _odbc(value):
    return "{" + value.replace("}", "}}") + "}"


def sql_run(cred, host, port, query, database, timeout, max_rows):
    """SQL Server over ODBC, autocommit. Usernames with a domain (DOMAIN\\user) use Windows auth through
    net_logon; any other username is a SQL login."""
    import pyodbc
    pyodbc.pooling = False  # a pooled connection could be handed out under another identity
    drivers = sorted((d for d in pyodbc.drivers() if re.fullmatch(r"ODBC Driver \d+ for SQL Server", d)),
                     key=lambda d: int(d.split()[2]))
    if not drivers:
        raise Refused("no 'ODBC Driver NN for SQL Server' is installed")
    conn = (f"DRIVER={_odbc(drivers[-1])};SERVER=tcp:{host},{port};DATABASE={_odbc(database or 'master')};"
            f"Encrypt=yes;TrustServerCertificate={'yes' if cred.flag('broker_trust_cert') else 'no'};")
    windows = "\\" in cred.username
    if windows:
        with net_logon(cred):
            db = pyodbc.connect(conn + "Trusted_Connection=yes;", timeout=timeout, autocommit=True)
    else:
        db = pyodbc.connect(conn + f"UID={_odbc(cred.username)};PWD={_odbc(cred.password)};",
                            timeout=timeout, autocommit=True)
    try:
        db.timeout = timeout
        cur = db.execute(query)
        sets = []
        while True:
            if cur.description:
                rows = cur.fetchmany(max_rows + 1)
                s = {"columns": [d[0] for d in cur.description],
                     "rows": [[v if isinstance(v, (int, float, str, bool, type(None))) else str(v) for v in r]
                              for r in rows[:max_rows]]}
                if len(rows) > max_rows:
                    s["truncated"] = f"only the first {max_rows} rows"
                sets.append(s)
            else:
                sets.append({"rows_affected": cur.rowcount})
            if not cur.nextset():
                break
        return {"status": "ok", "results": sets}
    finally:
        db.close()


class CREDENTIALW(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD), ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]


def save_rdp_login(cred, host):
    """Store the login for mstsc as TERMSRV/<host>. Domain-password type: only LSA can read the password
    back (not this user's other programs), and session persistence drops it at sign-out."""
    blob = cred.password.encode("utf-16-le")
    buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
    c = CREDENTIALW(Type=2, TargetName=f"TERMSRV/{host}", CredentialBlobSize=len(blob), Persist=1,
                    CredentialBlob=ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)), UserName=cred.username)
    if not ctypes.WinDLL("advapi32", use_last_error=True).CredWriteW(ctypes.byref(c), 0):
        raise ctypes.WinError(ctypes.get_last_error())


def rdp_run(cred, host, port):
    save_rdp_login(cred, host)
    subprocess.Popen(["mstsc", f"/v:{host}" + (f":{port}" if port != 3389 else "")])
    return {"status": "opened", "target": f"{host}:{port}"}


def login_probe(cred, scheme, host, port):
    """Sign in and return a short proof; raises if the sign-in fails."""
    if scheme == "ssh":
        return ssh_run(cred, host, port, None, 15)["status"]
    if scheme in ("winrm", "winrms"):
        r = winrm_run(cred, scheme, host, port, "$env:COMPUTERNAME", 15)
        if r["exit_code"]:
            raise RuntimeError(r["stderr"][:200])
        return "signed in to " + r["stdout"].strip()
    if scheme == "mssql":
        return "signed in as " + str(sql_run(cred, host, port, "SELECT SUSER_SNAME()", None, 15, 1)["results"][0]["rows"][0][0])
    raise Refused(f"{scheme} sign-in cannot be tested")
