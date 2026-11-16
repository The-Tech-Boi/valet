"""Broker core: item policy, host allowlist, approval, redaction, audit, and the two operations."""
import asyncio
import base64
import ctypes
import datetime as dt
import json
import re
import time
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
DEFAULTS = {"http_request": ("bearer", "never"), "browser_login": ("form", "daily")}  # tool -> (auth, approval)
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
        out = []
        for u in self.uris:
            host = urlsplit(u if "://" in u else "https://" + u).hostname
            if host:
                out.append(host.lower())
        return out

    def auth(self, tool):
        return self.fields.get("broker_auth") or DEFAULTS[tool][0]

    def approval(self, tool):
        return self.fields.get("broker_approval") or DEFAULTS[tool][1]

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


def scrub(obj, cred):
    """Replace every secret of cred in every string inside obj with [REDACTED:<name>]."""
    secrets = cred.secrets() if cred else []
    if not secrets:
        return obj
    pattern = re.compile("|".join(map(re.escape, secrets)), re.I)
    tag = f"[REDACTED:{cred.name}]"

    def walk(o):
        if isinstance(o, str):
            return pattern.sub(tag, o)
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
    http_ok = host in LOCAL_HOSTS or cred.fields.get("broker_allow_http", "").lower() in ("yes", "true", "1")
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
            result = await fn(cred, url)
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

    def list_credentials(self):
        try:
            out = []
            for c in self.creds():
                tools = {t: {"auth": c.auth(t), "approval": c.approval(t)} for t in DEFAULTS}
                if c.auth("browser_login") not in BROWSER_AUTH:
                    del tools["browser_login"]
                if c.auth("http_request") == "form":
                    del tools["http_request"]
                out.append({"name": c.name, "id": c.id, "hosts": c.hosts, "tools": tools, "totp": bool(c.totp)})
            return {"credentials": out}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {(str(e).splitlines() or [''])[0]}"[:500]}

    async def http_request(self, credential, method, url, headers=None, body=None, json_body=None, timeout=30):
        async def go(cred, url):
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
        return await self._run("http_request", credential, method.upper(), url, go)

    async def browser_login(self, credential, url=None):
        explicit = url

        async def go(cred, url):
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
