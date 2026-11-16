"""`python -m valet` runs the MCP server on stdio.
`python -m valet browser` starts Edge/Chrome with the CDP port the broker connects to.
"""
import json
import os
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

from mcp.server import MCPServer

from .broker import Broker
from .vault import BwServe

HOME = os.environ.get("VALET_DIR") or os.path.join(os.environ.get("LOCALAPPDATA", "."), "valet")
CDP = os.environ.get("VALET_CDP", "http://127.0.0.1:9333")

INSTRUCTIONS = """Uses credentials from a vault without ever revealing them. Call list_credentials to see what
exists and which hosts each credential may be sent to. Then use http_request for APIs or browser_login for
web logins. Secret values never appear in results; anything secret that echoes back is shown as
[REDACTED:<name>]. Some operations pop up an approval dialog for the user and wait for the answer."""


def build_app(broker):
    app = MCPServer("valet", instructions=INSTRUCTIONS)

    def out(result):
        return json.dumps(result, indent=1)

    @app.tool()
    async def list_credentials() -> str:
        """List the credentials available to you: name, id, allowed hosts, which tools each one works with
        (with its auth type and approval policy), and whether it has TOTP. Never returns secret values."""
        return out(broker.list_credentials())

    @app.tool()
    async def http_request(credential: str, method: str, url: str, headers: dict[str, str] | None = None,
                           body: str | None = None, json: dict | list | None = None, timeout: float = 30) -> str:
        """Send an HTTP request with the named credential (name or id) injected as configured on the item
        (bearer token, basic auth, a custom header, or a query parameter). Do not add auth yourself.
        The url must be https (http only for localhost) on one of the credential's allowed hosts, otherwise
        the request is refused. Redirects are not followed (you get the status and Location).
        Pass either body (raw text) or json, not both. Returns status, selected response headers and the
        body text (truncated past 20000 characters, which the result says). Returns {"error": ...} on
        refusal, user denial or network failure."""
        return out(await broker.http_request(credential, method, url, headers, body, json, timeout))

    @app.tool()
    async def browser_login(credential: str, url: str | None = None) -> str:
        """Log in to a website in the shared browser using the named credential (name or id). Reuses an
        open tab on one of the credential's hosts, otherwise opens url (or the item's first URI) in a new
        tab. Fills username and password, a TOTP code if a code field appears, and submits. Returns only a
        status, the resulting page URL and title; continue in that tab with your own browser tools.
        Refuses pages on hosts the credential is not allowed for."""
        return out(await broker.browser_login(credential, url))

    return app


def start_browser():
    port = urlsplit(CDP).port or 9333
    candidates = [shutil.which("msedge"), shutil.which("chrome")] + [
        os.path.join(os.environ.get(base, ""), exe)
        for base in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA")
        for exe in (r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe")]
    exe = next((c for c in candidates if c and os.path.isfile(c)), None)
    if not exe:
        sys.exit("Neither Microsoft Edge nor Google Chrome was found.")
    profile = os.path.join(HOME, "browser-profile")
    subprocess.Popen([exe, f"--remote-debugging-port={port}", f"--user-data-dir={profile}", "--no-first-run"])
    print(f"Started {exe}\nCDP endpoint: http://127.0.0.1:{port}\nProfile: {profile}")


def main():
    if sys.argv[1:] == ["browser"]:
        return start_browser()
    collection = os.environ.get("VALET_COLLECTION")
    if not collection:
        sys.exit("Set VALET_COLLECTION to the vault collection name or id.")
    backend = BwServe(os.environ.get("VALET_BW_URL", "http://127.0.0.1:8087"), collection)
    build_app(Broker(backend, HOME, cdp=CDP)).run()


if __name__ == "__main__":
    main()
