"""`python -m valet` runs the MCP server on stdio. Other commands:

  python -m valet vault                      unlock the vault and keep it open for valet (Ctrl+C locks it)
  python -m valet browser                    start Edge/Chrome with the CDP port the broker connects to
  python -m valet run [-e NAME=valet://ITEM/FIELD] [--env-file F] -- COMMAND...
                                             run a script with secrets in its environment, output redacted
  python -m valet rdp ITEM [HOST]            open Remote Desktop with the item's login, nothing typed
  python -m valet check [ITEM...]            try every item's sign-in and print ok/failed per URI
"""
import argparse
import asyncio
import json
import locale
import os
import shutil
import subprocess
import sys
import threading
from urllib.parse import urlsplit

from mcp.server import MCPServer

from .broker import Broker
from .vault import BwServe

HOME = os.environ.get("VALET_DIR") or os.path.join(os.environ.get("LOCALAPPDATA", "."), "valet")
CDP = os.environ.get("VALET_CDP", "http://127.0.0.1:9333")

INSTRUCTIONS = """Uses credentials from a vault without ever revealing them. Call list_credentials to see what
exists, where each credential may be used and with which tools. Then use http_request for APIs, browser_login
for web logins, ssh_exec / win_exec for commands on servers, sql_query for SQL Server, rdp_open to open a
Remote Desktop window for the user. Secret values never appear in results; anything secret that echoes back
is shown as [REDACTED:<name>]. Some operations pop up an approval dialog for the user and wait for the answer.
For scripts that need a password, do not hardcode it: put NAME=valet://<item>/password in the environment
and start the script with `python -m valet run -- <command>`."""


def build_app(broker):
    app = MCPServer("valet", instructions=INSTRUCTIONS)

    def out(result):
        return json.dumps(result, indent=1)

    @app.tool()
    async def list_credentials() -> str:
        """List the credentials available to you: name, id, allowed web hosts, which tools each one works
        with (with auth type, approval policy and, for server tools, the allowed targets), and whether it
        has TOTP. Never returns secret values."""
        return out(broker.list_credentials())

    @app.tool()
    async def http_request(credential: str, method: str, url: str, headers: dict[str, str] | None = None,
                           body: str | None = None, json: dict | list | None = None, timeout: float = 30) -> str:
        """Send an HTTP request with the named credential (name or id) injected as configured on the item
        (bearer token, basic auth, a custom header, a query parameter, or Windows NTLM). Do not add auth
        yourself. The url must be https (http only for localhost or items that allow it) on one of the
        credential's allowed hosts, otherwise the request is refused. Redirects are not followed (you get the
        status and Location). Pass either body (raw text) or json, not both. Returns status, selected response
        headers and the body text (truncated past 20000 characters, which the result says). Returns
        {"error": ...} on refusal, user denial or network failure."""
        return out(await broker.http_request(credential, method, url, headers, body, json, timeout))

    @app.tool()
    async def browser_login(credential: str, url: str | None = None) -> str:
        """Log in to a website in the shared browser using the named credential (name or id). Reuses an
        open tab on one of the credential's hosts, otherwise opens url (or the item's first URI) in a new
        tab. Fills username and password, a TOTP code if a code field appears, and submits (or answers a
        Windows sign-in challenge). Returns only a status, the resulting page URL and title; continue in that
        tab with your own browser tools. Refuses pages on hosts the credential is not allowed for."""
        return out(await broker.browser_login(credential, url))

    @app.tool()
    async def ssh_exec(credential: str, command: str, host: str | None = None, timeout: float = 60) -> str:
        """Run a shell command over SSH with the credential's username and password, on the item's ssh://
        URI (pass host to pick one when it lists several). The server's host key must already be trusted
        in ~/.ssh/known_hosts. Returns exit_code, stdout and stderr. For key-based SSH use the normal ssh
        command instead (the SSH agent handles it)."""
        return out(await broker.ssh_exec(credential, command, host, timeout))

    @app.tool()
    async def win_exec(credential: str, command: str, host: str | None = None, timeout: float = 60) -> str:
        """Run a PowerShell command on a Windows server over WinRM (NTLM) with the credential, on the item's
        winrm:// (port 5985) or winrms:// (5986) URI. Returns exit_code, stdout and stderr."""
        return out(await broker.win_exec(credential, command, host, timeout))

    @app.tool()
    async def sql_query(credential: str, query: str, database: str | None = None, host: str | None = None,
                        max_rows: int = 200) -> str:
        """Run T-SQL on SQL Server with the credential, on the item's mssql:// URI. Items whose username has
        a domain (DOMAIN\\user) sign in with Windows auth, others as a SQL login. Autocommit: writes take
        effect immediately. Returns one entry per result set: columns and rows (first max_rows), or
        rows_affected."""
        return out(await broker.sql_query(credential, query, database, host, max_rows))

    @app.tool()
    async def rdp_open(credential: str, host: str | None = None) -> str:
        """Open a Remote Desktop window on the user's screen for the item's rdp:// URI, signed in with the
        credential (handed to Windows directly, nobody types it). For the user to work in; you cannot see
        or drive the session."""
        return out(await broker.rdp_open(credential, host))

    @app.tool()
    async def check_credentials(credentials: list[str] | None = None) -> str:
        """Try the sign-in of each credential (all, or the given names/ids) on each of its URIs and report
        ok / failed / skipped with a short reason. One approval covers the whole batch. Scheme-less URIs
        (a bare IP) are probed for ssh, winrm and SQL Server. Use after importing credentials to find wrong
        passwords."""
        return out(await broker.check_credentials(credentials))

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


def open_vault():
    """Unlock the vault and keep it open for valet on localhost until Ctrl+C. Runs the Bitwarden CLI
    (`bw`, which also talks to Vaultwarden) so you never have to drive it yourself."""
    import getpass
    bw = shutil.which("bw")
    if not bw:
        sys.exit("The Bitwarden CLI (bw) is not installed: winget install Bitwarden.CLI")
    url = urlsplit(os.environ.get("VALET_BW_URL", "http://127.0.0.1:8087"))
    status = json.loads(subprocess.run([bw, "status"], capture_output=True, text=True).stdout or "{}")
    if not status.get("serverUrl"):
        server = input("Vault server URL (e.g. https://vault.example.com): ").strip()
        subprocess.run([bw, "config", "server", server], check=True)
    if status.get("status") in (None, "unauthenticated"):
        print("Sign in (your browser opens for single sign-on):")
        subprocess.run([bw, "login", "--sso"], check=True)
    env = dict(os.environ, VALET_MASTER=getpass.getpass("Master password: "))
    unlock = subprocess.run([bw, "unlock", "--passwordenv", "VALET_MASTER", "--raw"], env=env,
                            capture_output=True, text=True)
    if unlock.returncode or not unlock.stdout.strip():
        sys.exit("Unlock failed: " + (unlock.stderr.strip() or "wrong master password?"))
    env = dict(os.environ, BW_SESSION=unlock.stdout.strip())
    print(f"Vault open for valet on {url.hostname}:{url.port}. Keep this window open; Ctrl+C locks it again.")
    try:
        subprocess.run([bw, "serve", "--hostname", url.hostname, "--port", str(url.port)], env=env)
    except KeyboardInterrupt:
        pass
    subprocess.run([bw, "lock"], env=env, capture_output=True)


def read_env_file(path):
    out = {}
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            key, sep, value = line.strip().partition("=")
            if sep and key and not key.startswith("#"):
                out[key.removeprefix("export ").strip()] = value.strip().strip("'\"")
    return out


def decode(line):
    try:
        return line.decode("utf-8")
    except UnicodeDecodeError:
        return line.decode(locale.getpreferredencoding(False), errors="replace")


def run_command(broker, argv, stdout=None, stderr=None):
    """Start a command with valet:// references in its environment replaced by the secrets, and copy its
    output to ours with every one of those secrets redacted. Returns the command's exit code."""
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    p = argparse.ArgumentParser(prog="python -m valet run")
    p.add_argument("-e", "--env", action="append", default=[], metavar="NAME=valet://ITEM/FIELD")
    p.add_argument("--env-file", action="append", default=[])
    p.add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not cmd:
        p.error("give the command to run after --")
    env = dict(os.environ)
    for path in a.env_file:
        env.update(read_env_file(path))
    env.update(kv.split("=", 1) for kv in a.env if "=" in kv)
    env.pop("BW_SESSION", None)  # the child gets its secrets, not the key to the whole vault
    refs = {k: v for k, v in env.items() if v.startswith("valet://")}
    try:
        values, redact = asyncio.run(broker.resolve(refs, " ".join(cmd)))
    except Exception as e:  # Refused, Denied, or the vault being unreachable
        print(f"valet: {e}", file=stderr)
        return 2
    env.update(values)
    proc = subprocess.Popen([shutil.which(cmd[0]) or cmd[0], *cmd[1:]], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def pump(src, dst):
        for line in iter(src.readline, b""):  # line-buffered; a prompt without newline shows late
            dst.write(redact(decode(line)))
            dst.flush()

    pumps = [threading.Thread(target=pump, args=io) for io in ((proc.stdout, stdout), (proc.stderr, stderr))]
    for t in pumps:
        t.start()
    code = proc.wait()
    for t in pumps:
        t.join()
    return code


def main():
    args = sys.argv[1:]
    if args == ["browser"]:
        return start_browser()
    if args == ["vault"]:
        return open_vault()
    backend = BwServe(os.environ.get("VALET_BW_URL", "http://127.0.0.1:8087"),
                      os.environ.get("VALET_COLLECTION", "Agent"))
    broker = Broker(backend, HOME, cdp=CDP)
    if args[:1] == ["run"]:
        for stream in (sys.stdout, sys.stderr):
            stream.reconfigure(errors="replace")
        sys.exit(run_command(broker, args[1:]))
    if args[:1] == ["rdp"] and len(args) in (2, 3):
        print(json.dumps(asyncio.run(broker.rdp_open(args[1], args[2] if len(args) == 3 else None))))
        return
    if args[:1] == ["check"]:
        result = asyncio.run(broker.check_credentials(args[1:] or None))
        for r in result.get("results", []):
            print(f"{r['result']:8} {r['credential']}  {r['uri']}  {r['detail']}")
        print(result.get("summary") or result.get("error"))
        return
    if args:
        sys.exit(__doc__)
    build_app(broker).run()


if __name__ == "__main__":
    main()
