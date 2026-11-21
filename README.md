# valet

A small local MCP server that lets automation and coding assistants *use* credentials stored in
Vaultwarden without ever seeing them. It works like an SSH agent: the broker reads the secret from the
vault, performs the auth (an HTTP request with the token injected, a browser form login, a Windows sign-in,
an SSH, WinRM or SQL Server session, a Remote Desktop window), and hands back only the result. Anything
secret that echoes back in a response or an error is replaced with `[REDACTED:<credential>]`. Scripts that
need the value itself get it through `python -m valet run`, with their output redacted.

A longer walkthrough with diagrams: [docs/how-valet-works.html](docs/how-valet-works.html).

## Security model

The broker runs as the same Windows user as the caller, so it is **not** an OS-level isolation boundary: a
process that can read your files or attach to your browser can get at what the broker can. What it does
is keep secret values out of the caller's context, transcript and logs, refuse to send a credential to any
host not listed on the vault item, ask you before sensitive uses, and write an audit trail. Only items in
one vault collection exist for the broker, which limits the blast radius to what you put there. The shared
browser is a deliberate trade-off: after `browser_login` the session cookie lives in a browser the caller
drives, which is the point; a hostile caller could also read a field the broker just filled.

## Setup

1. Install the Bitwarden CLI (`winget install Bitwarden.CLI`; it also talks to Vaultwarden). valet drives
   it for you:
   ```
   valet vault
   ```
   The first time it asks for the server URL and signs you in; then it asks for the master password,
   unlocks, and keeps the vault open for valet on `127.0.0.1:8087` until you press Ctrl+C (which locks it).
   `valet.cmd` in the repo root runs the venv's Python; add the folder to your PATH or call it by path.
2. In the vault, create a collection named `Agent` and put the items the broker may use in it.
3. Create the venv (keep the folder path short; very deep paths break Playwright's DLL loading):
   ```
   py -3 -m venv .venv
   .venv\Scripts\python -m pip install mcp httpx httpx-ntlm playwright pyotp paramiko pywinrm pyodbc pytest
   ```
   `sql_query` also needs Microsoft's "ODBC Driver 17/18 for SQL Server".
   No Playwright browser download is needed for normal use; the broker drives your Edge or Chrome.
4. Start the shared browser: `.venv\Scripts\python -m valet browser`. It launches Edge (or Chrome)
   with `--remote-debugging-port=9333` and a separate profile in `%LOCALAPPDATA%\valet\browser-profile`.
   Point your other browser automation at the same endpoint (for example Playwright MCP with
   `--cdp-endpoint http://127.0.0.1:9333`).
5. Register the MCP server (example below). Tests are offline (fake vault, local test site) and need
   Playwright's Chromium once: `.venv\Scripts\python -m playwright install chromium`, then
   `.venv\Scripts\python -m pytest`.

Environment variables (no config files):

| Variable | Default |
|---|---|
| `VALET_COLLECTION` | `Agent` (collection name or id) |
| `VALET_BW_URL` | `http://127.0.0.1:8087` |
| `VALET_CDP` | `http://127.0.0.1:9333` |
| `VALET_DIR` | `%LOCALAPPDATA%\valet` (audit log, browser profile) |

## Tools

- `list_credentials()`: names, ids, allowed hosts, usable tools with auth type and approval policy, TOTP yes/no.
- `http_request(credential, method, url, headers, body, json, timeout)`: injects auth; https only (http
  allowed for localhost); refuses hosts not on the item; does not follow redirects; returns status,
  selected headers and the body (truncated at 20,000 characters).
- `browser_login(credential, url)`: reuses a tab on an allowed host or opens the URL; fills username,
  password and TOTP; returns status, URL and title only. It re-checks the page host before typing anything.
- `ssh_exec(credential, command, host, timeout)`: password SSH to the item's `ssh://` URI. The host key must
  already be in `~/.ssh/known_hosts`. Returns exit code, stdout, stderr. (Key-based SSH: use an SSH agent.)
- `win_exec(credential, command, host, timeout)`: PowerShell over WinRM with NTLM to the item's `winrm://`
  (5985, message-encrypted) or `winrms://` (5986) URI.
- `sql_query(credential, query, database, host, max_rows)`: T-SQL on the item's `mssql://` URI, autocommit.
  `DOMAIN\user` usernames sign in with Windows auth (like `runas /netonly`), others as SQL logins.
- `rdp_open(credential, host)`: stores the login as a Windows domain credential for `TERMSRV/<host>` (only
  LSA can read its password back; dropped at sign-out) and starts `mstsc`. Nobody types the password.
- `check_credentials(credentials)`: one approval, then tries every item's sign-in on every URI and reports
  ok / failed / skipped. Scheme-less URIs (a bare IP) are probed for ssh, WinRM and SQL Server.

## Scripts: `valet run`

Don't hardcode a password in a script; read it from the environment and let valet fill it in:

```
python -m valet run -e SQL_PASS=valet://SQL sync/password -- python sync.py
python -m valet run --env-file .env -- python sync.py     # .env lines like API_TOKEN=valet://Contacts API/password
```

A value `valet://<item>/<field>` (field: `password`, `username`, `totp`, `uri` or a custom field name) is
replaced with the secret after one approval per item (tool `run`, default `daily`). `BW_SESSION` is removed
from the child's environment, the child's stdout and stderr are copied through the redactor, the exit code is
passed on, and the run is audited. The script itself does hold the value, so prefer the MCP tools when they
cover the job.

## Command line

```
python -m valet vault            # unlock and serve the vault for valet (Ctrl+C locks)
python -m valet browser          # shared Edge/Chrome with the CDP port
python -m valet run ... -- CMD   # see above
python -m valet rdp ITEM [HOST]  # Remote Desktop, signed in
python -m valet check [ITEM...]  # ok/failed per item and URI
```

## Item fields

The broker reads the item's login (username, password, TOTP, URIs) and these custom fields:

| Field | Values | Default |
|---|---|---|
| `broker_auth` | `bearer`, `basic`, `header:<Name>`, `query:<param>`, `form`, `ntlm` | `bearer` for http_request, `form` for browser_login |
| `broker_approval` | `never`, `daily`, `always` | `never` for http_request, `daily` for browser_login |
| `broker_allow_http` | `yes` to allow plain http to the item's hosts (e.g. over a VPN) | https only (http always allowed for localhost) |
| `broker_trust_cert` | `yes` to accept a self-signed certificate (SQL Server, `winrms://`) | certificate validated |
| `user_selector`, `pass_selector`, `submit_selector` | CSS selectors for odd login forms | heuristics |

Approval defaults per tool: `http_request` and `rdp_open` never; `browser_login`, `ssh_exec`, `win_exec`,
`sql_query` and `run` daily; `check_credentials` always (once per batch). `broker_approval` on the item
overrides all of them.

The URI scheme decides which tool may use the item where: `ssh://`, `winrm://`, `winrms://`, `mssql://`,
`rdp://` (optional `:port`) for the server tools, `http(s)://` or no scheme for the web tools. A password is
never sent to a host or protocol the item does not list. Web hosts are exact matches; write
`https://*.example.com` to allow subdomains. `browser_login` works with `form` and `ntlm` items; `http_request` works with everything but
`form`. `ntlm` is Windows sign-in (servers answering 401 with `Negotiate`/`NTLM`, such as on-premises IIS
apps): username as `DOMAIN\user`. In the browser the broker answers the sign-in challenge over CDP and the
browser keeps it for the session, so later tabs on that host stay signed in.

Approval pops up a Windows dialog naming the credential, operation and host: **Yes** allows until midnight
(only meaningful for `daily`), **No** allows once, **Cancel** (the default button) denies.

Every call is appended to `%LOCALAPPDATA%\valet\audit.jsonl` (time, tool, credential, method,
host and path without query string, result). No secrets are written there.

### Examples

**API token** (`GitLab API`): password = the token; URI `https://gitlab.example.com`; no custom fields
(bearer, no approval). A token sent in a custom header instead: `broker_auth` = `header:PRIVATE-TOKEN`.

**Basic auth** (`Router admin API`): username and password; URI `https://router.example.lan`;
`broker_auth` = `basic`, `broker_approval` = `always`.

**Windows sign-in app** (`Intranet CRM`): username `CORP\jdoe`, password; URI
`http://crm.corp.lan:5555/Org`; `broker_auth` = `ntlm`, `broker_allow_http` = `yes` (only if it really is
plain http on a trusted network). Works for both the web UI and its REST API.

**Web login with TOTP** (`Vendor portal`): username, password, authenticator key (TOTP) set on the item;
URIs `https://portal.vendor.com` and `https://login.vendor.com` (the login redirect host must be listed
too); no custom fields (form, daily approval). If the form is unusual, add for example
`user_selector` = `#login-email`.

## MCP registration example

Not installed anywhere by this project; adapt the paths and add it to your client's MCP config:

```json
{
  "mcpServers": {
    "valet": {
      "command": "C:\\tools\\valet\\.venv\\Scripts\\python.exe",
      "args": ["-m", "valet"],
      "env": {
        "PYTHONPATH": "C:\\tools\\valet",
        "VALET_COLLECTION": "Agent"
      }
    }
  }
}
```

## Licence

MIT, see [LICENSE](LICENSE).
