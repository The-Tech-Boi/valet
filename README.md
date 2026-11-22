# valet

A small local MCP server that lets automation and coding assistants *use* credentials stored in
Vaultwarden without ever seeing them. It works like an SSH agent: valet reads the secret from the vault,
performs the auth (an HTTP request with the token injected, a browser form login, a Windows sign-in, an
SSH, WinRM or SQL Server session, a Remote Desktop window), and hands back only the result. Anything
secret that echoes back in a response or an error is replaced with `[REDACTED:<credential>]`. Scripts that
need the value itself get it through `valet run`, with their output redacted.

One Windows executable, no runtime to install. A longer walkthrough with diagrams:
[docs/how-valet-works.html](docs/how-valet-works.html).

## Security model

valet runs as the same Windows user as the caller, so it is **not** an OS-level isolation boundary: a
process that can read your files or attach to your browser can get at what valet can. What it does is keep
secret values out of the caller's context, transcript and logs, refuse to send a credential to any host
not listed on the vault item, ask you before sensitive uses, and write an audit trail. Only items in one
vault collection exist for valet, which limits the blast radius to what you put there. The shared browser
is a deliberate trade-off: after `browser_login` the session cookie lives in a browser the caller drives,
which is the point; a hostile caller could also read a field valet just filled.

## Setup

1. Build it (Rust stable, Windows):
   ```
   cargo build --release
   ```
2. Install it: copies `valet.exe` to `%LOCALAPPDATA%\Programs\valet` and adds that folder to your user
   PATH (no admin rights), so `valet` works in any new terminal.
   ```
   target\release\valet.exe install
   ```
   The first install opens the setup window: your vault URL and your **personal** API key
   (Vaultwarden web vault → Account settings → Security → Keys → View API key; the `client_id` starts
   with `user.`). valet stores the login in `%LOCALAPPDATA%\valet`, protected with Windows DPAPI.
   Run `valet setup` to change it later.
3. In the vault, create a collection named `Agent` and put the items valet may use in it.
4. Register the MCP server in your client (see below).
5. For `browser_login`, start the shared browser with `valet browser`. It launches Edge (or Chrome) with
   `--remote-debugging-port=9333` and its own profile in `%LOCALAPPDATA%\valet\browser-profile`. Point
   other browser automation at the same endpoint (for example Playwright MCP with
   `--cdp-endpoint http://127.0.0.1:9333`).

The first tool call starts a background agent and opens an Unlock window for your master password. The
agent keeps the vault unlocked until `valet lock` or `valet stop`. It reads the vault when it unlocks, so
after changing items run `valet lock`; the next call unlocks again with the current items.

Environment variables (no config files):

| Variable | Default |
|---|---|
| `VALET_COLLECTION` | `Agent` (collection name or id) |
| `VALET_CDP` | `http://127.0.0.1:9333` |
| `VALET_DIR` | `%LOCALAPPDATA%\valet` (login, audit log, browser profile) |

## Tools

- `list_credentials()`: names, ids, allowed hosts, usable tools with auth type and approval policy, TOTP yes/no.
- `http_request(credential, method, url, headers, body, json, timeout)`: injects auth; https only (http
  allowed for localhost); refuses hosts not on the item; does not follow redirects; returns status,
  selected headers and the body (truncated at 20,000 characters).
- `browser_login(credential, url)`: reuses a tab on an allowed host or opens the URL; fills username,
  password and TOTP; returns status, URL and title only. It re-checks the page host before typing anything.
- `ssh_exec(credential, command, host, timeout)`: password SSH to the item's `ssh://` URI. The host key must
  already be in `~/.ssh/known_hosts`. Returns exit code, stdout, stderr. (Key-based SSH: use an SSH agent.)
- `win_exec(credential, command, host, timeout)`: PowerShell over WinRM with Negotiate/NTLM to the item's
  `winrm://` (5985, message-encrypted) or `winrms://` (5986) URI.
- `sql_query(credential, query, database, host, max_rows)`: T-SQL on the item's `mssql://` URI, autocommit.
  `DOMAIN\user` usernames sign in with Windows auth, others as SQL logins.
- `rdp_open(credential, host)`: stores the login as a Windows domain credential for `TERMSRV/<host>` (only
  LSA can read its password back; dropped at sign-out) and starts `mstsc`. Nobody types the password.
- `check_credentials(credentials)`: one approval, then tries every item's sign-in on every URI and reports
  ok / failed / skipped. A URI without a scheme (a bare IP) is never signed in to; the result says which
  server ports are open there.

## Scripts: `valet run`

Don't hardcode a password in a script; read it from the environment and let valet fill it in:

```
valet run -e SQL_PASS=valet://SQL sync/password -- python sync.py
valet run --env-file .env -- python sync.py     # .env lines like API_TOKEN=valet://Contacts API/password
```

A value `valet://<item>/<field>` (field: `password`, `username`, `totp`, `uri` or a custom field name) is
replaced with the secret after one approval per item (tool `run`, default `daily`). `BW_SESSION` is removed
from the child's environment, the child's stdout and stderr are copied through the redactor, the exit code is
passed on, and the run is audited. The script itself does hold the value, so prefer the MCP tools when they
cover the job.

## Command line

```
valet                   MCP server on stdio (what MCP clients run)
valet install           copy to %LOCALAPPDATA%\Programs\valet, add to PATH, then setup
valet uninstall         undo install (your login in %LOCALAPPDATA%\valet stays)
valet setup             connect to the vault: URL and personal API key
valet unlock | lock     unlock (asks the master password) or lock the agent
valet status            locked/unlocked, item count
valet stop              stop the background agent
valet run ... -- CMD    see above
valet rdp ITEM [HOST]   Remote Desktop, signed in
valet check [ITEM...]   ok/failed per item and URI
valet browser           Edge/Chrome with the CDP port browser_login uses
```

## Item fields

valet reads the item's login (username, password, TOTP, URIs) and these custom fields:

| Field | Values | Default |
|---|---|---|
| `broker_auth` | `bearer`, `basic`, `header:<Name>`, `query:<param>`, `form`, `ntlm` | `bearer` for http_request, `form` for browser_login |
| `broker_approval` | `never`, `daily`, `always` | `never` for http_request, `daily` for browser_login |
| `broker_allow_http` | `yes` to allow plain http to the item's hosts (e.g. over a VPN) | https only (http always allowed for localhost) |
| `broker_trust_cert` | `yes` to accept a self-signed certificate (SQL Server, `winrms://`, https) | certificate validated |
| `user_selector`, `pass_selector`, `submit_selector` | CSS selectors for odd login forms | heuristics |

Approval defaults per tool: `http_request` and `rdp_open` never; `browser_login`, `ssh_exec`, `win_exec`,
`sql_query` and `run` daily; `check_credentials` always (once per batch). `broker_approval` on the item
overrides all of them.

The URI scheme decides which tool may use the item where: `ssh://`, `winrm://`, `winrms://`, `mssql://`,
`rdp://` (optional `:port`) for the server tools, `http(s)://` or no scheme for the web tools. A password is
never sent to a host or protocol the item does not list. Web hosts are exact matches; write
`https://*.example.com` to allow subdomains. `browser_login` works with `form` and `ntlm` items;
`http_request` works with everything but `form`. `ntlm` is Windows sign-in (servers answering 401 with
`Negotiate`/`NTLM`, such as on-premises IIS apps): username as `DOMAIN\user`. In the browser valet answers
the sign-in challenge over CDP and the browser keeps it for the session, so later tabs on that host stay
signed in.

Approval opens a window naming the credential, operation, host and calling program: **Allow today**
(only meaningful for `daily`), **Allow once**, or **Deny** (the default button). Concurrent calls for the
same item share one prompt.

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

**Remote Desktop** (`Jump host`): username `CORP\jdoe` (or `.\admin` for a local account), password; URI
`rdp://jump.corp.lan`. The vault's Launch button cannot open it; call `rdp_open` or run
`valet rdp "Jump host"`.

## MCP registration

Register a stdio server whose command is the installed exe, with no arguments:

```json
{
  "mcpServers": {
    "valet": {
      "command": "C:\\Users\\<you>\\AppData\\Local\\Programs\\valet\\valet.exe"
    }
  }
}
```

## Development

```
cargo test
cargo clippy --all-targets
```

Tests are offline (fake vault, local test servers). The browser tests drive a real Edge or Chrome.

## Licence

MIT, see [LICENSE](LICENSE).
