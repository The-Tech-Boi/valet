# valet

A small local MCP server that lets automation and coding assistants *use* credentials stored in
Vaultwarden without ever seeing them. It works like an SSH agent: the broker reads the secret from the
vault, performs the auth (an HTTP request with the token injected, a browser form login, or a Windows sign-in), and hands
back only the result. Anything secret that echoes back in a response or an error is replaced with
`[REDACTED:<credential>]`.

## Security model

The broker runs as the same Windows user as the caller, so it is **not** an OS-level isolation boundary: a
process that can read your files or attach to your browser can get at what the broker can. What it does
is keep secret values out of the caller's context, transcript and logs, refuse to send a credential to any
host not listed on the vault item, ask you before sensitive uses, and write an audit trail. Only items in
one vault collection exist for the broker, which limits the blast radius to what you put there. The shared
browser is a deliberate trade-off: after `browser_login` the session cookie lives in a browser the caller
drives, which is the point; a hostile caller could also read a field the broker just filled.

## Setup

1. Install the Bitwarden CLI (`bw`) and point it at the vault:
   ```
   bw config server https://vault.example.com
   bw login
   $env:BW_SESSION = (bw unlock --raw)
   bw serve --hostname 127.0.0.1 --port 8087
   ```
   Keep `bw serve` running (it exposes the unlocked vault on localhost only).
2. In the vault, create a collection named `Agent` and put the items the broker may use in it.
3. Create the venv (keep the folder path short; very deep paths break Playwright's DLL loading):
   ```
   py -3 -m venv .venv
   .venv\Scripts\python -m pip install mcp httpx httpx-ntlm playwright pyotp pytest
   ```
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
| `VALET_COLLECTION` | required: collection name or id |
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

## Item fields

The broker reads the item's login (username, password, TOTP, URIs) and these custom fields:

| Field | Values | Default |
|---|---|---|
| `broker_auth` | `bearer`, `basic`, `header:<Name>`, `query:<param>`, `form`, `ntlm` | `bearer` for http_request, `form` for browser_login |
| `broker_approval` | `never`, `daily`, `always` | `never` for http_request, `daily` for browser_login |
| `broker_allow_http` | `yes` to allow plain http to the item's hosts (e.g. over a VPN) | https only (http always allowed for localhost) |
| `user_selector`, `pass_selector`, `submit_selector` | CSS selectors for odd login forms | heuristics |

Allowed hosts are the hosts of the item's URIs (exact match; write `https://*.example.com` to allow
subdomains). `browser_login` works with `form` and `ntlm` items; `http_request` works with everything but
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
