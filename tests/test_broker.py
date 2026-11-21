import asyncio
import base64
import json

import httpx
import pytest

from conftest import PASSWORD, TOKEN, Handler, assert_clean, free_port
from valet.__main__ import build_app
from valet.broker import Cred, not_allowed


def run(coro):
    return asyncio.run(coro)


def test_list_credentials_has_no_secrets_and_respects_collection(broker):
    out = broker.list_credentials()
    assert_clean(out)
    names = {c["name"]: c for c in out["credentials"]}
    assert "outside" not in names
    assert names["web"]["totp"] is True and names["api-bearer"]["totp"] is False
    assert set(names["api-bearer"]["tools"]) == {"http_request", "browser_login"}
    assert set(names["web-plain"]["tools"]) == {"browser_login"}
    assert set(names["api-basic"]["tools"]) == {"http_request"}
    assert names["api-bearer"]["tools"]["http_request"] == {"auth": "bearer", "approval": "never"}
    assert names["web"]["tools"]["browser_login"]["approval"] == "daily"
    assert names["remote"]["hosts"] == ["api.example.com", "*.example.org"]


@pytest.mark.parametrize("name, check", [
    ("api-bearer", lambda req: req["headers"]["Authorization"] == f"Bearer {TOKEN}"),
    ("api-basic", lambda req: req["headers"]["Authorization"] ==
     "Basic " + base64.b64encode(f"svc-user:{PASSWORD}".encode()).decode()),
    ("api-header", lambda req: req["headers"]["X-Api-Key"] == TOKEN),
    ("api-query", lambda req: req["path"] == f"/echo?a=1&api_key={TOKEN}"),
])
def test_auth_injected_and_echo_redacted(broker, server, name, check):
    Handler.seen.clear()
    out = run(broker.http_request(name, "get", server + "/echo?a=1", headers={"Authorization": "mine"}))
    assert out["status"] == 200, out
    assert check(Handler.seen[-1])  # the server really got the secret
    assert_clean(out)  # ...but the caller never sees it
    assert f"[REDACTED:{name}]" in out["body"]


def test_post_json_and_truncation(broker, server):
    out = run(broker.http_request("api-bearer", "POST", server + "/echo", json_body={"k": "v"}))
    assert json.loads(out["body"])["body"] == '{"k":"v"}'
    big = run(broker.http_request("api-bearer", "GET", server + "/big"))
    assert len(big["body"]) == 20_000 and "50000" in big["truncated"]


def test_host_allowlist_refuses_other_hosts(broker, server):
    Handler.seen.clear()
    port = server.rsplit(":", 1)[1]
    for url in [f"http://localhost:{port}/echo", "https://evil.example.net/", "https://api.example.com.evil.net/"]:
        out = run(broker.http_request("api-bearer", "GET", url))
        assert "not allowed" in out["error"], out
    assert Handler.seen == []


def test_scheme_and_wildcard_rules():
    c = Cred("i", "remote", "", "", "", ["https://api.example.com", "*.example.org", "http://localhost:8080"], {})
    assert not_allowed(c, "https://api.example.com/v1") is None
    assert "scheme" in not_allowed(c, "http://api.example.com/v1")
    assert "scheme" in not_allowed(c, "ftp://api.example.com/")
    assert not_allowed(c, "https://a.example.org/") is None
    assert not_allowed(c, "https://a.b.example.org/") is None
    assert "not allowed" in not_allowed(c, "https://example.org/")
    assert "not allowed" in not_allowed(c, "https://badexample.org/")
    assert not_allowed(c, "http://localhost:9999/x") is None
    assert "scheme" in not_allowed(Cred("i", "n", "", "", "", ["http://10.0.0.5"], {}), "http://10.0.0.5/")
    lan = Cred("i", "n", "", "", "", ["http://10.0.0.5"], {"broker_allow_http": "yes"})
    assert not_allowed(lan, "http://10.0.0.5/") is None
    assert "scheme" in not_allowed(lan, "ftp://10.0.0.5/")


def test_item_outside_collection_is_invisible(broker, server):
    out = run(broker.http_request("outside", "GET", server + "/echo"))
    assert "no credential" in out["error"]
    out = run(broker.http_request("id-outside", "GET", server + "/echo"))
    assert "no credential" in out["error"]


def test_form_item_refused_for_http(broker, server):
    assert "cannot use" in run(broker.http_request("web-plain", "GET", server + "/echo"))["error"]


def test_approval_deny(broker, approver, server):
    Handler.seen.clear()
    approver.answer = "deny"
    out = run(broker.http_request("api-daily", "GET", server + "/echo"))
    assert "denied" in out["error"]
    assert Handler.seen == []
    assert approver.calls == [("api-daily", "http_request", "127.0.0.1")]


def test_approval_once_asks_every_time(broker, approver, server):
    for _ in range(2):
        assert run(broker.http_request("api-daily", "GET", server + "/echo"))["status"] == 200
    assert len(approver.calls) == 2


def test_approval_today_is_remembered_for_daily_only(broker, approver, server):
    approver.answer = "today"
    for _ in range(3):
        assert run(broker.http_request("api-daily", "GET", server + "/echo"))["status"] == 200
    assert len(approver.calls) == 1
    for _ in range(2):
        run(broker.http_request("api-always", "GET", server + "/echo"))
    assert len(approver.calls) == 3
    run(broker.http_request("api-bearer", "GET", server + "/echo"))  # policy never
    assert len(approver.calls) == 3


def test_audit_has_no_secrets(broker, approver, server, tmp_path):
    run(broker.http_request("api-query", "GET", server + "/echo?x=1"))
    run(broker.http_request("api-basic", "GET", "https://evil.example.net/"))
    approver.answer = "deny"
    run(broker.http_request("api-daily", "GET", server + "/echo"))
    text = (tmp_path / "audit.jsonl").read_text()
    assert_clean(text)
    lines = [json.loads(line) for line in text.splitlines()]
    assert [line["result"] for line in lines] == [200, "refused", "denied"]
    assert lines[0]["target"] == "127.0.0.1/echo" and lines[0]["method"] == "GET"
    assert all({"ts", "tool", "credential"} <= line.keys() for line in lines)


def test_connection_refused_and_timeout_do_not_leak(broker, items, server):
    dead = f"http://127.0.0.1:{free_port()}"
    for it in items:
        it["login"]["uris"].append({"uri": dead})
    for name in ("api-query", "api-basic", "api-bearer"):
        out = run(broker.http_request(name, "GET", dead + "/x"))
        assert "ConnectError" in out["error"]
        assert_clean(out)
    out = run(broker.http_request("api-query", "GET", server + "/slow", timeout=0.3))
    assert "Timeout" in out["error"]
    assert_clean(out)


def test_exception_text_is_redacted(broker, server, monkeypatch):
    async def boom(self, method, url, **kw):
        raise RuntimeError(f"failed {url} with {dict(kw['headers'])}")
    monkeypatch.setattr(httpx.AsyncClient, "request", boom)
    for name in ("api-query", "api-basic", "api-header"):
        out = run(broker.http_request(name, "GET", server + "/echo"))
        assert f"[REDACTED:{name}]" in out["error"]
        assert_clean(out)


def test_mcp_tools_registered_and_callable(broker, server):
    app = build_app(broker)
    assert {t.name for t in run(app.list_tools())} == {"list_credentials", "http_request", "browser_login", "ssh_exec",
                                                       "win_exec", "sql_query", "rdp_open", "check_credentials"}
    res = run(app.call_tool("http_request", {"credential": "api-header", "method": "GET", "url": server + "/e"}))
    text = res.content[0].text
    assert json.loads(text)["status"] == 200
    assert_clean(text)
