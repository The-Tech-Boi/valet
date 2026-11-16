import asyncio

from conftest import Handler, assert_clean


def test_login_with_totp(broker, cdp, server, tmp_path):
    out = asyncio.run(broker.browser_login("web"))  # opens the item's first URI in a new tab
    assert out["status"] == "submitted", out
    assert out["url"] == server + "/welcome" and out["title"] == "Welcome"
    assert_clean(out)
    assert_clean((tmp_path / "audit.jsonl").read_text())


def test_login_without_totp_reuses_tab(broker, cdp, server, approver):
    asyncio.run(broker.browser_login("web-plain", server + "/login"))
    Handler.seen.clear()
    out = asyncio.run(broker.browser_login("web-plain", server + "/login"))
    assert out["status"] == "submitted" and out["title"] == "Welcome", out
    assert len(approver.calls) == 2  # default policy for browser_login is daily; "once" asks again
    assert_clean(out)


def test_wrong_password_reported_without_leak(broker, items, cdp, server):
    items[7]["login"]["password"] = "Wr0ng-test-pass"
    out = asyncio.run(broker.browser_login("web"))
    assert "still visible" in out["status"], out
    assert out["title"] == "Sign in"
    assert "Wr0ng" not in str(out)
    assert_clean(out)


def test_refuses_to_type_on_foreign_host(broker, cdp, server):
    Handler.seen.clear()
    out = asyncio.run(broker.browser_login("web", server + "/elsewhere"))  # redirects to localhost
    assert "may not use" in out["error"], out
    assert not any(r["path"] == "/login" and r["body"] for r in Handler.seen)


def test_api_item_refused_for_browser(broker, cdp):
    assert "only form or ntlm items" in asyncio.run(broker.browser_login("api-basic"))["error"]


def test_no_browser_does_not_leak(broker):
    out = asyncio.run(broker.browser_login("web"))  # cdp points at a closed port
    assert "error" in out
    assert_clean(out)
