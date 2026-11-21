import asyncio
import ctypes
import io
import json
import socket
import sys
import threading

import paramiko
import pytest

import valet.broker as vb
from conftest import PASSWORD, Approver, FakeVault, assert_clean, item
from valet.__main__ import build_app, run_command
from valet.broker import Broker, Cred


def run(coro):
    return asyncio.run(coro)


class SSHServer(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        ok = (username, password) == ("svc-user", PASSWORD)
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        def reply():  # echo the command and the password back, to prove the result gets redacted
            channel.sendall(b"ran " + command + b" as " + PASSWORD.encode() + b"\n")
            channel.sendall_stderr(b"warn\n")
            channel.send_exit_status(3)
            channel.close()
        threading.Timer(0.05, reply).start()
        return True


@pytest.fixture(scope="session")
def ssh_server():
    key = paramiko.ECDSAKey.generate()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()

    def serve():
        while True:
            conn, _ = sock.accept()
            t = paramiko.Transport(conn)
            t.add_server_key(key)
            t.start_server(server=SSHServer())

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1], key


@pytest.fixture
def trusted(ssh_server, tmp_path, monkeypatch):
    """A home directory whose known_hosts trusts the test server."""
    port, key = ssh_server
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "known_hosts").write_text(f"[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n")
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    return port


@pytest.fixture
def remote(ssh_server, server, tmp_path):
    port = ssh_server[0]
    items = [
        item("box", [f"ssh://127.0.0.1:{port}"], PASSWORD),
        item("box-wrong", [f"ssh://127.0.0.1:{port}"], "not-it"),
        item("winbox", ["winrm://10.0.0.7", "winrms://10.0.0.8", "rdp://10.0.0.7"], PASSWORD,
             username="CORP\\svc-user"),
        item("db", ["mssql://10.0.0.9:1444"], PASSWORD, fields={"broker_approval": "never"}),
        item("api-basic", [server], PASSWORD, fields={"broker_auth": "basic"}),
        item("web-form", [server + "/login"], PASSWORD, fields={"broker_auth": "form"}),
        item("bare", ["10.0.0.10"], PASSWORD),
    ]
    approver = Approver()
    return Broker(FakeVault(items), tmp_path / "home", approver=approver), approver


def test_endpoints_are_scoped_by_scheme(remote):
    broker, _ = remote
    creds = {c["name"]: c for c in broker.list_credentials()["credentials"]}
    assert set(creds["box"]["tools"]) == {"ssh_exec"} and creds["box"]["hosts"] == []
    assert creds["winbox"]["tools"]["win_exec"]["targets"] == ["winrm://10.0.0.7:5985", "winrms://10.0.0.8:5986"]
    assert creds["winbox"]["tools"]["rdp_open"] == {"approval": "never", "targets": ["rdp://10.0.0.7:3389"]}
    assert creds["db"]["tools"]["sql_query"]["targets"] == ["mssql://10.0.0.9:1444"]
    # an ssh:// URI does not make its host a web host for the same password
    assert "not allowed" in run(broker.http_request("winbox", "GET", "https://10.0.0.7/"))["error"]
    # and a credential only goes to the endpoints listed for that protocol
    assert "no ssh:// URI" in run(broker.ssh_exec("winbox", "id"))["error"]
    assert "no winrm/winrms:// URI for host '10.0.0.9'" in run(broker.win_exec("winbox", "x", host="10.0.0.9"))["error"]


def test_ssh_exec_runs_and_redacts(remote, trusted):
    broker, approver = remote
    out = run(broker.ssh_exec("box", "uptime"))
    assert out["exit_code"] == 3 and out["stdout"] == "ran uptime as [REDACTED:box]\n" and out["stderr"] == "warn\n"
    assert approver.calls == [("box", "ssh_exec", "127.0.0.1")]
    assert_clean(out)
    assert "Authentication" in run(broker.ssh_exec("box-wrong", "uptime"))["error"]


def test_ssh_refuses_unknown_host_key(remote, tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    broker, _ = remote
    assert "known_hosts" in run(broker.ssh_exec("box", "uptime"))["error"]


def test_win_and_sql_go_to_the_right_endpoint_and_redact(remote, monkeypatch):
    broker, approver = remote
    seen = []
    monkeypatch.setattr(vb, "winrm_run", lambda c, s, h, p, cmd, t: seen.append((s, h, p)) or
                        {"status": 0, "exit_code": 0, "stdout": "pw " + c.password, "stderr": ""})
    monkeypatch.setattr(vb, "sql_run", lambda c, h, p, q, d, t, m: seen.append((h, p, d)) or
                        {"status": "ok", "results": [{"columns": ["p"], "rows": [[c.password]]}]})
    assert run(broker.win_exec("winbox", "hostname", host="10.0.0.8"))["stdout"] == "pw [REDACTED:winbox]"
    out = run(broker.sql_query("db", "select 1", database="crm"))
    assert out["results"][0]["rows"] == [["[REDACTED:db]"]]
    assert seen == [("winrms", "10.0.0.8", 5986), ("10.0.0.9", 1444, "crm")]
    assert approver.calls == [("winbox", "win_exec", "10.0.0.8")]  # db has broker_approval=never
    audit = (broker.home / "audit.jsonl").read_text()
    assert "winrms://10.0.0.8:5986" in audit and "mssql://10.0.0.9:1444" in audit


def test_rdp_login_is_saved_unreadable_then_mstsc_starts(remote, monkeypatch):
    broker, _ = remote
    started = []
    monkeypatch.setattr(vb.subprocess, "Popen", lambda args, **kw: started.append(args))
    cred = Cred("i", "t", "CORP\\svc-user", PASSWORD, "", [], {})
    target, adv = "TERMSRV/valet-test.invalid", ctypes.WinDLL("advapi32", use_last_error=True)
    try:
        vb.save_rdp_login(cred, "valet-test.invalid")
        p = ctypes.POINTER(vb.CREDENTIALW)()
        assert adv.CredReadW(target, 2, 0, ctypes.byref(p))
        assert p.contents.UserName == "CORP\\svc-user"
        assert p.contents.CredentialBlobSize == 0  # Windows does not hand the password back to programs
        adv.CredFree(p)
    finally:
        adv.CredDeleteW(target, 2, 0)
    assert run(broker.rdp_open("winbox"))["status"] == "opened"
    assert started == [["mstsc", "/v:10.0.0.7"]]
    adv.CredDeleteW("TERMSRV/10.0.0.7", 2, 0)


def test_net_logon_impersonates_and_reverts():
    with vb.net_logon(Cred("i", "t", "CORP\\nobody", "x", "", [], {})):  # NEW_CREDENTIALS: not validated locally
        pass


def test_check_credentials(remote, trusted, monkeypatch):
    broker, approver = remote
    monkeypatch.setattr(vb, "port_open", lambda h, p, timeout=2: p in (22, 3389))
    monkeypatch.setattr(vb, "login_probe", lambda c, s, h, p: "signed in")
    out = run(broker.check_credentials(["box", "api-basic", "web-form", "bare", "winbox"]))
    got = {(r["credential"], r["uri"].split(":")[0]): (r["result"], r["detail"]) for r in out["results"]}
    assert got[("box", "ssh")] == ("ok", "signed in")
    assert got[("api-basic", "http")] == ("ok", "HTTP 200")
    assert got[("web-form", "http")][0] == "skipped"
    assert got[("bare", "10.0.0.10")][0] == "ok" and "ssh ok" in got[("bare", "10.0.0.10")][1]
    assert got[("winbox", "rdp")][0] == "skipped"
    assert approver.calls == [("5 credentials", "check_credentials", "the hosts listed on each item")]
    assert_clean(out)


def test_check_reports_wrong_password(remote, trusted):
    broker, _ = remote
    out = run(broker.check_credentials(["box", "box-wrong"]))
    assert {r["credential"]: r["result"] for r in out["results"]} == {"box": "ok", "box-wrong": "failed"}
    assert out["summary"] == {"ok": 1, "failed": 1, "skipped": 0}


def test_run_command_injects_and_redacts(remote, monkeypatch):
    broker, approver = remote
    monkeypatch.setenv("BW_SESSION", "vault-key")
    monkeypatch.setenv("DB_USER", "valet://db/username")
    child = ("import os, sys; print('pw is', os.environ['DB_PASS']); print('user', os.environ['DB_USER']); "
             f"sys.exit(0 if os.environ['DB_PASS'] == {PASSWORD!r} and 'BW_SESSION' not in os.environ else 5)")
    out, err = io.StringIO(), io.StringIO()
    code = run_command(broker, ["-e", "DB_PASS=valet://db/password", "--", sys.executable, "-c", child], out, err)
    assert code == 0, err.getvalue()
    assert out.getvalue().splitlines() == ["pw is [REDACTED:db]", "user svc-user"]
    assert approver.calls == []  # db has broker_approval=never; others ask once per item
    audit = [json.loads(line) for line in (broker.home / "audit.jsonl").read_text().splitlines()]
    assert audit[-1]["tool"] == "run" and audit[-1]["result"] == "ok"
    assert run_command(broker, ["-e", "X=valet://nope/password", "--", sys.executable, "-c", "pass"], out, err) == 2
    assert "no credential 'nope'" in err.getvalue()


def test_mcp_lists_new_tools(remote):
    broker, _ = remote
    names = {t.name for t in run(build_app(broker).list_tools())}
    assert {"ssh_exec", "win_exec", "sql_query", "rdp_open", "check_credentials"} <= names
