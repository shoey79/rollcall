"""Who can do what: every route that changes something, tried as an ordinary Home Assistant user, an editor (named
in `editors`, not an admin) and an admin. Ordinary users can change nothing; editors everything except the admins-
only routes (exports and imports hold the private keys, security review RC-02); admins everything.

Run from the repository root:  python3 -m pytest tests/test_roles.py
"""
import asyncio
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
main = pytest.importorskip("main")
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402
from test_upstream import FakeHA  # noqa: E402

ADMIN = {"u-admin": "owner"}
USERS = [{"id": "u-admin", "name": "owner", "is_admin": True}, {"id": "u-ed", "name": "helper", "is_admin": False},
         {"id": "u-guest", "name": "guest", "is_admin": False}]
AS = {"user": {"X-Remote-User-Id": "u-guest", "X-Remote-User-Name": "guest"},
      "editor": {"X-Remote-User-Id": "u-ed", "X-Remote-User-Name": "helper"},
      "admin": {"X-Remote-User-Id": "u-admin", "X-Remote-User-Name": "owner"}}

# Admins only. Anything else that changes something is for editors and admins.
ADMIN_ONLY = {("GET", "/api/export"), ("POST", "/api/hints/test"), ("POST", "/api/import"), ("POST", "/api/import/chunk"),
              ("POST", "/api/database/compact"), ("POST", "/api/agents/tls"), ("POST", "/api/agents/legacy-updates"),
              ("POST", "/api/whats-new/seen")}
ADMIN_ONLY_PREFIX = ("/api/messages",)
# GET routes that show what only someone who can make changes should see
EDITOR_GETS = {"/api/database", "/api/log", "/api/agents", "/api/agents/msi", "/api/agents/script", "/api/discovery",
               "/api/ha/devices", "/api/ha/entities", "/api/settings"}
ADMIN_GETS = {"/api/messages", "/api/changelog"}  # What's new and its changelog: admins only
# Routes anyone viewing the panel may use, though they're not GETs (they change nothing)
OPEN = {("POST", "/api/check/{key}")}   # Check now: only asks for a fresh check


class HA(FakeHA):
    enabled = True
    session = None
    async def list_users(self): return USERS
    async def write_options(self, *_a, **_k): return None
    async def addon_info(self, *_a, **_k): return {}


def need(method: str, path: str) -> str:
    if (method, path) in ADMIN_ONLY or (path.startswith(ADMIN_ONLY_PREFIX) and method != "GET") or (method == "GET" and path in ADMIN_GETS):
        return "admin"
    if method != "GET" or path in EDITOR_GETS:
        return "editor"
    return "anyone"


@pytest.fixture
def app(tmp_path, monkeypatch):
    for name, fn in (("HOSTS_PATH", "hosts.json"), ("IMPORT_MARK", "imported.json"), ("MAINT_PATH", "maint.json"),
                     ("AGENT_SETTINGS", "agent_settings.json"), ("DISCOVERY_PATH", "discovery.json"),
                     ("DB_HEALTH_PATH", "db_health.json"), ("CLAUDE_HINTS_PATH", "claude_hints.json"),
                     ("MESSAGES_PATH", "messages.json")):
        monkeypatch.setattr(main, name, tmp_path / fn)
    monkeypatch.setattr(main, "VULN_DIR", tmp_path / "vulns")
    monkeypatch.setattr(main, "SUPERVISOR_TOKEN", "test-token")   # as inside Home Assistant
    opts = {**main.DEFAULTS, "editors": ["helper"]}
    ha = HA()
    m = main.Monitor(opts, main.Store(tmp_path / "db.sqlite"), ha)
    return main.build_app(m, main.Access(opts, ha), None)


def routes(app):
    out = set()
    for r in app.router.routes():
        info = r.resource.get_info() if r.resource else {}
        path = info.get("path") or info.get("formatter") or ""
        if r.method in ("HEAD", "OPTIONS") or not path.startswith("/api/"):
            continue
        out.add((r.method, path))
    return sorted(out)


def test_every_route_needs_the_right_role(app):
    found = routes(app)
    assert ("GET", "/api/export") in found and len(found) > 60

    async def go():
        wrong = []
        async with TestClient(TestServer(app)) as c:
            for method, path in found:
                url = re.sub(r"\{[^}]+\}", "nosuch", path)
                want = need(method, path)
                for who in ("user", "editor", "admin"):
                    allowed = want == "anyone" or (want == "editor" and who != "user") or (want == "admin" and who == "admin") \
                        or (method, path) in OPEN
                    r = await c.request(method, url, headers=AS[who], data=b"{}" if method != "GET" else None)
                    blocked = r.status == 403 and b"admin" in (await r.read())
                    if blocked == allowed:
                        wrong.append(f"{method} {path} as {who}: {r.status} (expected {'allowed' if allowed else 'blocked'})")
        return wrong
    wrong = asyncio.run(go())
    assert not wrong, "\n".join(wrong)
