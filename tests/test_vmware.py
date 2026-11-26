"""VMware ESXi, vCenter and Aria (vmware.py), against a stand-in over HTTPS.

The SOAP answers in fixtures/vmware were recorded from vcsim, VMware's own vSphere simulator (govmomi), in vCenter
and ESXi mode, so the requests and parsing match the real API; problems are written into copies of them here.
vCenter's REST API (/api) and the Aria APIs are stood in for from VMware's documented answers.

Run from the repository root:  python3 -m pytest tests/test_vmware.py
"""
import asyncio
import base64
import datetime as dt
import json
import re
import ssl
import sys
import time
from pathlib import Path

import pytest
from aiohttp import web

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import vmware  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "vmware"
NO_CHECK = ssl.create_default_context()
NO_CHECK.check_hostname, NO_CHECK.verify_mode = False, ssl.CERT_NONE

FAULT = (b'<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
         b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><soapenv:Fault><faultcode>ServerFaultCode</faultcode>'
         b'<faultstring>Cannot complete login due to an incorrect user name or password.</faultstring><detail>'
         b'<InvalidLoginFault xmlns="urn:vim25" xsi:type="InvalidLogin"></InvalidLoginFault></detail></soapenv:Fault>'
         b'</soapenv:Body></soapenv:Envelope>')
ALARM_STATE = ('<AlarmState><key>alarm-7.host-21</key><entity type="HostSystem">host-21</entity><alarm type="Alarm">alarm-7</alarm>'
               '<overallStatus>red</overallStatus><time>2026-11-25T10:00:00Z</time><acknowledged>false</acknowledged></AlarmState>'
               '<AlarmState><key>alarm-9.host-37</key><entity type="HostSystem">host-37</entity><alarm type="Alarm">alarm-9</alarm>'
               '<overallStatus>yellow</overallStatus><time>2026-11-25T11:00:00Z</time><acknowledged>true</acknowledged></AlarmState>')
ALARM_NAMES = ('<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
               '<soapenv:Body><RetrievePropertiesExResponse xmlns="urn:vim25"><returnval>'
               '<objects><obj type="Alarm">alarm-7</obj><propSet><name>info.name</name><val>Host hardware fan status</val></propSet></objects>'
               '<objects><obj type="Alarm">alarm-9</obj><propSet><name>info.name</name><val>Host memory usage</val></propSet></objects>'
               '</returnval></RetrievePropertiesExResponse></soapenv:Body></soapenv:Envelope>')


def make_cert(days: float):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vcsa.example.local")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=days)).sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


class Fake:
    """vCenter (or ESXi) and the Aria appliances on one HTTPS port. problems=True writes faults into the answers."""

    def __init__(self, tmp: Path, kind="vcenter", problems=False, rest=True, cert_days=400.0):
        self.kind, self.problems, self.rest, self.cert_days, self.tmp = kind, problems, rest, cert_days, tmp
        self.calls: list[str] = []
        self.logged_out = self.rest_closed = False

    def sdk(self, op: str, body: bytes) -> bytes:
        tag = "-root" if b'<obj type="Folder"' in body else ("-alarm" if b"<type>Alarm</type>" in body else "")
        if op == "Login" and b"<password>pw</password>" not in body:
            return FAULT
        if op == "Logout":
            self.logged_out = True
        if tag == "-alarm":
            return ALARM_NAMES.encode()
        x = (FIX / self.kind / f"{op}{tag}.xml").read_text()
        if self.problems and op == "RetrievePropertiesEx" and not tag:
            # In vcsim's inventory host-21 is DC0_H0, host-37 DC0_C0_H0, host-47 DC0_C0_H1.
            # host-37 stops answering; host-47 is in maintenance mode; a red sensor on host-21 (the first in the answer);
            # the datastore at 3% free
            x = re.sub(r'(<obj type="HostSystem">host-37</obj>.*?<name>runtime.connectionState</name><val[^>]*>)connected',
                       r"\1notResponding", x, count=1, flags=re.S)
            x = re.sub(r'(<obj type="HostSystem">host-47</obj>.*?<name>runtime.inMaintenanceMode</name><val[^>]*>)false',
                       r"\1true", x, count=1, flags=re.S)
            x = x.replace("<label>Green</label><summary>Sensor is operating under normal conditions</summary><key>green</key>",
                          "<label>Red</label><summary>Sensor is critical</summary><key>red</key>", 1)
            cap = int(re.search(r"<name>summary.capacity</name><val[^>]*>(\d+)", x).group(1))
            x = re.sub(r"(<name>summary.freeSpace</name><val[^>]*>)\d+", lambda m: m.group(1) + str(cap * 3 // 100), x, count=1)
        if self.problems and tag == "-root":
            x = x.replace('ArrayOfAlarmState"></val>', f'ArrayOfAlarmState">{ALARM_STATE}</val>')
        return x.encode()

    def app(self) -> web.Application:
        app = web.Application()
        auth_ok = "Basic " + base64.b64encode(b"ro:pw").decode()

        async def sdk(req):
            body = await req.read()
            op = re.search(rb'<(\w+) xmlns="urn:vim25">', body).group(1).decode()
            self.calls.append("sdk " + op)
            out = self.sdk(op, body)
            return web.Response(body=out, content_type="text/xml", status=500 if out is FAULT else 200)

        def rest_get(path, value):
            async def h(req):
                self.calls.append("GET " + path)
                if req.headers.get("vmware-api-session-id") != "tok":
                    return web.json_response({"error_type": "UNAUTHENTICATED"}, status=401)
                return web.json_response(value)
            app.router.add_get(path, h)

        async def session(req):
            if not self.rest:
                return web.Response(status=404, text="404 page not found")
            if req.headers.get("Authorization") != auth_ok:
                return web.json_response({"error_type": "UNAUTHENTICATED"}, status=401)
            return web.json_response("tok", status=201)

        async def session_end(req):
            self.rest_closed = True
            return web.Response(status=204)
        app.router.add_post("/sdk", sdk)
        app.router.add_post("/api/session", session)
        app.router.add_delete("/api/session", session_end)
        p = self.problems
        for k in ("system", "load", "mem", "storage", "swap", "database-storage", "software-packages"):
            rest_get(f"/api/appliance/health/{k}", "orange" if p and k == "storage" else "yellow" if p and k == "system" else "green")
        rest_get("/api/appliance/system/version", {"version": "8.0.3.00400", "build": "24322831", "product": "VMware vCenter Server",
                                                   "type": "vCenter Server with an embedded Platform Services Controller",
                                                   "releasedate": "October 9, 2024"})
        rest_get("/api/appliance/system/uptime", 1234567.8)
        rest_get("/api/vcenter/services", {
            "vpxd": {"name_key": "cis.vpxd.ServiceName", "startup_type": "AUTOMATIC", "health": "HEALTHY", "state": "STARTED"},
            "vsphere-ui": {"name_key": "cis.vsphere-ui.ServiceName", "startup_type": "AUTOMATIC", "health": "HEALTHY",
                           "state": "STOPPED" if p else "STARTED"},
            "vmcam": {"name_key": "cis.vmcam.ServiceName", "startup_type": "MANUAL", "state": "STOPPED"}})
        rest_get("/api/appliance/recovery/backup/schedules", {"default": {"enable": True, "location": "sftp://backup.example.local/vcsa"}})
        rest_get("/api/appliance/recovery/backup/job/details", {
            "20261124-020000-24322831": {"status": "SUCCEEDED", "start_time": "2026-11-24T02:00:00.000Z", "end_time": "2026-11-24T02:09:00.000Z", "type": "SCHEDULED", "size": 2147483648},
            "20261125-020000-24322831": {"status": "FAILED" if p else "SUCCEEDED", "start_time": "2026-11-25T02:00:00.000Z",
                                         "end_time": "2026-11-25T02:03:00.000Z", "type": "SCHEDULED"}})
        rest_get("/api/appliance/update", {"state": "UPDATES_PENDING" if p else "UP_TO_DATE", "latest_query_time": "2026-11-25T06:00:00.000Z"})
        rest_get("/api/appliance/update/pending", [{"version": "8.0.3.00500", "name": "VC-8.0U3e", "severity": "CRITICAL"}])

        # Aria Operations
        async def ops_token(req):
            b = await req.json()
            if (b.get("username"), b.get("password"), b.get("authSource")) != ("ro", "pw", "local"):
                return web.json_response({"message": "Invalid credentials"}, status=401)
            return web.json_response({"token": "ops1", "validity": int(time.time() * 1000) + 3600000})

        def ops(path, value):
            async def h(req):
                if req.headers.get("Authorization") != "OpsToken ops1":
                    return web.json_response({}, status=401)
                return web.json_response(value)
            app.router.add_get(path, h)
        app.router.add_post("/suite-api/api/auth/token/acquire", ops_token)
        app.router.add_post("/suite-api/api/auth/token/release", lambda r: web.Response(status=200))
        ops("/suite-api/api/deployment/node/status", {"status": "OFFLINE" if p else "ONLINE"})
        ops("/suite-api/api/versions/current", {"releaseName": "VMware Aria Operations 8.18.2", "major": 8, "minor": 18, "buildNumber": 24137489})
        ops("/suite-api/api/alerts", {"alerts": [{"alertLevel": "CRITICAL", "status": "ACTIVE", "alertDefinitionName": "Host has lost connection"},
                                                 {"alertLevel": "WARNING", "status": "ACTIVE", "alertDefinitionName": "Datastore filling up"}]})

        # Aria Automation
        async def health(req):
            return web.Response(status=500 if p else 200, text="")

        async def csp_login(req):
            b = await req.json()
            if (b.get("username"), b.get("password")) != ("ro", "pw"):
                return web.json_response({"message": "Invalid user credentials"}, status=401)
            return web.json_response({"cspAuthToken": "eyJ.x.y"})
        app.router.add_get("/health", health)
        app.router.add_get("/iaas/api/about", lambda r: web.json_response({"latestApiVersion": "2021-07-15", "supportedApis": []}))
        app.router.add_post("/csp/gateway/am/api/login", csp_login)

        # Aria Operations for Logs
        async def li_session(req):
            b = await req.json()
            if (b.get("username"), b.get("password")) != ("ro", "pw"):
                return web.json_response({"errorMessage": "Invalid username or password"}, status=401)
            return web.json_response({"userId": "u1", "sessionId": "li1", "ttl": 1800})

        async def li_version(req):
            if req.headers.get("Authorization") != "Bearer li1":
                return web.json_response({}, status=401)
            return web.json_response({"version": "8.18.0-24029231", "releaseName": "GA"})
        app.router.add_post("/api/v2/sessions", li_session)
        app.router.add_get("/api/v2/version", li_version)
        return app

    async def __aenter__(self):
        pem, key = make_cert(self.cert_days)
        (self.tmp / "c.pem").write_bytes(pem)
        (self.tmp / "k.pem").write_bytes(key)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.tmp / "c.pem", self.tmp / "k.pem")
        self.runner = web.AppRunner(self.app())
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0, ssl_context=ctx)
        await site.start()
        self.url = f"https://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        return self

    async def __aexit__(self, *a):
        await self.runner.cleanup()


def run(coro):
    return asyncio.run(coro)


def test_vcenter_healthy(tmp_path):
    async def go():
        async with Fake(tmp_path) as f:
            d = await vmware.poll(f.url, "vsphere", "ro", "pw", NO_CHECK, 20)
            return f, d
    f, d = run(go())
    assert d["product"] == "vcenter" and d["version"] == "6.5.0"        # vcsim's version
    assert [h["name"] for h in d["hosts"]] == ["DC0_C0_H0", "DC0_C0_H1", "DC0_C0_H2", "DC0_H0"]
    assert all(h["connection"] == "connected" and h["sensors"] for h in d["hosts"])
    assert d["vms_on"] == 4 and d["clusters"][0]["name"] == "DC0_C0"
    assert d["datastores"][0]["free_pct"] > 90 and d["rest"] == "ok" and d["appliance_version"] == "8.0.3.00400"
    assert d["uptime_s"] == 1234567 and d["update"]["state"] == "UP_TO_DATE" and d["backup_jobs"][0]["status"] == "SUCCEEDED"
    assert d["services"] == {"count": 3, "problems": []}               # a MANUAL service that's stopped is fine
    assert d["cert"]["subject"] == "vcsa.example.local" and d["cert"]["self_signed"]
    assert f.logged_out and f.rest_closed                              # both sessions closed again
    assert not [c for c in f.calls if not (c.startswith("GET") or c.startswith("sdk"))]  # only reads
    items = vmware.problems(d)
    assert items == []
    ok, ms, detail = vmware.evaluate(d, items)
    assert ok and ms is not None and detail == "vCenter 6.5.0; 4 hosts; 4 VMs on"


def test_vcenter_problems(tmp_path):
    async def go():
        async with Fake(tmp_path, problems=True) as f:
            return await vmware.poll(f.url, "vsphere", "ro", "pw", NO_CHECK, 20)
    d = run(go())
    items = vmware.problems(d)
    got = {(i["level"], i["what"], i["detail"]) for i in items}
    assert ("crit", "Host DC0_C0_H0", "not responding") in got
    assert ("crit", "DC0_H0: VMware Rollup Health State", "system red") in got
    assert ("crit", "Datastore LocalDS_0", "3.0% free") in got
    assert ("crit", "Alarm: Host hardware fan status", "DC0_H0") in got
    assert not [i for i in items if "memory usage" in i["what"]]       # acknowledged in vCenter: doesn't count
    assert ("crit", "Appliance health: storage", "orange") not in got and ("warn", "Appliance health: storage", "orange") in got
    assert ("crit", "Appliance backup", "last backup failed (2026-11-25T02:03:00.000Z)") in got
    assert ("warn", "Service vsphere-ui", "stopped, set to start automatically") in got
    assert [h["maintenance"] for h in d["hosts"]] == [False, True, False, False]
    assert d["update"] == {"state": "UPDATES_PENDING", "checked": "2026-11-25T06:00:00.000Z", "version": "8.0.3.00500"}
    ok, _, detail = vmware.evaluate(d, items)
    assert not ok and "maintenance: DC0_C0_H1" in detail and "update available (8.0.3.00500)" in detail and "+" in detail
    # Ignoring the crit ones (as the device's Ignore does) leaves amber
    assert vmware.evaluate(d, [i for i in items if i["level"] == "warn"])[3] == "warn"


def test_esxi_and_old_vcenter(tmp_path):
    async def go():
        async with Fake(tmp_path, kind="esxi") as f:
            esx = await vmware.poll(f.url, "vsphere", "ro", "pw", NO_CHECK, 20)
            esx_calls = list(f.calls)
        async with Fake(tmp_path, rest=False) as f:
            old = await vmware.poll(f.url, "vsphere", "ro", "pw", NO_CHECK, 20)
        return esx, esx_calls, old
    esx, calls, old = run(go())
    assert esx["product"] == "esxi" and len(esx["hosts"]) == 1 and esx["clusters"] == [] and "rest" not in esx
    assert not [c for c in calls if "/api/" in c]                     # ESXi has no REST API to ask
    assert vmware.evaluate(esx, vmware.problems(esx))[2] == "ESXi 6.5.0; 2 VMs on"
    assert old["rest"] == "unavailable" and "health" not in old          # vCenter before 7.0 U2: SOAP only


def test_wrong_password_and_not_vmware(tmp_path):
    async def go():
        async with Fake(tmp_path) as f:
            with pytest.raises(vmware.VmwareError) as e1:
                await vmware.poll(f.url, "vsphere", "ro", "nope", NO_CHECK, 20)
            with pytest.raises(vmware.VmwareError) as e2:
                await vmware.poll(f.url, "aria_ops", "ro", "nope", NO_CHECK, 20)
        app = web.Application()
        app.router.add_post("/sdk", lambda r: web.Response(text="<html>hello</html>", content_type="text/html"))
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        try:
            with pytest.raises(vmware.VmwareError) as e3:
                await vmware.poll(f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}", "vsphere", "ro", "pw", None, 10)
        finally:
            await runner.cleanup()
        return e1.value, e2.value, e3.value
    e1, e2, e3 = run(go())
    assert e1.login and "user name and password" in str(e1)
    assert e2.login
    assert not e3.login and "not vSphere" in str(e3)


def test_aria(tmp_path):
    async def go(p):
        async with Fake(tmp_path, problems=p) as f:
            return [await vmware.poll(f.url, k, "ro", "pw", NO_CHECK, 20) for k in ("aria_ops", "aria_auto", "aria_logs")]
    ops, auto, logs = run(go(False))
    assert ops["node_status"] == "ONLINE" and ops["version"] == "VMware Aria Operations 8.18.2"
    assert ops["alerts"]["critical"] == 1 and ops["alerts"]["top"] == [{"name": "Host has lost connection", "level": "critical"}]
    assert auto == {**auto, "health_page": "healthy", "version": "2021-07-15", "login": "ok"}
    assert logs["version"] == "8.18.0-24029231" and logs["login"] == "ok"
    assert vmware.problems(auto) == [] and vmware.problems(logs) == []
    assert vmware.problems(ops) == [{"level": "warn", "what": "Aria Operations alerts", "detail": "1 critical"}]
    ops, auto, _ = run(go(True))
    assert {"level": "crit", "what": "Aria Operations", "detail": "node offline"} in vmware.problems(ops)
    assert vmware.problems(auto) == [{"level": "crit", "what": "Aria Automation", "detail": "/health: HTTP 500"}]


def test_certificate_expiry(tmp_path):
    async def go():
        async with Fake(tmp_path, kind="esxi", cert_days=10) as f:
            return await vmware.poll(f.url, "vsphere", "ro", "pw", NO_CHECK, 20)
    d = run(go())
    items = vmware.problems(d, cert_warn=30, cert_crit=14)
    assert [i for i in items if i["what"] == "Certificate"] == [{"level": "crit", "what": "Certificate", "detail": "expires in 9 days"}]
    assert vmware.problems(d, cert_warn=30, cert_crit=7)[0]["level"] == "warn"


def test_check_in_rollcall(tmp_path, monkeypatch):
    """The check on a device: presets, the form, the password kept for its own server only, ignore, readings."""
    import main
    import readings
    from test_ip_change_and_acks import monitor
    assert main.parse_check("vmware:vsphere")[0]["kind"] == "vmware"
    assert main.parse_check("vmware:aria_ops")[0]["entity"] == "aria_ops"
    with pytest.raises(ValueError):
        main.parse_check("vmware:other")
    entry = main.validate_entry({"name": "VCSA", "host": "10.0.1.20", "checks": ["vmware:vsphere"],
                                 "vmware_url": "https://vcsa.example.local", "vmware_user": "rollcall@vsphere.local", "vmware_pass": "pw"})
    assert (entry["vmware_url"], entry["vmware_user"], entry["vmware_pass"]) == ("https://vcsa.example.local", "rollcall@vsphere.local", "pw")
    with pytest.raises(ValueError):
        main.validate_entry({"name": "VCSA", "host": "10.0.1.20", "checks": [], "vmware_url": "http://vcsa.example.local"})
    m, _ = monitor(tmp_path, monkeypatch, [{"id": "vc", "name": "VCSA", "host": "127.0.0.1", "checks": ["vmware:vsphere"],
                                            "vmware_user": "ro", "vmware_pass": "pw"}])
    h = m.hosts["vc"]
    s = next(x for x in h.services if x.kind == "vmware")

    async def go():
        async with Fake(tmp_path, problems=True) as f:
            h.vm_url = f.url
            r1 = await m.vmware_check(h, s, 1000.0)
            r2 = await m.vmware_check(h, s, 1060.0)  # within 5 minutes: not read again
            n = len(f.calls)
            h.vm_ignore = [i["what"] for i in h.vm_items if i["level"] == "crit"]
            r3 = m.vmware_result(h)
            return r1, r2, r3, n, len(f.calls)
    r1, r2, r3, n1, n2 = run(go())
    assert not r1[0] and len(r1) == 3 and r2 == r1 and n1 == n2
    assert len(r3) == 4 and r3[3] == "warn" and all(i["ignored"] for i in h.vm_items if i["level"] == "crit")
    ids = {r["id"] for r in readings.catalog("vmware", h.vm_data)}
    assert {"vms_on", "hosts_maintenance", "hosts_disconnected", "alarms", "ds_localds_0", "cert_days"} <= ids
    assert next(r for r in readings.catalog("vmware", h.vm_data) if r["id"] == "hosts_disconnected")["value"] == 1
    # No account: amber, asks for one
    h.vm_pass = ""
    assert asyncio.run(m.vmware_check(h, s, 5000.0))[2] == "enter a read-only VMware account under Edit"
