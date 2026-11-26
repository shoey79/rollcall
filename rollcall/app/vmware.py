"""VMware: ESXi hosts, vCenter Server and the Aria appliances, read with a read-only account.

Everything here only reads: no call changes anything on the VMware side. Give Rollcall an account with the
Read-only role (ESXi: Permissions; vCenter: Administration, Access Control, Global Permissions, Read-only,
propagated). The password is only ever sent to the address set for the device; redirects aren't followed.

ESXi and vCenter: the vSphere Web Services (SOAP) API at /sdk, which both have
  RetrieveServiceContent      product, version, build, and whether it's an ESXi host or a vCenter
  Login / Logout              a session for the account (cookie vmware_soap_session)
  CreateContainerView + RetrievePropertiesEx   in one pass, from the root folder down:
      HostSystem              name, connection state, maintenance mode, power, boot time, product,
                              hardware, CPU/memory use, hardware health sensors and status, alarms
      Datastore               name, capacity, free space, accessible
      VirtualMachine          name, power state (templates left out)
      ClusterComputeResource  name, overall status, HA and DRS on or off (vCenter)
  the root folder's triggeredAlarmState, and each triggered alarm's name
vCenter 7.0 U2 and later also has the REST API at /api (a session from POST /api/session):
  /api/appliance/health/{system,load,mem,storage,swap,database-storage,software-packages}
                              green, yellow, orange, red or gray
  /api/appliance/system/version, /api/appliance/system/uptime
  /api/vcenter/services       each service's state, health and startup type
  /api/appliance/recovery/backup/schedules, /api/appliance/recovery/backup/job/details
                              the appliance's file-based backup and its latest jobs
  /api/appliance/update       whether an update is waiting
vSAN health needs VMware's separate vSAN API, which isn't read; vSAN datastores' free space is.

Aria Operations: POST /suite-api/api/auth/token/acquire, then /suite-api/api/deployment/node/status (ONLINE),
  /suite-api/api/versions/current and the active alerts (/suite-api/api/alerts?activeOnly=true).
Aria Automation: GET /health (no login), /iaas/api/about (version) and a login to
  /csp/gateway/am/api/login, which shows the account works.
Aria Operations for Logs: POST /api/v2/sessions, then GET /api/v2/version.

The certificate each one presents is read from the connection itself, for its expiry.
"""
from __future__ import annotations

import asyncio
import json
import re
import ssl
import time
import xml.etree.ElementTree as ET
from base64 import b64encode
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import aiohttp

PRODUCTS = {"vsphere": "ESXi or vCenter", "esxi": "ESXi", "vcenter": "vCenter", "aria_ops": "Aria Operations",
            "aria_auto": "Aria Automation", "aria_logs": "Aria Operations for Logs"}
URL_RE = re.compile(r"^https://[A-Za-z0-9.\-]+(:\d{1,5})?/?$|^https://\[[0-9A-Fa-f:]+\](:\d{1,5})?/?$")
MAX_BYTES = 16 * 1024 * 1024   # a big vCenter's hosts, datastores and VMs in one answer
MAX_VMS = 5000
SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
COLOURS = {"green": 0, "gray": 0, "grey": 0, "unknown": 0, "yellow": 1, "orange": 1, "red": 2}


class VmwareError(Exception):
    """It couldn't be read. login is True when the account was turned down."""

    def __init__(self, msg: str, login: bool = False):
        super().__init__(msg)
        self.login = login


def clean_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if url and not URL_RE.match(url):
        raise ValueError("Enter the address as https://name or https://name:port")
    return url


def default_url(host: str) -> str:
    return f"https://[{host}]" if ":" in host else f"https://{host}"


def same_server(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.hostname or "").lower() == (pb.hostname or "").lower() and (pa.port or 443) == (pb.port or 443)


# ---- HTTP, with the certificate the server presented ----

class _Http:
    def __init__(self, base: str, tls, timeout: float):
        self.base, self.tls, self.timeout = base.rstrip("/"), tls, timeout
        self.session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
        self.ms: float | None = None

    async def close(self):
        await self.session.close()

    async def req(self, method: str, path: str, *, headers: dict | None = None, body: bytes | None = None,
                  ok=(200, 201, 204), login_codes=(401, 403)) -> tuple[int, bytes]:
        t0 = time.monotonic()
        try:
            async with self.session.request(method, self.base + path, headers={"User-Agent": "Rollcall", **(headers or {})},
                                            data=body, ssl=self.tls, allow_redirects=False,
                                            timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                if self.ms is None:
                    self.ms = round((time.monotonic() - t0) * 1000, 1)
                data = bytearray()
                async for part in r.content.iter_chunked(65536):
                    data += part
                    if len(data) > MAX_BYTES:
                        raise VmwareError("answer too large")
                if r.status in login_codes:
                    raise VmwareError("the account was turned down (check the user name and password)", login=True)
                if 300 <= r.status < 400:
                    raise VmwareError(f"redirected (HTTP {r.status}); set the address it redirects to")
                if ok and r.status not in ok:
                    raise _Status(r.status, bytes(data))
                return r.status, bytes(data)
        except asyncio.TimeoutError:
            raise VmwareError("no answer (timed out)") from None
        except aiohttp.ClientConnectorCertificateError as err:
            raise VmwareError(f"certificate problem ({type(err).__name__})") from None
        except aiohttp.ClientConnectorError as err:
            raise VmwareError((getattr(err, "strerror", None) or "can't connect").lower()) from None
        except aiohttp.ClientError as err:
            raise VmwareError(f"connection failed ({type(err).__name__})") from None

    async def json(self, method: str, path: str, **kw):
        _, data = await self.req(method, path, headers={"Accept": "application/json", **kw.pop("headers", {})}, **kw)
        if not data.strip():
            return None
        try:
            return json.loads(data)
        except ValueError:
            raise VmwareError(f"{path} didn't answer with JSON") from None


class _Status(VmwareError):
    def __init__(self, status: int, body: bytes):
        super().__init__(f"HTTP {status}")
        self.status, self.body = status, body


# ---- vSphere SOAP ----

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _py(el: ET.Element):
    """A SOAP value as Python: text, a managed object reference ("Type", "id"), or a dict of its fields
    (a field that repeats is a list)."""
    kids = list(el)
    if not kids:
        if "type" in el.attrib:
            return (el.attrib["type"], (el.text or "").strip())
        return (el.text or "").strip()
    out: dict = {}
    for k in kids:
        key, v = _local(k.tag), _py(k)
        if key in out:
            if not isinstance(out[key], list) or not out.get("_list_" + key):
                out[key] = [out[key]]
                out["_list_" + key] = True
            out[key].append(v)
        else:
            out[key] = v
    return {k: v for k, v in out.items() if not k.startswith("_list_")}


def _list(v) -> list:
    """An ArrayOfX value, or one item or several, as a list."""
    if v is None or v == "":
        return []
    if isinstance(v, dict) and len(v) == 1 and next(iter(v))[:1].isupper():
        v = next(iter(v.values()))
    return v if isinstance(v, list) else [v]


def _moref(t: str, v: str, tag: str = "_this") -> str:
    return f'<{tag} type="{escape(t)}">{escape(v)}</{tag}>'


class _Soap:
    def __init__(self, http: _Http):
        self.http, self.action = http, "urn:vim25"

    async def call(self, op: str, inner: str) -> ET.Element:
        body = (f'<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="{SOAP_NS}" '
                f'xmlns:xsi="{XSI}" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soapenv:Body>'
                f'<{op} xmlns="urn:vim25">{inner}</{op}></soapenv:Body></soapenv:Envelope>').encode()
        status, data = await self.http.req("POST", "/sdk", headers={"Content-Type": "text/xml; charset=utf-8",
                                                                    "SOAPAction": self.action},
                                           body=body, ok=None, login_codes=())
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            raise VmwareError("not vSphere? /sdk didn't answer with SOAP" if status == 200 else f"HTTP {status} from /sdk") from None
        fault = root.find(f".//{{{SOAP_NS}}}Fault")
        if fault is not None:
            msg = (fault.findtext("faultstring") or "").strip()
            detail = fault.find("detail")
            kind = _local(list(detail)[0].tag) if detail is not None and len(detail) else ""
            if kind in ("InvalidLoginFault", "InvalidLogin", "NotAuthenticatedFault", "NoPermissionFault") or \
                    "incorrect user name or password" in msg.lower():
                raise VmwareError("the account was turned down (check the user name and password)"
                                  if "Login" in kind or "password" in msg.lower() else
                                  f"the account can't read this ({msg or kind})", login=True)
            raise VmwareError(f"{op}: {msg or kind or 'fault'}")
        resp = root.find(f".//{{urn:vim25}}{op}Response")
        if resp is None:
            raise VmwareError(f"not vSphere? no answer to {op}")
        return resp

    async def retrieve(self, pc, specs: list[tuple[str, list[str]]], objs: str, max_objects: int = 1000) -> list[dict]:
        """RetrievePropertiesEx, following its continuation token; each object as {"_ref": (type, id), path: value}."""
        props = "".join(f"<propSet><type>{t}</type>" + "".join(f"<pathSet>{p}</pathSet>" for p in paths) + "</propSet>"
                        for t, paths in specs)
        resp = await self.call("RetrievePropertiesEx", _moref(*pc) + f"<specSet>{props}{objs}</specSet>"
                               f"<options><maxObjects>{max_objects}</maxObjects></options>")
        out: list[dict] = []
        while True:
            ret = resp.find("{urn:vim25}returnval")
            if ret is None:
                break
            for o in ret.findall("{urn:vim25}objects"):
                ref = o.find("{urn:vim25}obj")
                row = {"_ref": (ref.attrib.get("type", ""), (ref.text or "").strip())}
                for ps in o.findall("{urn:vim25}propSet"):
                    v = ps.find("{urn:vim25}val")
                    row[ps.findtext("{urn:vim25}name")] = _py(v) if v is not None else None
                out.append(row)
                if len(out) > MAX_VMS + 2000:
                    return out
            token = ret.findtext("{urn:vim25}token")
            if not token:
                break
            resp = await self.call("ContinueRetrievePropertiesEx", _moref(*pc) + f"<token>{escape(token)}</token>")
        return out


HOST_PROPS = ["name", "overallStatus", "runtime.connectionState", "runtime.inMaintenanceMode", "runtime.powerState",
              "runtime.bootTime", "summary.config.product.fullName", "summary.config.product.version",
              "summary.config.product.build", "summary.hardware.vendor", "summary.hardware.model",
              "summary.hardware.cpuMhz", "summary.hardware.numCpuCores", "summary.hardware.memorySize",
              "summary.quickStats.overallCpuUsage", "summary.quickStats.overallMemoryUsage",
              "runtime.healthSystemRuntime", "triggeredAlarmState"]
DS_PROPS = ["name", "summary.capacity", "summary.freeSpace", "summary.accessible", "summary.type", "overallStatus"]
VM_PROPS = ["name", "runtime.powerState", "config.template"]
CLUSTER_PROPS = ["name", "overallStatus", "configuration.dasConfig.enabled", "configuration.drsConfig.enabled"]


def _num(v, default=None):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _bool(v) -> bool | None:
    return None if v in (None, "") else str(v).lower() == "true"


def _sensor(s: dict) -> dict:
    """A numeric sensor as a reading: currentReading is scaled by 10^unitModifier."""
    hs = s.get("healthState") or {}
    raw, mod = _num(s.get("currentReading")), _num(s.get("unitModifier"), 0)
    val = None if raw is None else round(raw * (10 ** mod), 2)
    unit = {"degrees C": "°C", "rpm": "RPM", "volts": "V", "amps": "A", "watts": "W", "percent": "%"}.get(
        s.get("baseUnits") or "", s.get("baseUnits") or "")
    return {"name": (s.get("name") or "").strip()[:120], "type": s.get("sensorType") or "",
            "state": (hs.get("key") or "unknown").lower(), "value": val, "unit": unit}


def _hw_status(h: dict) -> list[dict]:
    """hardwareStatusInfo: memory, CPU and storage elements whose status isn't green."""
    out = []
    info = (h or {}).get("hardwareStatusInfo") or {}
    for key, what in (("memoryStatusInfo", "Memory"), ("cpuStatusInfo", "CPU"), ("storageStatusInfo", "Storage")):
        for e in _list(info.get(key)):
            if not isinstance(e, dict):
                continue
            st = ((e.get("status") or {}).get("key") or "").lower()
            if st and st not in ("green", "unknown"):
                out.append({"name": f"{what}: {(e.get('name') or '').strip()[:100]}", "state": st})
    return out


async def _vsphere(http: _Http, user: str, password: str) -> dict:
    soap = _Soap(http)
    sc = await soap.call("RetrieveServiceContent", _moref("ServiceInstance", "ServiceInstance"))
    sc = _py(sc.find("{urn:vim25}returnval"))
    about = sc.get("about") or {}
    if about.get("apiVersion"):
        soap.action = f"urn:vim25/{about['apiVersion']}"
    product = "vcenter" if about.get("apiType") == "VirtualCenter" else "esxi"
    sm, pc, vm_mgr, root = sc.get("sessionManager"), sc.get("propertyCollector"), sc.get("viewManager"), sc.get("rootFolder")
    if not (sm and pc and vm_mgr and root):
        raise VmwareError("not vSphere? the service content is incomplete")
    await soap.call("Login", _moref(*sm) + f"<userName>{escape(user)}</userName><password>{escape(password)}</password>")
    d: dict = {"product": product, "name": about.get("name") or "", "full_name": about.get("fullName") or "",
               "version": about.get("version") or "", "build": about.get("build") or "", "api": about.get("apiVersion") or ""}
    try:
        types = "".join(f"<type>{t}</type>" for t in ("HostSystem", "Datastore", "VirtualMachine", "ClusterComputeResource"))
        view = await soap.call("CreateContainerView", _moref(*vm_mgr) + _moref(*root, tag="container") + types +
                               "<recursive>true</recursive>")
        vref = _py(view.find("{urn:vim25}returnval"))
        objs = (f'<objectSet>{_moref(*vref, tag="obj")}<skip>true</skip><selectSet xsi:type="TraversalSpec">'
                f"<name>view</name><type>ContainerView</type><path>view</path><skip>false</skip></selectSet></objectSet>")
        try:
            rows = await soap.retrieve(pc, [("HostSystem", HOST_PROPS), ("Datastore", DS_PROPS),
                                            ("VirtualMachine", VM_PROPS), ("ClusterComputeResource", CLUSTER_PROPS)], objs)
        finally:
            try:
                await soap.call("DestroyView", _moref(*vref))
            except VmwareError:
                pass
        names = {r["_ref"]: r.get("name") or r["_ref"][1] for r in rows}
        alarms = []
        root_rows = await soap.retrieve(pc, [("Folder", ["triggeredAlarmState"])], f"<objectSet>{_moref(*root, tag='obj')}</objectSet>")
        for r in root_rows + [r for r in rows if r["_ref"][0] == "HostSystem"]:
            for a in _list(r.get("triggeredAlarmState")):
                if isinstance(a, dict) and a.get("alarm"):
                    alarms.append(a)
        seen, uniq = set(), []
        for a in alarms:
            k = (tuple(a["alarm"]), tuple(a.get("entity") or ()))
            if k not in seen:
                seen.add(k)
                uniq.append(a)
        anames = {}
        if uniq:
            refs = {tuple(a["alarm"]) for a in uniq}
            aobjs = "".join(f"<objectSet>{_moref(*r, tag='obj')}</objectSet>" for r in refs)
            try:
                for r in await soap.retrieve(pc, [("Alarm", ["info.name"])], aobjs):
                    anames[r["_ref"]] = r.get("info.name") or ""
            except VmwareError:
                pass
        d["alarms"] = [{"name": anames.get(tuple(a["alarm"])) or a["alarm"][1],
                        "entity": names.get(tuple(a.get("entity") or ()), (a.get("entity") or ("", ""))[1]),
                        "status": (a.get("overallStatus") or "").lower(), "time": a.get("time") or "",
                        "acknowledged": _bool(a.get("acknowledged")) or False} for a in uniq][:200]
    finally:
        try:
            await soap.call("Logout", _moref(*sm))
        except VmwareError:
            pass
    hosts, dss, vms, clusters = [], [], [], []
    for r in rows:
        t = r["_ref"][0]
        if t == "HostSystem":
            hsr = r.get("runtime.healthSystemRuntime") or {}
            # ESXi lists every installed software package as a "Software Components" sensor: they never fail, so they're left out
            sensors = [_sensor(s) for s in _list(((hsr.get("systemHealthInfo") or {}).get("numericSensorInfo")))
                       if isinstance(s, dict) and (s.get("sensorType") or "") != "Software Components"]
            mem = _num(r.get("summary.hardware.memorySize"))
            cores, mhz = _num(r.get("summary.hardware.numCpuCores")), _num(r.get("summary.hardware.cpuMhz"))
            used_mhz, used_mb = _num(r.get("summary.quickStats.overallCpuUsage")), _num(r.get("summary.quickStats.overallMemoryUsage"))
            hosts.append({
                "name": r.get("name") or "", "status": (r.get("overallStatus") or "").lower(),
                "connection": (r.get("runtime.connectionState") or "").lower(),
                "maintenance": bool(_bool(r.get("runtime.inMaintenanceMode"))),
                "power": r.get("runtime.powerState") or "", "boot": r.get("runtime.bootTime") or "",
                "product": r.get("summary.config.product.fullName") or "",
                "version": r.get("summary.config.product.version") or "", "build": r.get("summary.config.product.build") or "",
                "hardware": " ".join(x for x in (r.get("summary.hardware.vendor"), r.get("summary.hardware.model")) if x),
                "cpu_pct": round(used_mhz * 100 / (cores * mhz)) if used_mhz is not None and cores and mhz else None,
                "mem_pct": round(used_mb * 100 / (mem / 1048576)) if used_mb is not None and mem else None,
                "mem_gb": round(mem / 1073741824) if mem else None,
                "sensors": sorted(sensors, key=lambda s: (-COLOURS.get(s["state"], 0), s["type"], s["name"]))[:300],
                "hw_status": _hw_status(hsr),
            })
        elif t == "Datastore":
            cap, free = _num(r.get("summary.capacity")), _num(r.get("summary.freeSpace"))
            dss.append({"name": r.get("name") or "", "type": r.get("summary.type") or "", "capacity": cap, "free": free,
                        "free_pct": round(free * 100 / cap, 1) if cap and free is not None else None,
                        "accessible": _bool(r.get("summary.accessible")) is not False,
                        "status": (r.get("overallStatus") or "").lower()})
        elif t == "VirtualMachine":
            if _bool(r.get("config.template")):
                continue
            vms.append({"name": r.get("name") or "", "power": r.get("runtime.powerState") or ""})
        elif t == "ClusterComputeResource":
            clusters.append({"name": r.get("name") or "", "status": (r.get("overallStatus") or "").lower(),
                             "ha": _bool(r.get("configuration.dasConfig.enabled")),
                             "drs": _bool(r.get("configuration.drsConfig.enabled"))})
    d["hosts"] = sorted(hosts, key=lambda x: x["name"].lower())
    d["datastores"] = sorted(dss, key=lambda x: x["name"].lower())
    d["clusters"] = sorted(clusters, key=lambda x: x["name"].lower())
    d["vms_on"] = sum(1 for v in vms if v["power"] == "poweredOn")
    d["vms_off"] = sum(1 for v in vms if v["power"] == "poweredOff")
    d["vms_suspended"] = sum(1 for v in vms if v["power"] == "suspended")
    d["vms"] = sorted(vms, key=lambda x: x["name"].lower())[:MAX_VMS]
    return d


async def _vcenter_rest(http: _Http, user: str, password: str) -> dict:
    """The appliance's own health, services, file-based backup and updates (vCenter 7.0 U2 and later)."""
    basic = "Basic " + b64encode(f"{user}:{password}".encode()).decode()
    try:
        token = await http.json("POST", "/api/session", headers={"Authorization": basic})
    except _Status as err:
        if err.status == 404:
            return {"rest": "unavailable"}
        raise
    if not isinstance(token, str):
        return {"rest": "unavailable"}
    h = {"vmware-api-session-id": token}
    out: dict = {"rest": "ok", "health": {}}

    async def get(path):
        try:
            return await http.json("GET", path, headers=h)
        except _Status:
            return None
    try:
        for k in ("system", "load", "mem", "storage", "swap", "database-storage", "software-packages"):
            v = await get(f"/api/appliance/health/{k}")
            if isinstance(v, str):
                out["health"][k] = v.lower()
        ver = await get("/api/appliance/system/version")
        if isinstance(ver, dict):
            out["appliance_version"] = ver.get("version") or ""
            out["appliance_build"] = ver.get("build") or ""
            out["release_date"] = ver.get("releasedate") or ""
        up = await get("/api/appliance/system/uptime")
        if isinstance(up, (int, float)):
            out["uptime_s"] = int(up)
        svcs = await get("/api/vcenter/services")
        if isinstance(svcs, dict):
            bad = []
            for name, s in svcs.items():
                if not isinstance(s, dict):
                    continue
                st, health, start = (s.get("state") or "").upper(), (s.get("health") or "").upper(), (s.get("startup_type") or "").upper()
                if start == "AUTOMATIC" and st != "STARTED":
                    bad.append({"name": name, "problem": f"{st.lower() or 'not started'}, set to start automatically"})
                elif st == "STARTED" and health and health not in ("HEALTHY", "HEALTHY_WITH_WARNINGS"):
                    bad.append({"name": name, "problem": f"health {health.lower()}"})
            out["services"] = {"count": len(svcs), "problems": bad[:50]}
        sched = await get("/api/appliance/recovery/backup/schedules")
        out["backup_scheduled"] = bool(sched) if isinstance(sched, (dict, list)) else None
        jobs = await get("/api/appliance/recovery/backup/job/details")
        if isinstance(jobs, dict) and jobs:
            last = []
            for jid, j in jobs.items():
                if isinstance(j, dict):
                    last.append({"id": jid, "status": (j.get("status") or j.get("state") or "").upper(),
                                 "end": j.get("end_time") or "", "start": j.get("start_time") or "",
                                 "type": j.get("type") or "", "size": j.get("size")})
            last.sort(key=lambda j: j["end"] or j["start"] or j["id"], reverse=True)
            out["backup_jobs"] = last[:10]
        upd = await get("/api/appliance/update")
        if isinstance(upd, dict):
            out["update"] = {"state": (upd.get("state") or "").upper(), "checked": upd.get("latest_query_time") or ""}
            if out["update"]["state"] == "UPDATES_PENDING":
                pend = await get("/api/appliance/update/pending?source_type=LAST_CHECK")
                if isinstance(pend, list) and pend:
                    out["update"]["version"] = max((str(p.get("version") or "") for p in pend if isinstance(p, dict)), default="")
    finally:
        try:
            await http.req("DELETE", "/api/session", headers=h, ok=None)
        except VmwareError:
            pass
    return out


# ---- Aria ----

async def _aria_ops(http: _Http, user: str, password: str) -> dict:
    src = "local"
    if "@" in user:
        user, src = user.rsplit("@", 1)
    tok = await http.json("POST", "/suite-api/api/auth/token/acquire", headers={"Content-Type": "application/json"},
                          body=json.dumps({"username": user, "password": password, "authSource": src}).encode())
    token = (tok or {}).get("token") if isinstance(tok, dict) else None
    if not token:
        raise VmwareError("not Aria Operations? no token from /suite-api/api/auth/token/acquire")
    d: dict = {"product": "aria_ops"}
    h = {"Authorization": f"OpsToken {token}"}
    try:
        try:
            st = await http.json("GET", "/suite-api/api/deployment/node/status", headers=h)
        except VmwareError as err:  # older releases call it vRealizeOpsToken
            if not err.login:
                raise
            h = {"Authorization": f"vRealizeOpsToken {token}"}
            st = await http.json("GET", "/suite-api/api/deployment/node/status", headers=h)
        d["node_status"] = (st or {}).get("status", "") if isinstance(st, dict) else ""
        try:
            v = await http.json("GET", "/suite-api/api/versions/current", headers=h)
            if isinstance(v, dict):
                d["version"] = v.get("releaseName") or ".".join(str(v.get(k)) for k in ("major", "minor", "minorMinor") if v.get(k) is not None)
                d["build"] = str(v.get("buildNumber") or "")
        except _Status:
            pass
        try:
            al = await http.json("GET", "/suite-api/api/alerts?activeOnly=true&pageSize=1000", headers=h)
            lv: dict = {}
            top = []
            for a in (al or {}).get("alerts") or []:
                level = (a.get("alertLevel") or "").upper()
                lv[level] = lv.get(level, 0) + 1
                if level in ("CRITICAL", "IMMEDIATE"):
                    top.append({"name": a.get("alertDefinitionName") or "", "level": level.lower()})
            d["alerts"] = {"critical": lv.get("CRITICAL", 0), "immediate": lv.get("IMMEDIATE", 0),
                           "warning": lv.get("WARNING", 0), "top": top[:10]}
        except _Status:
            pass
    finally:
        try:
            await http.req("POST", "/suite-api/api/auth/token/release", headers=h, ok=None)
        except VmwareError:
            pass
    return d


async def _aria_auto(http: _Http, user: str, password: str) -> dict:
    d: dict = {"product": "aria_auto"}
    try:
        status, body = await http.req("GET", "/health", ok=None, login_codes=())
        d["health_page"] = "healthy" if status == 200 else f"HTTP {status}"
    except VmwareError as err:
        d["health_page"] = str(err)
    try:
        about = await http.json("GET", "/iaas/api/about")
        if isinstance(about, dict):
            d["version"] = about.get("latestApiVersion") or ""
    except _Status:
        pass
    domain = None
    if "@" in user:
        user, domain = user.rsplit("@", 1)
    body = {"username": user, "password": password, **({"domain": domain} if domain else {})}
    try:
        tok = await http.json("POST", "/csp/gateway/am/api/login", headers={"Content-Type": "application/json"},
                              body=json.dumps(body).encode())
    except _Status as err:
        raise VmwareError(f"not Aria Automation? the login answered HTTP {err.status}") from None
    if not isinstance(tok, dict) or not (tok.get("cspAuthToken") or tok.get("access_token")):
        raise VmwareError("the account was turned down (no token from the login)", login=True)
    d["login"] = "ok"
    return d


async def _aria_logs(http: _Http, user: str, password: str) -> dict:
    d: dict = {"product": "aria_logs"}
    provider = "ActiveDirectory" if "@" in user or "\\" in user else "Local"
    try:
        s = await http.json("POST", "/api/v2/sessions", headers={"Content-Type": "application/json"},
                            body=json.dumps({"username": user, "password": password, "provider": provider}).encode())
    except _Status as err:
        raise VmwareError(f"not Aria Operations for Logs? /api/v2/sessions answered HTTP {err.status}") from None
    sid = (s or {}).get("sessionId") if isinstance(s, dict) else None
    if not sid:
        raise VmwareError("the account was turned down (no session)", login=True)
    d["login"] = "ok"
    try:
        v = await http.json("GET", "/api/v2/version", headers={"Authorization": f"Bearer {sid}"})
        if isinstance(v, dict):
            d["version"] = v.get("version") or ""
            d["release"] = v.get("releaseName") or ""
    except _Status:
        pass
    return d


async def _cert(base: str) -> dict | None:
    """The certificate it presents (its own TLS handshake; nothing is sent), for its expiry."""
    import certcheck
    u = urlparse(base)
    try:
        c = certcheck.describe(await certcheck.fetch(u.hostname or "", u.port or 443, u.hostname, timeout=10))
    except Exception:  # noqa: BLE001 - a certificate that can't be read just isn't shown
        return None
    return {"expires": c["expires"], "subject": c["subject"], "issuer": c["issuer"], "self_signed": c["self_signed"]}


async def poll(base: str, product: str, user: str, password: str, tls, timeout: float = 60.0) -> dict:
    """Read it. product is vsphere (ESXi or vCenter, found from the answer), aria_ops, aria_auto or aria_logs.
    Raises VmwareError if it can't be reached, isn't what it should be, or turns the account down."""
    http = _Http(base, tls, timeout)
    try:
        if product in ("vsphere", "esxi", "vcenter"):
            d = await _vsphere(http, user, password)
            if d["product"] == "vcenter":
                try:
                    d.update(await _vcenter_rest(http, user, password))
                except VmwareError as err:
                    if err.login:  # SOAP took the account, so the REST API just can't be used by it
                        d["rest"] = "refused"
                    else:
                        d["rest"] = f"error: {err}"
        elif product == "aria_ops":
            d = await _aria_ops(http, user, password)
        elif product == "aria_auto":
            d = await _aria_auto(http, user, password)
        elif product == "aria_logs":
            d = await _aria_logs(http, user, password)
        else:
            raise VmwareError(f"unknown VMware product {product!r}")
        d["ms"] = http.ms
        d["cert"] = await _cert(base)
        return d
    finally:
        await http.close()


# ---- judging it ----

def problems(d: dict, now: float | None = None, ds_warn: float = 10, ds_crit: float = 5,
             cert_warn: int = 30, cert_crit: int = 14) -> list[dict]:
    """What's wrong: [{level: warn|crit, what, detail}]."""
    now = time.time() if now is None else now
    out: list[dict] = []

    def add(level, what, detail):
        out.append({"level": level, "what": what, "detail": detail})
    for h in d.get("hosts") or []:
        n = h["name"]
        if h["connection"] and h["connection"] != "connected":
            add("crit", f"Host {n}", {"disconnected": "disconnected from vCenter", "notresponding": "not responding"}.get(h["connection"], h["connection"]))
            continue
        for s in h.get("sensors") or []:
            if s["state"] in ("red", "yellow"):
                add("crit" if s["state"] == "red" else "warn", f"{n}: {s['name']}",
                    f"{s['type'] or 'sensor'} {s['state']}" + (f" ({s['value']} {s['unit']})" if s["value"] is not None and s["unit"] else ""))
        for e in h.get("hw_status") or []:
            add("crit" if e["state"] == "red" else "warn", f"{n}: {e['name']}", e["state"])
    for ds in d.get("datastores") or []:
        if not ds["accessible"]:
            add("crit", f"Datastore {ds['name']}", "not accessible")
        elif ds["free_pct"] is not None and ds["free_pct"] < ds_warn:
            add("crit" if ds["free_pct"] < ds_crit else "warn", f"Datastore {ds['name']}", f"{ds['free_pct']}% free")
    for a in d.get("alarms") or []:
        if a["acknowledged"] or a["status"] not in ("red", "yellow"):
            continue
        add("crit" if a["status"] == "red" else "warn", f"Alarm: {a['name']}", a["entity"])
    for k, v in (d.get("health") if isinstance(d.get("health"), dict) else {}).items():
        if COLOURS.get(v, 0):
            add("crit" if v == "red" else "warn", f"Appliance health: {k}", v)
    for s in (d.get("services") or {}).get("problems") or []:
        add("warn", f"Service {s['name']}", s["problem"])
    jobs = d.get("backup_jobs") or []
    if jobs and jobs[0]["status"] == "FAILED":
        add("crit", "Appliance backup", f"last backup failed ({jobs[0]['end'] or jobs[0]['start']})")
    if d.get("product") == "aria_ops":
        if d.get("node_status") and d["node_status"].upper() != "ONLINE":
            add("crit", "Aria Operations", f"node {d['node_status'].lower()}")
        al = d.get("alerts") or {}
        if al.get("critical"):
            add("warn", "Aria Operations alerts", f"{al['critical']} critical" + (f", {al['immediate']} immediate" if al.get("immediate") else ""))
    if d.get("product") == "aria_auto" and d.get("health_page") and d["health_page"] != "healthy":
        add("crit", "Aria Automation", f"/health: {d['health_page']}")
    c = d.get("cert")
    if c and c.get("expires"):
        days = (c["expires"] - now) / 86400
        if days < cert_warn:
            add("crit" if days < cert_crit else "warn", "Certificate",
                "expired" if days < 0 else f"expires in {int(days)} day{'' if int(days) == 1 else 's'}")
    return out


def evaluate(d: dict, items: list[dict]) -> tuple:
    """(ok, latency, detail[, level]) for the check: red for any crit item, amber for warn items, else green."""
    p = d.get("product")
    bits = [PRODUCTS.get(p, "VMware") + (f" {d['version']}" if d.get("version") else "")]
    if p in ("esxi", "vcenter"):
        hs = d.get("hosts") or []
        if p == "vcenter":
            bits.append(f"{len(hs)} host{'' if len(hs) == 1 else 's'}")
        bits.append(f"{d.get('vms_on', 0)} VM{'' if d.get('vms_on') == 1 else 's'} on")
        maint = [h["name"] for h in hs if h.get("maintenance")]
        if maint:
            bits.append(("in maintenance mode" if p == "esxi" else f"maintenance: {', '.join(maint[:3])}"))
        if (d.get("update") or {}).get("state") == "UPDATES_PENDING":
            bits.append("update available" + (f" ({d['update']['version']})" if d["update"].get("version") else ""))
    crit = [i for i in items if i["level"] == "crit"]
    warn = [i for i in items if i["level"] == "warn"]
    show = (crit or warn)[:3]
    if show:
        more = len(crit or warn) - len(show)
        bits += [f"{i['what']}: {i['detail']}" for i in show] + ([f"+{more} more"] if more > 0 else [])
    if crit:
        return False, None, "; ".join(bits)
    if warn:
        return False, None, "; ".join(bits), "warn"
    return True, d.get("ms"), "; ".join(bits)
