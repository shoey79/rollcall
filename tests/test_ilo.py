"""HPE iLO health (rollcall/app/ilo.py): parsing RIBCL answers and judging what they show.

The samples follow the layout iLO 4 and iLO 3 use for GET_EMBEDDED_HEALTH, with made-up values.
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))

import ilo  # noqa: E402

OK = "<?xml version=\"1.0\"?>\r\n<RIBCL VERSION=\"2.23\">\r\n<RESPONSE\r\n    STATUS=\"0x0000\"\r\n    MESSAGE='No error'\r\n     />\r\n</RIBCL>\r\n"

ILO4 = OK + OK + """<?xml version="1.0"?>
<RIBCL VERSION="2.23">
<RESPONSE STATUS="0x0000" MESSAGE='No error' />
<GET_FW_VERSION FIRMWARE_VERSION = "2.82" FIRMWARE_DATE = "Feb 06 2023" MANAGEMENT_PROCESSOR = "iLO4" LICENSE_TYPE = "iLO Advanced" />
</RIBCL>
<?xml version="1.0"?>
<RIBCL VERSION="2.23">
<RESPONSE STATUS="0x0000" MESSAGE='No error' />
<GET_HOST_POWER HOST_POWER="ON" />
</RIBCL>
<?xml version="1.0"?>
<RIBCL VERSION="2.23">
<RESPONSE STATUS="0x0000" MESSAGE='No error' />
<GET_HOST_DATA>
<SMBIOS_RECORD TYPE="1" B64_DATA="AAAA">
 <FIELD NAME="Product Name" VALUE="ProLiant DL380p Gen8"/>
 <FIELD NAME="Serial Number" VALUE="SN0000000"/>
</SMBIOS_RECORD>
</GET_HOST_DATA>
</RIBCL>
<?xml version="1.0"?>
<RIBCL VERSION="2.23">
<RESPONSE STATUS="0x0000" MESSAGE='No error' />
<GET_EMBEDDED_HEALTH_DATA>
 <FANS>
  <FAN><ZONE VALUE = "System"/><LABEL VALUE = "Fan 1"/><STATUS VALUE = "OK"/><SPEED VALUE = "19" UNIT="Percentage"/></FAN>
  <FAN><ZONE VALUE = "System"/><LABEL VALUE = "Fan 2"/><STATUS VALUE = "Failed"/><SPEED VALUE = "0" UNIT="Percentage"/></FAN>
 </FANS>
 <TEMPERATURE>
  <TEMP><LABEL VALUE = "01-Inlet Ambient"/><LOCATION VALUE = "Ambient"/><STATUS VALUE = "OK"/>
   <CURRENTREADING VALUE = "21" UNIT="Celsius"/><CAUTION VALUE = "42" UNIT="Celsius"/><CRITICAL VALUE = "46" UNIT="Celsius"/></TEMP>
  <TEMP><LABEL VALUE = "02-CPU 1"/><LOCATION VALUE = "CPU"/><STATUS VALUE = "OK"/>
   <CURRENTREADING VALUE = "72" UNIT="Celsius"/><CAUTION VALUE = "70" UNIT="Celsius"/><CRITICAL VALUE = "0" UNIT="Celsius"/></TEMP>
  <TEMP><LABEL VALUE = "03-P1 DIMM 1-6"/><LOCATION VALUE = "Memory"/><STATUS VALUE = "Not Installed"/>
   <CURRENTREADING VALUE = "N/A"/><CAUTION VALUE = "N/A"/><CRITICAL VALUE = "N/A"/></TEMP>
 </TEMPERATURE>
 <POWER_SUPPLIES>
  <POWER_SUPPLY_SUMMARY><PRESENT_POWER_READING VALUE = "180 Watts"/><POWER_SYSTEM_REDUNDANCY VALUE = "Redundant"/></POWER_SUPPLY_SUMMARY>
  <SUPPLY><LABEL VALUE = "Power Supply 1"/><PRESENT VALUE = "Yes"/><STATUS VALUE = "Good, In Use"/><MODEL VALUE = "656362-B21"/><CAPACITY VALUE = "460 Watts"/></SUPPLY>
  <SUPPLY><LABEL VALUE = "Power Supply 2"/><PRESENT VALUE = "Yes"/><STATUS VALUE = "Good, In Use"/><MODEL VALUE = "656362-B21"/><CAPACITY VALUE = "460 Watts"/></SUPPLY>
 </POWER_SUPPLIES>
 <STORAGE>
  <CONTROLLER>
   <LABEL VALUE = "Controller on System Board"/><STATUS VALUE = "OK"/><CONTROLLER_STATUS VALUE = "OK"/>
   <MODEL VALUE = "Smart Array P420i Controller"/><FW_VERSION VALUE = "8.32"/><CACHE_MODULE_STATUS VALUE = "OK"/>
   <DRIVE_ENCLOSURE><LABEL VALUE = "Port 1I Box 1"/><STATUS VALUE = "OK"/><DRIVE_BAY VALUE = "04"/></DRIVE_ENCLOSURE>
   <LOGICAL_DRIVE>
    <LABEL VALUE = "01"/><STATUS VALUE = "Degraded (Recovering)"/><CAPACITY VALUE = "279 GiB"/><FAULT_TOLERANCE VALUE = "RAID 1/RAID 1+0"/>
    <PHYSICAL_DRIVE><LABEL VALUE = "Port 1I Box 1 Bay 1"/><STATUS VALUE = "OK"/><MODEL VALUE = "EG0300FBDBR"/><CAPACITY VALUE = "279 GiB"/>
     <LOCATION VALUE = "Port 1I Box 1 Bay 1"/><DRIVE_CONFIGURATION VALUE = "Configured"/><MEDIA_TYPE VALUE = "HDD"/></PHYSICAL_DRIVE>
    <PHYSICAL_DRIVE><LABEL VALUE = "Port 1I Box 1 Bay 2"/><STATUS VALUE = "Failed"/><MODEL VALUE = "EG0300FBDBR"/><CAPACITY VALUE = "279 GiB"/>
     <LOCATION VALUE = "Port 1I Box 1 Bay 2"/><DRIVE_CONFIGURATION VALUE = "Configured"/><MEDIA_TYPE VALUE = "HDD"/></PHYSICAL_DRIVE>
   </LOGICAL_DRIVE>
   <PHYSICAL_DRIVE><LABEL VALUE = "Port 1I Box 1 Bay 3"/><STATUS VALUE = "Predictive Failure"/><MODEL VALUE = "EG0300FBDBR"/>
    <LOCATION VALUE = "Port 1I Box 1 Bay 3"/><DRIVE_CONFIGURATION VALUE = "Spare"/></PHYSICAL_DRIVE>
  </CONTROLLER>
 </STORAGE>
 <HEALTH_AT_A_GLANCE>
  <BIOS_HARDWARE STATUS= "OK"/>
  <FANS STATUS= "Failed"/>
  <FANS REDUNDANCY= "Not Redundant"/>
  <TEMPERATURE STATUS= "OK"/>
  <POWER_SUPPLIES STATUS= "OK"/>
  <POWER_SUPPLIES REDUNDANCY= "Redundant"/>
  <PROCESSOR STATUS= "OK"/>
  <MEMORY STATUS= "Degraded"/>
  <NETWORK STATUS= "Link Down"/>
  <STORAGE STATUS= "Degraded"/>
 </HEALTH_AT_A_GLANCE>
</GET_EMBEDDED_HEALTH_DATA>
</RIBCL>
"""

ILO3 = OK + """<?xml version="1.0"?>
<RIBCL VERSION="2.22">
<RESPONSE STATUS="0x0000" MESSAGE='No error' />
<GET_EMBEDDED_HEALTH_DATA>
 <FANS><FAN><ZONE VALUE = "System"/><LABEL VALUE = "Fan 1"/><STATUS VALUE = "Ok"/><SPEED VALUE = "30" UNIT="Percentage"/></FAN></FANS>
 <TEMPERATURE><TEMP><LABEL VALUE = "Temp 1"/><LOCATION VALUE = "Ambient"/><STATUS VALUE = "Ok"/>
  <CURRENTREADING VALUE = "24" UNIT="Celsius"/><CAUTION VALUE = "42" UNIT="Celsius"/><CRITICAL VALUE = "46" UNIT="Celsius"/></TEMP></TEMPERATURE>
 <POWER_SUPPLIES><SUPPLY><LABEL VALUE = "Power Supply 1"/><STATUS VALUE = "Ok"/></SUPPLY></POWER_SUPPLIES>
 <DRIVES>
  <BACKPLANE>
   <FIRMWARE_VERSION VALUE="1.16"/><ENCLOSURE_ADDR VALUE="224"/>
   <DRIVE_BAY VALUE = "1"/><PRODUCT_ID VALUE = "EG0146FAWHU"/><STATUS VALUE = "Ok"/><UID_LED VALUE = "Off"/>
   <DRIVE_BAY VALUE = "2"/><PRODUCT_ID VALUE = "EG0146FAWHU"/><STATUS VALUE = "Fault"/><UID_LED VALUE = "Off"/>
   <DRIVE_BAY VALUE = "3"/><PRODUCT_ID VALUE = "N/A"/><STATUS VALUE = "Not Installed"/><UID_LED VALUE = "Off"/>
  </BACKPLANE>
 </DRIVES>
 <HEALTH_AT_A_GLANCE><FANS STATUS= "Ok"/><TEMPERATURE STATUS= "Ok"/><POWER_SUPPLIES STATUS= "Ok"/><POWER_SUPPLIES REDUNDANCY= "Not Redundant"/></HEALTH_AT_A_GLANCE>
</GET_EMBEDDED_HEALTH_DATA>
</RIBCL>
"""

LOGIN_FAIL = """<?xml version="1.0"?>
<RIBCL VERSION="2.23">
<RESPONSE STATUS="0x005F" MESSAGE='Login failed.' />
</RIBCL>
"""


def by_what(items):
    return {i["what"]: i for i in items}


def test_ilo4_parse():
    d = ilo.parse(ILO4)
    assert d["ilo"] == "iLO4" and d["firmware"] == "2.82" and d["power"] == "ON"
    assert d["model"] == "ProLiant DL380p Gen8"
    assert len(d["fans"]) == 2 and len(d["temps"]) == 3 and len(d["psus"]) == 2
    c = d["controllers"][0]
    assert c["model"] == "Smart Array P420i Controller"
    assert [p["label"] for p in c["logical"][0]["drives"]] == ["Port 1I Box 1 Bay 1", "Port 1I Box 1 Bay 2"]
    assert c["drives"][0]["label"] == "Port 1I Box 1 Bay 3"


def test_ilo4_evaluate():
    items = by_what(ilo.evaluate(ilo.parse(ILO4)))
    assert items["Drive Port 1I Box 1 Bay 2"]["level"] == "crit"            # the failed disk: red
    assert items["Drive Port 1I Box 1 Bay 3"]["level"] == "warn"            # predictive failure: amber
    assert items["Logical drive 01"]["level"] == "warn"
    assert items["Fan 2"]["level"] == "crit"
    assert items["Temperature 02-CPU 1"]["level"] == "warn"                 # over its caution limit
    assert items["Fan redundancy"]["level"] == "warn"
    assert items["Memory"]["level"] == "warn"                               # only in the summary
    assert "Fans" not in items and "Storage" not in items                   # detail already covers them
    assert "Network" not in items                                           # a NIC without a cable isn't a fault
    assert "Drive Port 1I Box 1 Bay 1" not in items and "Power supply 1" not in items
    assert not any("DIMM" in w for w in items)                              # not installed


def test_ilo3_backplane():
    d = ilo.parse(ILO3)
    assert d["backplanes"][0]["bays"][1] == {"bay": "2", "product_id": "EG0146FAWHU", "status": "Fault", "uid_led": "Off"}
    items = by_what(ilo.evaluate(d))
    assert items["Drive bay 2"]["level"] == "crit"
    assert "Drive bay 3" not in items and "Drive bay 1" not in items
    assert "Power redundancy" not in items  # one power supply: never redundant
    assert ilo.summary(d).startswith("2 drives OK")


def test_login_refused():
    try:
        ilo.parse(LOGIN_FAIL)
    except ilo.IloError as err:
        assert err.login
    else:
        raise AssertionError("expected IloError")


def test_bad_xml_tidied_and_entities_refused():
    d = ilo.parse(ILO4.replace("Smart Array P420i Controller", "Smart Array & Co\x01"))
    assert d["controllers"][0]["model"] == "Smart Array & Co"
    try:
        ilo.parse('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><RIBCL/>')
    except ilo.IloError:
        pass
    else:
        raise AssertionError("expected IloError")


def test_powered_off_and_levels():
    d = ilo.parse(ILO4.replace('HOST_POWER="ON"', 'HOST_POWER="OFF"'))
    assert by_what(ilo.evaluate(d))["Server"] == {"level": "warn", "what": "Server", "detail": "powered off", "group": "power"}
    assert ilo.level_of("Good, In Use") == "ok" and ilo.level_of("Not Redundant") == "warn"
    assert ilo.level_of("Rebuilding") == "warn" and ilo.level_of("Interim Recovery Mode") == "warn"
    assert ilo.level_of("Power Supply Failure") == "crit" and ilo.level_of("Something new") is None


def test_request_escapes_credentials():
    x = ilo.request_xml('ad"min', "p<w>&'d").decode()
    assert "USER_LOGIN='ad\"min'" in x and "PASSWORD=\"p&lt;w&gt;&amp;'d\"" in x


def test_poll_over_http_chunked():
    """poll() end to end against a local server (plain TCP: the TLS layer is the standard library's)."""
    body = ILO3.encode()
    chunks = b"".join(b"%x\r\n" % len(body[i:i + 500]) + body[i:i + 500] + b"\r\n" for i in range(0, len(body), 500)) + b"0\r\n\r\n"
    seen = {}

    async def handle(reader, writer):
        req = await reader.readuntil(b"\r\n\r\n")
        n = int(next(l for l in req.split(b"\r\n") if l.lower().startswith(b"content-length")).split(b":")[1])
        seen["req"] = req + await reader.readexactly(n)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks)
        await writer.drain()
        writer.close()

    async def run():
        srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await ilo.poll("127.0.0.1", "admin", "secret", None, timeout=5, port=port)
        finally:
            srv.close()

    d = asyncio.run(run())
    assert seen["req"].startswith(b"POST /ribcl HTTP/1.1") and b"GET_EMBEDDED_HEALTH" in seen["req"]
    assert d["backplanes"][0]["bays"][1]["status"] == "Fault"


# -- the add-on side: reading on a schedule, confirming before red, acknowledging, login back-off --
def _monitor(monkeypatch, answers):
    import types
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))
    import main
    M = main.Monitor
    m = types.SimpleNamespace(ILO_EVERY=M.ILO_EVERY, ILO_LOGIN_RETRY=M.ILO_LOGIN_RETRY, saved=0)
    m._save_hosts = lambda: setattr(m, "saved", m.saved + 1)
    for name in ("ilo_eval", "ilo_result", "ilo_check"):
        setattr(m, name, types.MethodType(getattr(M, name), m))
    calls = []

    async def fake_poll(host, user, pw, tls, timeout=60):
        calls.append(host)
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return ilo.parse(a)
    monkeypatch.setattr(main.ilolib, "poll", fake_poll)
    h = main.Host(key="srv01", name="SRV01", host="192.168.1.20", ilo_user="rollcall", ilo_pass="secret")
    return m, h, calls


def test_check_confirms_then_caches(monkeypatch):
    m, h, calls = _monitor(monkeypatch, [ILO3, ILO3])
    run = lambda t: asyncio.run(m.ilo_check(h, t))  # noqa: E731
    r1 = run(1000)
    assert r1[0] is False and len(r1) == 3 and "Drive bay 2" in r1[2]   # crit: amber now (first failure)...
    r2 = run(1060)
    assert len(calls) == 2 and r2[0] is False                           # ...read again at the next check, red if still there
    run(1120)
    assert len(calls) == 2                                              # then every 5 minutes
    h.ilo_acks = {"Drive bay 2": "crit"}
    r4 = run(1180)
    assert r4[0] is True and "acknowledged: Drive bay 2" in r4[2] and len(calls) == 2  # applied without a new read


def test_login_refused_backs_off(monkeypatch):
    m, h, calls = _monitor(monkeypatch, [ilo.IloError("the iLO refused the user name or password", login=True)])
    r = asyncio.run(m.ilo_check(h, 1000))
    assert r == (False, None, "the iLO refused the user name or password", "warn")
    asyncio.run(m.ilo_check(h, 1000 + m.ILO_EVERY + 1))
    assert len(calls) == 1                                              # not tried again for 30 minutes


def test_no_login_set(monkeypatch):
    m, h, calls = _monitor(monkeypatch, [])
    h.ilo_pass = ""
    assert asyncio.run(m.ilo_check(h, 1000))[3] == "warn" and not calls


def test_entry_keeps_password_and_validates():
    import main
    e = main.validate_entry({"name": "SRV01-iLO", "host": "192.168.1.21", "checks": ["hpilo"], "ilo_user": "rollcall", "ilo_pass": "pw"})
    assert e["checks"] == ["hpilo"] and e["ilo_pass"] == "pw"
    assert main.validate_entry({"name": "X", "host": "192.168.1.21", "checks": ["ilo4"]})["checks"] == ["hpilo"]
    assert main.parse_check("hpilo")[0]["kind"] == "ilo"


def test_two_controllers_and_worse_status_wins():
    d = ilo.parse(ILO4)
    c2 = json.loads(json.dumps(d["controllers"][0]))
    c2["label"] = "Controller in Slot 1"
    c2["logical"][0]["drives"][1]["status"] = "OK"          # bay 2 is fine on this one
    c2["drives"][0]["status"] = "Failed"                     # but bay 3 has failed
    c2["controller_status"] = "Failed"
    c2["status"] = "Degraded"
    d["controllers"].append(c2)
    items = by_what(ilo.evaluate(d))
    assert items["Drive Port 1I Box 1 Bay 3 (Controller in Slot 1)"]["level"] == "crit"
    assert items["Drive Port 1I Box 1 Bay 3 (Controller on System Board)"]["level"] == "warn"
    assert items["Controller Controller in Slot 1"]["level"] == "crit"   # Failed beats Degraded


def test_complete_answers_end_without_close():
    assert ilo._complete(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
    assert not ilo._complete(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc")
    assert ilo._complete(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
    assert not ilo._complete(b"HTTP/1.1 200 OK\r\n\r\nabc")


def test_connection_reset_is_an_ilo_error():
    async def handle(reader, writer):
        writer.transport.abort()

    async def run():
        srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await ilo.poll("127.0.0.1", "admin", "secret", None, timeout=5, port=port)
        finally:
            srv.close()
    try:
        asyncio.run(run())
    except ilo.IloError:
        pass
    else:
        raise AssertionError("expected IloError")
