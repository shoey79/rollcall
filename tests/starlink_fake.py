"""Stand-ins for a Starlink dish and for starlink.com, built on the real gRPC and protobuf libraries (grpcio,
protobuf), so Rollcall's own small HTTP/2 client and protobuf reader are checked against independent code.

The messages are a subset of SpaceX's definitions, with the same field numbers (enough for get_status). The
dish's id and serial-like values are made up.
"""
from __future__ import annotations

import asyncio
import threading

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

F = descriptor_pb2.FieldDescriptorProto


def _messages():
    fd = descriptor_pb2.FileDescriptorProto(name="rollcall_starlink_test.proto", package="SpaceX.API.Device", syntax="proto3")

    def msg(name, fields):
        m = fd.message_type.add(name=name)
        for fname, num, ftype, *rest in fields:
            f = m.field.add(name=fname, number=num, type=ftype, label=F.LABEL_OPTIONAL)
            if rest:
                f.type_name = rest[0]
        return m

    msg("GetStatusRequest", [])
    msg("RebootRequest", [])
    msg("DishGetObstructionMapRequest", [])
    msg("DishClearObstructionMapRequest", [])
    msg("Request", [("id", 1, F.TYPE_UINT64), ("target_id", 13, F.TYPE_STRING),
                    ("get_status", 1004, F.TYPE_MESSAGE, ".SpaceX.API.Device.GetStatusRequest"),
                    ("reboot", 1001, F.TYPE_MESSAGE, ".SpaceX.API.Device.RebootRequest"),
                    ("dish_get_obstruction_map", 2008, F.TYPE_MESSAGE, ".SpaceX.API.Device.DishGetObstructionMapRequest"),
                    ("dish_clear_obstruction_map", 2017, F.TYPE_MESSAGE, ".SpaceX.API.Device.DishClearObstructionMapRequest")])
    msg("AlignmentStats", [("tilt_angle_deg", 3, F.TYPE_FLOAT), ("boresight_azimuth_deg", 4, F.TYPE_FLOAT),
                           ("boresight_elevation_deg", 5, F.TYPE_FLOAT), ("desired_boresight_azimuth_deg", 8, F.TYPE_FLOAT),
                           ("desired_boresight_elevation_deg", 9, F.TYPE_FLOAT)])
    m = msg("DishGetObstructionMapResponse", [("num_rows", 1, F.TYPE_UINT32), ("num_cols", 2, F.TYPE_UINT32),
                                              ("max_theta_deg", 5, F.TYPE_FLOAT), ("map_reference_frame", 6, F.TYPE_INT32)])
    m.field.add(name="snr", number=3, type=F.TYPE_FLOAT, label=F.LABEL_REPEATED)  # proto3: packed
    msg("DeviceInfo", [("id", 1, F.TYPE_STRING), ("hardware_version", 2, F.TYPE_STRING),
                       ("software_version", 3, F.TYPE_STRING), ("country_code", 4, F.TYPE_STRING)])
    msg("DeviceState", [("uptime_s", 1, F.TYPE_UINT64)])
    msg("DishAlerts", [(n, num, F.TYPE_BOOL) for n, num in (
        ("motors_stuck", 1), ("thermal_shutdown", 2), ("thermal_throttle", 3), ("mast_not_near_vertical", 5),
        ("slow_ethernet_speeds", 6), ("is_heating", 9))])
    msg("DishOutage", [("cause", 1, F.TYPE_INT32), ("start_timestamp_ns", 2, F.TYPE_INT64), ("duration_ns", 3, F.TYPE_UINT64)])
    msg("DishObstructionStats", [("fraction_obstructed", 1, F.TYPE_FLOAT), ("valid_s", 4, F.TYPE_FLOAT),
                                 ("currently_obstructed", 5, F.TYPE_BOOL), ("time_obstructed", 9, F.TYPE_FLOAT)])
    msg("DishGetStatusResponse", [
        ("device_info", 1, F.TYPE_MESSAGE, ".SpaceX.API.Device.DeviceInfo"),
        ("device_state", 2, F.TYPE_MESSAGE, ".SpaceX.API.Device.DeviceState"),
        ("pop_ping_drop_rate", 1003, F.TYPE_FLOAT),
        ("obstruction_stats", 1004, F.TYPE_MESSAGE, ".SpaceX.API.Device.DishObstructionStats"),
        ("alerts", 1005, F.TYPE_MESSAGE, ".SpaceX.API.Device.DishAlerts"),
        ("downlink_throughput_bps", 1007, F.TYPE_FLOAT), ("uplink_throughput_bps", 1008, F.TYPE_FLOAT),
        ("pop_ping_latency_ms", 1009, F.TYPE_FLOAT), ("stow_requested", 1010, F.TYPE_BOOL),
        ("outage", 1014, F.TYPE_MESSAGE, ".SpaceX.API.Device.DishOutage"),
        ("eth_speed_mbps", 1016, F.TYPE_INT32), ("is_snr_above_noise_floor", 1018, F.TYPE_BOOL),
        ("software_update_state", 1021, F.TYPE_INT32), ("disablement_code", 1024, F.TYPE_INT32),
        ("alignment_stats", 1027, F.TYPE_MESSAGE, ".SpaceX.API.Device.AlignmentStats"),
        ("swupdate_reboot_ready", 1030, F.TYPE_BOOL), ("reboot_reason", 1032, F.TYPE_INT32)])
    msg("Status", [("code", 1, F.TYPE_INT32), ("message", 2, F.TYPE_STRING)])
    msg("Response", [("id", 1, F.TYPE_UINT64), ("status", 2, F.TYPE_MESSAGE, ".SpaceX.API.Device.Status"),
                     ("api_version", 3, F.TYPE_UINT64),
                     ("dish_get_status", 2004, F.TYPE_MESSAGE, ".SpaceX.API.Device.DishGetStatusResponse"),
                     ("dish_get_obstruction_map", 2008, F.TYPE_MESSAGE, ".SpaceX.API.Device.DishGetObstructionMapResponse")])
    pool = descriptor_pool.DescriptorPool()
    pool.Add(fd)
    get = lambda n: message_factory.GetMessageClass(pool.FindMessageTypeByName("SpaceX.API.Device." + n))  # noqa: E731
    return get("Request"), get("Response")


Request, Response = _messages()


def healthy() -> dict:
    """A dish that's online, clear sky, nothing wrong."""
    return {
        "device_info": {"id": "ut00000000-11111111-22222222", "hardware_version": "rev4_prod1",
                        "software_version": "2026.11.01.mr12345", "country_code": "GB"},
        "device_state": {"uptime_s": 86400 * 3 + 3600},
        "pop_ping_latency_ms": 31.5, "pop_ping_drop_rate": 0.002,
        "downlink_throughput_bps": 48_250_000.0, "uplink_throughput_bps": 5_100_000.0,
        "obstruction_stats": {"fraction_obstructed": 0.0012, "valid_s": 43200.0, "time_obstructed": 0.0005},
        "eth_speed_mbps": 1000, "is_snr_above_noise_floor": True, "software_update_state": 1,
        "alerts": {"is_heating": False},
        "alignment_stats": {"tilt_angle_deg": 24.5, "boresight_azimuth_deg": 291.6, "boresight_elevation_deg": 65.4,
                            "desired_boresight_azimuth_deg": 297.0, "desired_boresight_elevation_deg": 66.0},
    }


def sky(rows: int = 123, cols: int = 123, max_theta: float = 80.0, frame: int = 1, blocked=((30, 75, 0, 30),),
        seen: float = 0.8) -> dict:
    """An obstruction map: the sky the dish has seen (a band of passes, the rest no data), clear except where
    blocked: (from_az, to_az, min_elev, max_elev) in degrees, north up and east right."""
    import math
    snr = []
    cy, cx, r_max = (rows - 1) / 2, (cols - 1) / 2, min(rows, cols) / 2
    for i in range(rows * cols):
        y, x = cy - i // cols, i % cols - cx
        r = math.hypot(x, y)
        if r > r_max or (math.sin(i * 12.9898) * 43758.5453) % 1 > seen:   # outside, or not seen yet
            snr.append(-1.0)
            continue
        az, el = math.degrees(math.atan2(x, y)) % 360, 90 - r / r_max * max_theta
        hit = any(a0 <= az <= a1 and e0 <= el <= e1 for a0, a1, e0, e1 in blocked)
        snr.append(0.0 if hit else 1.0)
    return {"num_rows": rows, "num_cols": cols, "snr": snr, "max_theta_deg": max_theta, "map_reference_frame": frame}


def response_bytes(status: dict | None, error: str = "", obstruction_map: dict | None = None) -> bytes:
    r = Response(api_version=30)
    if obstruction_map is not None:
        r.dish_get_obstruction_map.CopyFrom(_fill(Response.DESCRIPTOR.fields_by_name["dish_get_obstruction_map"].message_type, obstruction_map))
    elif status is not None:
        r.dish_get_status.CopyFrom(_fill(Response.DESCRIPTOR.fields_by_name["dish_get_status"].message_type, status))
    if error:
        r.status.code, r.status.message = 2, error
    return r.SerializeToString()


def _fill(desc, d):
    cls = message_factory.GetMessageClass(desc)
    m = cls()
    for k, v in d.items():
        f = desc.fields_by_name[k]
        if f.message_type is not None:
            getattr(m, k).CopyFrom(_fill(f.message_type, v))
        elif isinstance(v, (list, tuple)):
            getattr(m, k).extend(v)
        else:
            setattr(m, k, v)
    return m


class FakeDish:
    """A gRPC server answering SpaceX.API.Device.Device/Handle like a dish (plain gRPC, HTTP/2, no TLS)."""

    def __init__(self, port: int = 0):
        import grpc
        self.status: dict | None = healthy()
        self.map: dict | None = sky()
        self.error = ""
        self.requests: list = []
        self.server = grpc.server(__import__("concurrent.futures").futures.ThreadPoolExecutor(4))
        handler = grpc.method_handlers_generic_handler("SpaceX.API.Device.Device", {
            "Handle": grpc.unary_unary_rpc_method_handler(self._handle, request_deserializer=Request.FromString,
                                                         response_serializer=lambda b: b)})
        self.server.add_generic_rpc_handlers((handler,))
        self.port = self.server.add_insecure_port(f"127.0.0.1:{port}")
        self.server.start()

    def _handle(self, req, _ctx):
        self.requests.append(req)
        if req.HasField("reboot") or req.HasField("dish_clear_obstruction_map"):
            raise AssertionError("Rollcall asked the dish to change something")
        if req.HasField("dish_get_obstruction_map"):
            return response_bytes(None, "" if self.map else "unimplemented", self.map)
        return response_bytes(self.status, self.error)

    @property
    def addr(self) -> str:
        return f"127.0.0.1:{self.port}"

    def stop(self):
        self.server.stop(0)


class FakeStarlinkCom:
    """starlink.com's account side: the token from the cookie, the account's dishes, and gRPC-web status.
    Reached through PM_STARLINK_TEST_BASE (http://127.0.0.1:port), each real host as the first path part."""

    SSO = "sso-made-up-0001"
    IDLE = 600            # a session lapses 10 minutes after it was last kept alive (a visit to the account pages)

    def __init__(self):
        self.status: dict | None = healthy()
        self.map: dict | None = sky()
        self.expired = False
        self.clock = 0.0                                  # the stand-in's own time: tests move it on
        self.sessions = {self.SSO: self.IDLE}             # session cookie value -> when it lapses
        self.revoked_access: set[str] = set()             # short-lived access cookies it has deleted
        self.rotations = 0
        self.seen: list[tuple[str, str, dict]] = []      # (method, path, headers) of everything it was sent
        self.port = 0
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()
        self._ready.wait(10)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _run(self):
        from aiohttp import web
        asyncio.set_event_loop(self._loop)

        async def any_route(req):
            self.seen.append((req.method, req.path, dict(req.headers)))
            jar = dict(p.strip().partition("=")[::2] for p in req.headers.get("Cookie", "").split(";") if "=" in p)
            sso = jar.get("Starlink.Com.Sso", "")
            if self.expired or self.sessions.get(sso, -1) < self.clock:
                return web.json_response({"error": "authenticated_user_required"}, status=401)
            if jar.get("Starlink.Com.Access") in self.revoked_access:
                return web.json_response({"error": "token_expired"}, status=401)
            if req.path in ("/www.starlink.com/account/home", "/api.starlink.com/auth-rp/auth/user"):
                # Keeping the session alive: a new session cookie (the old one lasts a minute more) and the
                # short-lived access cookie from the browser deleted
                self.rotations += 1
                new = f"sso-made-up-{self.rotations + 1:04d}"
                self.sessions[new] = self.clock + self.IDLE
                self.sessions[sso] = min(self.sessions[sso], self.clock + 60)
                if jar.get("Starlink.Com.Access"):
                    self.revoked_access.add(jar["Starlink.Com.Access"])
                resp = web.Response(text="<html>account</html>", content_type="text/html")
                resp.headers.add("Set-Cookie", f"Starlink.Com.Sso={new}; Path=/; Domain=.starlink.com; Secure; HttpOnly; SameSite=None")
                resp.headers.add("Set-Cookie", "Starlink.Com.Access=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/")
                return resp
            if req.path == "/starlink.com/api/auth/auth/refresh-token":
                resp = web.json_response({"accessToken": "bearer-made-up-" + "x" * 30, "expiresIn": 3600})
                resp.set_cookie("XSRF-TOKEN", "xsrf-rotated")
                return resp
            if req.headers.get("Authorization") != "Bearer bearer-made-up-" + "x" * 30:
                return web.json_response({"error": "token_expired"}, status=401)
            if req.path == "/api.starlink.com/webagg/v2/accounts/service-lines":
                return web.json_response({"isValid": True, "content": {"results": [
                    {"serviceLineNumber": "SL-000000-00000-00", "nickname": "Garage", "userTerminals": [
                        {"userTerminalId": "00000000-11111111-22222222", "kitSerialNumber": "KIT000000000"}]}]}})
            if req.path == "/www.starlink.com/api/SpaceX.API.Device.Device/Handle":
                body = await req.read()
                n = int.from_bytes(body[1:5], "big")
                r = Request.FromString(body[5:5 + n])
                assert (r.HasField("get_status") or r.HasField("dish_get_obstruction_map")) and not r.HasField("reboot") \
                    and not r.HasField("dish_clear_obstruction_map")
                if r.target_id != "ut00000000-11111111-22222222":
                    trailer = b"grpc-status: 5\r\ngrpc-message: device not found\r\n"
                    return web.Response(body=b"\x80" + len(trailer).to_bytes(4, "big") + trailer,
                                        content_type="application/grpc-web+proto")
                if self.status is None:
                    trailer = b"grpc-status: 14\r\ngrpc-message: device offline\r\n"
                    return web.Response(body=b"\x80" + len(trailer).to_bytes(4, "big") + trailer,
                                        content_type="application/grpc-web+proto")
                msg = response_bytes(self.status, "", self.map if r.HasField("dish_get_obstruction_map") else None)
                trailer = b"grpc-status: 0\r\n"
                return web.Response(body=b"\x00" + len(msg).to_bytes(4, "big") + msg + b"\x80" + len(trailer).to_bytes(4, "big") + trailer,
                                    content_type="application/grpc-web+proto")
            return web.json_response({"error": "not found"}, status=404)

        async def start():
            app = web.Application()
            app.router.add_route("*", "/{tail:.*}", any_route)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            self.port = site._server.sockets[0].getsockname()[1]
            self._ready.set()
        self._loop.run_until_complete(start())
        self._loop.run_forever()

    @classmethod
    def cookie(cls) -> str:
        return f"_ga=GA1.1.made-up; Starlink.Com.Sso={cls.SSO}; Starlink.Com.Access=access-made-up; XSRF-TOKEN=xsrf-first"

    def stale_browser_cookie_revoked(self):
        """The browser's short-lived access cookie has expired on the server (it does within minutes)."""
        self.revoked_access.add("access-made-up")
