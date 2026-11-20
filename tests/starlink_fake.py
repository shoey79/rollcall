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
    msg("Request", [("id", 1, F.TYPE_UINT64), ("target_id", 13, F.TYPE_STRING),
                    ("get_status", 1004, F.TYPE_MESSAGE, ".SpaceX.API.Device.GetStatusRequest"),
                    ("reboot", 1001, F.TYPE_MESSAGE, ".SpaceX.API.Device.RebootRequest")])
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
        ("swupdate_reboot_ready", 1030, F.TYPE_BOOL), ("reboot_reason", 1032, F.TYPE_INT32)])
    msg("Status", [("code", 1, F.TYPE_INT32), ("message", 2, F.TYPE_STRING)])
    msg("Response", [("id", 1, F.TYPE_UINT64), ("status", 2, F.TYPE_MESSAGE, ".SpaceX.API.Device.Status"),
                     ("api_version", 3, F.TYPE_UINT64),
                     ("dish_get_status", 2004, F.TYPE_MESSAGE, ".SpaceX.API.Device.DishGetStatusResponse")])
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
    }


def response_bytes(status: dict | None, error: str = "") -> bytes:
    r = Response(api_version=30)
    if status is not None:
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
        else:
            setattr(m, k, v)
    return m


class FakeDish:
    """A gRPC server answering SpaceX.API.Device.Device/Handle like a dish (plain gRPC, HTTP/2, no TLS)."""

    def __init__(self, port: int = 0):
        import grpc
        self.status: dict | None = healthy()
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
        if req.HasField("reboot"):
            raise AssertionError("Rollcall asked the dish to reboot")
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

    def __init__(self):
        self.status: dict | None = healthy()
        self.expired = False
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
            cookie = req.headers.get("Cookie", "")
            if self.expired or f"Starlink.Com.Sso={self.SSO}" not in cookie:
                return web.json_response({"error": "authenticated_user_required"}, status=401)
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
                assert r.HasField("get_status") and not r.HasField("reboot")
                if r.target_id != "ut00000000-11111111-22222222":
                    trailer = b"grpc-status: 5\r\ngrpc-message: device not found\r\n"
                    return web.Response(body=b"\x80" + len(trailer).to_bytes(4, "big") + trailer,
                                        content_type="application/grpc-web+proto")
                if self.status is None:
                    trailer = b"grpc-status: 14\r\ngrpc-message: device offline\r\n"
                    return web.Response(body=b"\x80" + len(trailer).to_bytes(4, "big") + trailer,
                                        content_type="application/grpc-web+proto")
                msg = response_bytes(self.status)
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
        return f"_ga=GA1.1.made-up; Starlink.Com.Sso={cls.SSO}; XSRF-TOKEN=xsrf-first"
