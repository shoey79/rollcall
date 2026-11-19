"""The Jellyfin check reads Jellyfin's whole answer, even when it arrives in pieces.

It used to take one read of the reply, which returns only what had arrived so far: when an answer came
in two network packets, the check saw half of it and said "not Jellyfin? /System/Info didn't answer with
JSON" now and then. A stand-in Jellyfin here sends each answer in parts, with a pause between.

Run from the repository root:  python3 -m pytest tests/test_jellyfin_split.py
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))
import jellyfin  # noqa: E402

INFO = {"ServerName": "Media", "Version": "10.10.7", "Id": "abc", "HasPendingRestart": False, "OperatingSystem": "Linux",
        "Padding": "x" * 6000}   # long enough to come in more than one piece


def serve(answers: dict, pieces: int = 3, pause: float = 0.05):
    async def handle(reader, writer):
        line = (await reader.readline()).decode()
        while (await reader.readline()) not in (b"\r\n", b""):
            pass
        path = line.split(" ")[1].split("?")[0]
        body = answers.get(path, "").encode()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
        step = max(1, len(body) // pieces + 1)
        for i in range(0, len(body), step):
            part = body[i:i + step]
            writer.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
            await writer.drain()
            await asyncio.sleep(pause)  # the rest arrives a moment later
        writer.write(b"0\r\n\r\n")
        await writer.drain()
        writer.close()
    return asyncio.start_server(handle, "127.0.0.1", 0)


def test_answers_in_pieces_are_read_whole():
    async def go():
        srv = await serve({"/health": "Healthy", "/System/Info": json.dumps(INFO), "/ScheduledTasks": "[]",
                           "/Sessions": json.dumps([{"NowPlayingItem": {"Name": "A film"}, "PlayState": {"PlayMethod": "DirectPlay"}}])})
        async with srv:
            port = srv.sockets[0].getsockname()[1]
            return await jellyfin.poll(f"http://127.0.0.1:{port}", "key", None, timeout=10)
    r = asyncio.run(go())
    assert r["version"] == "10.10.7" and r["name"] == "Media" and r["streams"] == 1
