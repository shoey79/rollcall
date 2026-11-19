"""The Jellyfin tab's data: what's playing, plugins that need attention, and library counts.

Feeds jellyfin.parse() answers shaped like Jellyfin 10.10's (made-up users and titles).

Run from the repository root:  python3 -m pytest tests/test_jellyfin_details.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))
import jellyfin as jf  # noqa: E402

T = 10_000_000
INFO = {"ServerName": "Media", "Version": "10.10.7", "HasPendingRestart": True}
SESSIONS = [
    {"UserName": "alice", "Client": "Jellyfin Android TV", "DeviceName": "Living room TV",
     "NowPlayingItem": {"Name": "The Pilot", "Type": "Episode", "SeriesName": "Example Show", "ParentIndexNumber": 1, "IndexNumber": 2,
                        "RunTimeTicks": 2700 * T},
     "PlayState": {"PlayMethod": "Transcode", "PositionTicks": 900 * T, "IsPaused": False},
     "TranscodingInfo": {"IsVideoDirect": False, "IsAudioDirect": True, "VideoCodec": "h264", "Height": 1080, "Bitrate": 8_000_000,
                         "TranscodeReasons": ["VideoCodecNotSupported", "ContainerBitrateExceedsLimit"]}},
    {"UserName": "bob", "Client": "Jellyfin Web", "DeviceName": "Firefox",
     "NowPlayingItem": {"Name": "A Film", "Type": "Movie", "ProductionYear": 2019, "RunTimeTicks": 6000 * T},
     "PlayState": {"PlayMethod": "DirectPlay", "PositionTicks": 60 * T, "IsPaused": True}},
    {"UserName": "alice", "Client": "Jellyfin iOS", "DeviceName": "Phone"},    # signed in, not playing
]
PLUGINS = [{"Name": "LDAP Authentication", "Version": "19.0.0.0", "Status": "Malfunctioned"},
           {"Name": "TMDb", "Version": "10.10.7.0", "Status": "Active"},
           {"Name": "Old Plugin", "Version": "1.0", "Status": "Disabled"}]
COUNTS = {"MovieCount": 412, "SeriesCount": 38, "EpisodeCount": 2210, "SongCount": 0, "BookCount": 3}


def test_streams_plugins_and_library():
    d = jf.parse("Healthy", INFO, [], SESSIONS, 12.0, plugins=PLUGINS, counts=COUNTS)
    assert d["streams"] == 2 and d["transcodes"] == 1 and d["users"] == 2
    ep, film = d["playing"]
    assert ep == {"user": "alice", "client": "Jellyfin Android TV", "device": "Living room TV", "title": "Example Show S01E02 · The Pilot",
                  "type": "Episode", "method": "Transcoding", "paused": False, "position_s": 900, "runtime_s": 2700,
                  "reasons": ["video codec not supported", "container bitrate exceeds limit"],
                  "transcode": "video to h264, audio copied, 1080p, 8.0 Mbit/s"}
    assert film["title"] == "A Film (2019)" and film["method"] == "Direct play" and film["paused"] and film["reasons"] == []
    assert d["plugins"] == [{"name": "LDAP Authentication", "version": "19.0.0.0", "status": "Malfunctioned", "why": "failed to load"}]
    assert d["library"] == [{"name": "Movies", "count": 412}, {"name": "Series", "count": 38}, {"name": "Episodes", "count": 2210},
                            {"name": "Books", "count": 3}]


def test_restart_pending_says_which_plugin():
    d = jf.parse("Healthy", INFO, [], [], plugins=PLUGINS, counts=COUNTS)
    ok, _, detail, level = jf.evaluate(d)
    assert not ok and level == "warn" and "restart pending (LDAP Authentication: failed to load)" in detail
    d = jf.parse("Healthy", INFO, [], [], plugins=None, counts=None)          # a key that can't read plugins
    assert jf.evaluate(d)[2].endswith("restart pending") and d["plugins"] == [] and d["library"] == []
