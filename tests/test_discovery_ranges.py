"""Network scan ranges: oversized ranges are refused before any address is listed (security review RC-01), and
valid ranges still work.

Run from the repository root:  python3 -m pytest tests/test_discovery_ranges.py
"""
import ipaddress
import sys
import time
import tracemalloc
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import discovery  # noqa: E402


@pytest.mark.parametrize("cidr", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/21"])
def test_oversized_ranges_are_refused_without_listing_them(cidr, monkeypatch):
    listed = []
    real = ipaddress.IPv4Network.hosts
    monkeypatch.setattr(ipaddress.IPv4Network, "hosts", lambda self: listed.append(self) or real(self))
    tracemalloc.start()
    t = time.perf_counter()
    out, problems = discovery.parse_ranges(cidr)
    took = time.perf_counter() - t
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert out == [] and len(problems) == 1 and f"more than {discovery.MAX_PER_RANGE} addresses" in problems[0]
    assert not listed, "the range was listed before being refused"
    assert took < 0.1 and peak < 1_000_000


def test_largest_allowed_ranges_still_work():
    out, problems = discovery.parse_ranges("10.0.0.0/22")    # 1,022 hosts
    assert problems == [] and len(out) == 1022 and out[0] == "10.0.0.1" and out[-1] == "10.0.3.254"
    out, problems = discovery.parse_ranges("192.168.1.0/24, 192.168.1.10-20, 10.0.1.5")
    assert problems == [] and len(out) == 255 and "10.0.1.5" in out     # duplicates counted once


def test_a_slash_23_and_dash_ranges_over_the_limit():
    assert discovery.parse_ranges("10.0.0.0/23")[0] != []
    out, problems = discovery.parse_ranges("10.0.0.0-10.0.8.0")
    assert out == [] and "more than" in problems[0]


def test_public_and_ipv6_ranges_are_still_refused():
    assert "only private" in discovery.parse_ranges("8.8.8.0/24")[1][0]
    assert "IPv4 only" in discovery.parse_ranges("fd00::/120")[1][0]
