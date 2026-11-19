"""Named IP ranges (Settings, Display): e.g. "Servers=10.0.1.0/24", shown next to each device's address.

A range is written as a subnet (10.0.1.0/24), a span (10.0.1.10-10.0.1.50 or 10.0.1.10-50) or with
wildcards (10.0.1.* or 10.0.*). Where ranges overlap, the smallest one that holds the address wins,
so "Network=10.0.0.0/16" and "Printers=10.0.5.0/24" can be used together. IPv4 only.
"""
from __future__ import annotations

import ipaddress
import re

_NAME = re.compile(r"^[^=]{1,40}$")
_OCTET = r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IP = rf"{_OCTET}(\.{_OCTET}){{3}}"
_SPAN = re.compile(rf"^({_IP})-({_IP}|{_OCTET})$")
_WILD = re.compile(rf"^{_OCTET}(\.({_OCTET}|\*)){{1,3}}$")


def _num(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def parse_range(text: str) -> tuple[int, int]:
    """(first, last) address of a range as numbers. Raises ValueError if it isn't one."""
    t = text.strip()
    if "/" in t:
        try:
            net = ipaddress.IPv4Network(t, strict=False)
        except ValueError:
            raise ValueError(f"'{t}' isn't a subnet like 10.0.1.0/24") from None
        return int(net.network_address), int(net.broadcast_address)
    if m := _SPAN.match(t):
        first, last = m.group(1), m.group(5)
        lo = _num(first)
        hi = _num(last) if "." in last else (lo & ~0xFF) | int(last)
        if hi < lo:
            raise ValueError(f"'{t}' ends before it starts")
        return lo, hi
    if re.fullmatch(_IP, t):
        return _num(t), _num(t)
    if _WILD.match(t):
        parts = t.split(".")
        if "*" in parts and any(p != "*" for p in parts[parts.index("*"):]):
            raise ValueError(f"'{t}': wildcards go at the end, e.g. 10.0.1.*")
        fixed = [p for p in parts if p != "*"]
        lo_parts = fixed + ["0"] * (4 - len(fixed))
        hi_parts = fixed + ["255"] * (4 - len(fixed))
        return _num(".".join(lo_parts)), _num(".".join(hi_parts))
    raise ValueError(f"'{t}' isn't an IP range (use 10.0.1.0/24, 10.0.1.10-50 or 10.0.1.*)")


def parse_entry(entry: str) -> tuple[str, list[tuple[int, int]]]:
    """'Servers=10.0.1.0/24, 10.0.2.0/24' -> ("Servers", [(first, last), ...]). Raises ValueError."""
    name, sep, ranges = str(entry).partition("=")
    name = " ".join(name.split())
    if not sep or not name or not _NAME.match(name):
        raise ValueError(f"'{str(entry)[:60]}': write it as Name=range, e.g. Servers=10.0.1.0/24")
    parts = [p for p in re.split(r"[,\s]+", ranges) if p]
    if not parts:
        raise ValueError(f"'{name}': add a range after the =, e.g. {name}=10.0.1.0/24")
    return name, [parse_range(p) for p in parts]


class Ranges:
    """Looks up the name of the range an address is in."""

    def __init__(self, entries):
        self.spans: list[tuple[int, int, int, str]] = []  # (size, first, last, name), smallest first
        for e in entries or []:
            try:
                name, spans = parse_entry(e)
            except ValueError:
                continue
            self.spans += [(hi - lo, lo, hi, name) for lo, hi in spans]
        self.spans.sort()
        self._cache: dict[str, str | None] = {}

    def name_of(self, ip: str | None) -> str | None:
        if not ip or not self.spans:
            return None
        if ip in self._cache:
            return self._cache[ip]
        try:
            n = _num(ip)
        except ValueError:
            n = None
        hit = next((name for _size, lo, hi, name in self.spans if n is not None and lo <= n <= hi), None)
        if len(self._cache) < 10000:
            self._cache[ip] = hit
        return hit
