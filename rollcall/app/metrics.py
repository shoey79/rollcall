"""Metrics history from agent reports: disk space, network traffic, CPU and memory, for graphs.

Kept apart from the up/down history (and history_days), so it can be kept for a year for capacity
planning. Every report is kept for two days; after that they're rolled up into hourly figures, and
after a month into daily ones (average, lowest and highest), kept for metrics_days. About 10 series
per device: roughly 30,000 rows, a few MB, per device for a year.

Series names: "cpu" and "mem" (percent), "disk|<volume>|used" and "disk|<volume>|size" (GB),
"nic|<adapter>|rx" and "nic|<adapter>|tx" (bits per second, averaged since the previous report).
"""
from __future__ import annotations

import sqlite3
import time

RAW, HOUR, DAY = 0, 3600, 86400
RAW_KEEP = 2 * DAY       # every report, for the 24-hour graph (and a day spare)
HOUR_KEEP = 32 * DAY     # hourly figures, for the 7- and 30-day graphs
MAX_NICS = 6
MAX_DISKS = 32

RANGES = {"24h": DAY, "7d": 7 * DAY, "30d": 30 * DAY, "90d": 90 * DAY, "1y": 365 * DAY}
POINTS = 240             # about this many points per graph, whatever the range


class Metrics:
    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS metrics ("
            " host TEXT NOT NULL, series TEXT NOT NULL, res INTEGER NOT NULL, ts REAL NOT NULL,"
            " avg REAL NOT NULL, lo REAL NOT NULL, hi REAL NOT NULL, n INTEGER NOT NULL,"
            " PRIMARY KEY (host, series, res, ts)) WITHOUT ROWID")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_metrics_age ON metrics(res, ts)")
        self.db.commit()

    # -- recording ----------------------------------------------------------------------
    def record(self, host: str, ts: float, values: dict[str, float]) -> None:
        rows = [(host, s, RAW, ts, v, v, v, 1) for s, v in values.items() if v is not None]
        if rows:
            self.db.executemany("INSERT OR REPLACE INTO metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
            self.db.commit()

    @staticmethod
    def from_report(report: dict, nic_rates: dict) -> dict[str, float]:
        """The values worth keeping from one agent report."""
        out: dict[str, float] = {}
        cpu = report.get("cpu_pct")
        if isinstance(cpu, (int, float)) and not isinstance(cpu, bool) and 0 <= cpu <= 100:
            out["cpu"] = float(cpu)
        tot, free = report.get("mem_total_mb"), report.get("mem_free_mb")
        if isinstance(tot, (int, float)) and isinstance(free, (int, float)) and tot > 0 and 0 <= free <= tot:
            out["mem"] = round(100 * (1 - free / tot), 1)
        for d in (report.get("disks") or [])[:MAX_DISKS]:
            try:
                name, size, free = str(d.get("name") or "")[:80], float(d.get("size_gb") or 0), float(d.get("free_gb") or 0)
            except (TypeError, ValueError, AttributeError):
                continue
            if not name or size < 0.5 or not 0 <= free <= size * 1.01:
                continue
            out[f"disk|{name}|used"] = round(size - free, 2)
            out[f"disk|{name}|size"] = round(size, 2)
        # Connected adapters that carry traffic: physical ones, and virtual ones with an address
        # (e.g. a Hyper-V host's vEthernet), not every idle virtual adapter
        ads = (((report.get("checks") or {}).get("nics") or {}).get("adapters") or [])
        keep = {str(a.get("name") or "").lower() for a in ads
                if a.get("status") == "up" and (not a.get("virtual") or a.get("ips"))}
        for k, r in [(k, r) for k, r in (nic_rates or {}).items() if not ads or k in keep][:MAX_NICS]:
            for f, s in (("rx_bps", "rx"), ("tx_bps", "tx")):
                v = r.get(f)
                if isinstance(v, (int, float)) and v >= 0:
                    out[f"nic|{k}|{s}"] = float(v)
        return out

    # -- roll-ups and retention ---------------------------------------------------------
    def rollup(self, now: float, keep_days: int) -> None:
        """Every report older than a week into hourly figures, hourly older than ~90 days into daily
        ones, and daily older than keep_days dropped. Only whole buckets are rolled up."""
        self._roll(RAW, HOUR, (now - RAW_KEEP) // HOUR * HOUR)
        self._roll(HOUR, DAY, (now - HOUR_KEEP) // DAY * DAY)
        self.db.execute("DELETE FROM metrics WHERE res = ? AND ts < ?", (DAY, now - max(7, keep_days) * DAY))
        self.db.execute("DELETE FROM metrics WHERE res = ? AND ts < ?", (HOUR, now - max(7, keep_days) * DAY))
        self.db.commit()

    def _roll(self, src: int, dst: int, before: float) -> None:
        rows = self.db.execute(
            "SELECT host, series, CAST(ts / ? AS INTEGER) * ?, SUM(avg * n), SUM(n), MIN(lo), MAX(hi)"
            " FROM metrics WHERE res = ? AND ts < ? GROUP BY host, series, CAST(ts / ? AS INTEGER)",
            (dst, dst, src, before, dst)).fetchall()
        if not rows:
            return
        for host, series, bucket, total, n, lo, hi in rows:
            old = self.db.execute("SELECT avg, n, lo, hi FROM metrics WHERE host = ? AND series = ? AND res = ? AND ts = ?",
                                  (host, series, dst, bucket)).fetchone()
            if old:  # a bucket partly rolled up before (e.g. the add-on was off for a while)
                total, n, lo, hi = total + old[0] * old[1], n + old[1], min(lo, old[2]), max(hi, old[3])
            self.db.execute("INSERT OR REPLACE INTO metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (host, series, dst, float(bucket), total / n, lo, hi, n))
        self.db.execute("DELETE FROM metrics WHERE res = ? AND ts < ?", (src, before))

    def clear(self, host: str | None = None) -> None:
        if host is None:
            self.db.execute("DELETE FROM metrics")
        else:
            self.db.execute("DELETE FROM metrics WHERE host = ?", (host,))
        self.db.commit()

    def rename(self, old: str, new: str) -> None:
        self.db.execute("UPDATE OR REPLACE metrics SET host = ? WHERE host = ?", (new, old))
        self.db.commit()

    # -- reading ------------------------------------------------------------------------
    def series(self, host: str) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT DISTINCT series FROM metrics WHERE host = ?", (host,))]

    def query(self, host: str, series: str, start: float, end: float, step: float) -> list[list]:
        """[[bucket start, average, lowest, highest], ...] in buckets of `step` seconds. Each stored row
        counts by how many reports it stands for, so an hourly figure weighs as much as its reports."""
        rows = self.db.execute(
            "SELECT ts, avg, lo, hi, n, res FROM metrics WHERE host = ? AND series = ? AND ts >= ? AND ts < ? ORDER BY ts",
            (host, series, start - DAY, end)).fetchall()
        buckets: dict[int, list] = {}
        for ts, avg, lo, hi, n, res in rows:
            mid = ts + res / 2  # an hourly or daily figure stands for the middle of its hour or day
            if mid < start or mid >= end:
                continue
            b = int((mid - start) // step)
            x = buckets.setdefault(b, [0.0, 0, lo, hi])
            x[0] += avg * n
            x[1] += n
            x[2], x[3] = min(x[2], lo), max(x[3], hi)
        return [[start + b * step, round(t / n, 3), round(lo, 3), round(hi, 3)] for b, (t, n, lo, hi) in sorted(buckets.items())]

    def view(self, host: str, names: list[str], rng: str, now: float | None = None) -> dict:
        now = now or time.time()
        span = RANGES.get(rng, DAY)
        step = max(300, span / POINTS)
        # whole steps, so a graph doesn't shift between refreshes
        end = (now // step + 1) * step
        start = end - span
        out = {"range": rng, "start": start, "end": end, "step": step, "series": {}}
        for s in names[:8]:
            out["series"][s] = self.query(host, s, start, end, step)
        first = self.db.execute("SELECT MIN(ts) FROM metrics WHERE host = ?", (host,)).fetchone()
        out["since"] = first[0] if first and first[0] else None
        return out


def disk_forecast(points: list[list], size_gb: float | None, now: float) -> dict | None:
    """When a disk will be full, going by how used space has grown over the points given (a least-
    squares line through the daily averages). None with less than 3 days of history.

    {"gb_per_day": growth, "full_in_days": days or None (not growing, or over 10 years away)}"""
    if not points or not size_gb:
        return None
    days: dict[int, list] = {}
    for ts, avg, *_ in points:
        days.setdefault(int(ts // DAY), []).append(avg)
    xs = sorted(days)
    if len(xs) < 3 or xs[-1] - xs[0] < 3:
        return None
    ys = [sum(days[x]) / len(days[x]) for x in xs]
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if not sxx:
        return None
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx  # GB per day
    out = {"gb_per_day": round(slope, 3), "full_in_days": None, "based_on_days": xs[-1] - xs[0] + 1}
    if slope > 0.001:
        current = my + slope * (now / DAY - mx)
        left = (size_gb - current) / slope
        if 0 <= left <= 3650:
            out["full_in_days"] = round(left, 1)
        elif left < 0:
            out["full_in_days"] = 0
    return out
