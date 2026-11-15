"""Metrics history for graphs: recorded from agent reports, rolled up as it ages, and read back.

Run from the repository root:  python3 -m pytest tests/test_metrics.py
"""
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import metrics as M  # noqa: E402

DAY, HOUR = 86400, 3600
NOW = 1_800_000_000.0 // DAY * DAY  # midnight, to keep buckets simple


def store():
    return M.Metrics(sqlite3.connect(":memory:"))


def test_values_taken_from_a_report():
    rep = {"cpu_pct": 37, "mem_total_mb": 8192, "mem_free_mb": 2048,
           "disks": [{"name": "C:", "size_gb": 100, "free_gb": 40}, {"name": "tiny", "size_gb": 0.1, "free_gb": 0}, {"name": "bad"}]}
    rep["checks"] = {"nics": {"adapters": [{"name": "Ethernet", "status": "up"}, {"name": "vEthernet (idle)", "status": "up", "virtual": True},
                                           {"name": "Wi-Fi", "status": "down"}]}}
    rates = {"ethernet": {"rx_bps": 8000, "tx_bps": 1000}, "vethernet (idle)": {"rx_bps": 0, "tx_bps": 0}, "wi-fi": {"rx_bps": 0, "tx_bps": 0}}
    v = M.Metrics.from_report(rep, rates)
    assert v == {"cpu": 37.0, "mem": 75.0, "disk|C:|used": 60.0, "disk|C:|size": 100.0,
                 "nic|ethernet|rx": 8000.0, "nic|ethernet|tx": 1000.0}
    assert M.Metrics.from_report({"cpu_pct": 250, "mem_total_mb": 0}, {}) == {}


def test_reports_roll_up_without_changing_the_average():
    m = store()
    # 10 days of reports every 5 minutes; used space climbs 1 GB a day
    for i in range(10 * 288):
        ts = NOW - 10 * DAY + i * 300
        m.record("srv01", ts, {"disk|C:|used": 50 + (ts - (NOW - 10 * DAY)) / DAY, "cpu": 20 if i % 2 else 40})
    before = m.query("srv01", "cpu", NOW - 10 * DAY, NOW, DAY)
    m.rollup(NOW, 365)
    raw = m.db.execute("SELECT COUNT(*) FROM metrics WHERE res = 0").fetchone()[0]
    hourly = m.db.execute("SELECT COUNT(*) FROM metrics WHERE res = 3600").fetchone()[0]
    assert raw == 2 * 288 * 2 and hourly == 8 * 24 * 2       # the last 2 days stay as they were
    after = m.query("srv01", "cpu", NOW - 10 * DAY, NOW, DAY)
    assert [round(p[1], 6) for p in after] == [round(p[1], 6) for p in before]
    assert all(p[2] == 20 and p[3] == 40 for p in after)      # lowest and highest survive the roll-up
    m.rollup(NOW, 365)                                        # again: nothing changes
    assert m.db.execute("SELECT COUNT(*) FROM metrics WHERE res = 3600").fetchone()[0] == hourly


def test_old_hourly_figures_become_daily_and_go_after_keep_days():
    m = store()
    for h in range(200 * 24):
        m.db.execute("INSERT INTO metrics VALUES ('srv01', 'cpu', 3600, ?, 10, 5, 15, 12)", (NOW - 200 * DAY + h * HOUR,))
    m.rollup(NOW, 150)
    res = dict(m.db.execute("SELECT res, COUNT(*) FROM metrics GROUP BY res").fetchall())
    assert res[DAY] == 150 - 32 and res[HOUR] == 32 * 24      # older than a month: daily; older than 150 days: gone
    oldest = m.db.execute("SELECT MIN(ts) FROM metrics").fetchone()[0]
    assert oldest >= NOW - 150 * DAY


def test_view_has_about_240_points_whatever_the_range():
    m = store()
    for i in range(288):
        m.record("srv01", NOW - DAY + i * 300, {"cpu": 50})
    v = m.view("srv01", ["cpu"], "24h", NOW)
    assert 230 <= len(v["series"]["cpu"]) <= 290 and v["step"] == 360
    assert v["since"] == NOW - DAY


def test_forecast_when_full():
    pts = [[NOW - (30 - d) * DAY, 100 + 2 * d, 0, 0] for d in range(30)]     # 2 GB a day, 160 GB used now
    f = M.disk_forecast(pts, 500, NOW)
    assert f["gb_per_day"] == 2 and 165 <= f["full_in_days"] <= 172
    flat = [[NOW - d * DAY, 100, 0, 0] for d in range(30)]
    assert M.disk_forecast(flat, 500, NOW)["full_in_days"] is None
    assert M.disk_forecast(pts[:2], 500, NOW) is None                         # too little history
