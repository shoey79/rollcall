"""The 24-hour uptime and history strip, worked out in one pass, match the original per-segment
calculation exactly, and are much faster (the dashboard asks for them for everything, often).

Run from the repository root:  python3 -m pytest tests/test_day_summary.py
"""
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import main as M  # noqa: E402

SIZE, N = M.DAY / M.BUCKETS, M.BUCKETS


def old(rows, now, max_gap):
    """The calculation before 1.85.3: coverage() for each segment, and uptime_pct() for the day."""
    first = M.Monitor.history_start(now)
    strip = []
    for b in range(N):
        start = first + b * SIZE
        up, down, maint = M.coverage(rows, start, min(start + SIZE, now), max_gap)
        strip.append(("m" if maint > 0 else "n") if up + down <= 0 else ("g" if down == 0 else "r" if up == 0 else "a"))
    return M.uptime_pct(rows, now - M.DAY, now, max_gap), strip


def history(now, step, rng, gaps=False):
    """Checks every `step` s for 25 hours: mostly up, some down, some maintenance, maybe some gaps."""
    rows, t = [], now - 25 * 3600
    state = 1
    while t < now:
        r = rng.random()
        if r < 0.01:
            state = 0
        elif r < 0.03:
            state = 1
        elif r < 0.035:
            state = M.MAINT_OK
        rows.append((t, state))
        t += step * (rng.uniform(5, 40) if gaps and rng.random() < 0.01 else rng.uniform(0.8, 1.2))
    return rows


def test_one_pass_matches_the_original_exactly():
    rng = random.Random(7)
    for i in range(60):
        now = 1794000000 + rng.uniform(0, 86400)
        step = rng.choice([15, 30, 60, 300])
        rows = history(now, step, rng, gaps=i % 2 == 0)
        max_gap = rng.choice([90, 180, 900])
        since = [r for r in rows if r[0] >= now - M.DAY]
        before = [r for r in rows if r[0] < now - M.DAY][-1:]
        got = M.day_summary(before + since, M.Monitor.history_start(now), now, SIZE, N, max_gap)
        assert got == old(rows, now, max_gap), i


def test_edge_cases():
    now = 1794000000.0
    first = M.Monitor.history_start(now)
    assert M.day_summary([], first, now, SIZE, N, 90) == (None, ["n"] * N)
    rows = [(now - 60, M.MAINT_OK)]
    assert M.day_summary(rows, first, now, SIZE, N, 90) == old(rows, now, 90)
    rows = [(now - 2 * M.DAY, 1)]                     # one old row: max_gap stops it counting now
    assert M.day_summary(rows, first, now, SIZE, N, 90) == old(rows, now, 90) == (None, ["n"] * N)


def test_much_faster():
    rng = random.Random(1)
    now = 1794000000.0
    rows = history(now, 30, rng)
    t0 = time.perf_counter()
    old(rows, now, 90)
    t_old = time.perf_counter() - t0
    t0 = time.perf_counter()
    M.day_summary(rows, M.Monitor.history_start(now), now, SIZE, N, 90)
    t_new = time.perf_counter() - t0
    assert t_new * 10 < t_old, (t_old, t_new)
    print(f"old {t_old * 1000:.1f} ms, new {t_new * 1000:.1f} ms per host")
