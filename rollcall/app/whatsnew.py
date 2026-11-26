"""What's new: the changelog's headline for each version an admin hasn't seen yet.

Each admin's last-seen version is kept here (not in their browser), so it shows once per admin wherever they open
Rollcall. A fresh install starts everyone at the version it was installed with, so nobody gets a pop-up the first
time; an install that was already running before this existed starts at BEFORE (the last release without it).
"""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

BEFORE = "1.98.1"   # the release before What's new: installs upgraded from it see everything since
HEAD = re.compile(r"^## (\d+(?:\.\d+)+)(?:\s*[-–]\s*(.+?))?\s*$")
LEAD = re.compile(r"^- \*\*(.+?)\*\*")


def vt(v) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:4]) or (0,)


def plain(md: str) -> str:
    """Markdown to plain text for a headline: links keep their text, code and emphasis lose their marks."""
    md = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", md)
    return re.sub(r"[*`_]", "", md).strip().rstrip(".")


def parse(text: str) -> list[dict]:
    """[{"version", "date", "lines": [headline, ...]}], newest first, as the changelog lists them.
    "Unreleased" isn't a version, so it's left out."""
    out: list[dict] = []
    cur = None
    for line in text.splitlines():
        if line.startswith("## "):
            m = HEAD.match(line)
            cur = {"version": m.group(1), "date": (m.group(2) or "").strip(), "lines": []} if m else None
            if cur:
                out.append(cur)
        elif cur is not None and (m := LEAD.match(line)):
            cur["lines"].append(plain(m.group(1)))
    return out


class WhatsNew:
    def __init__(self, path: Path, changelog: Path, version: str | None, existing_install: bool):
        self.path, self.changelog, self.version = path, changelog, str(version or "")
        self.lock = threading.Lock()
        try:
            self.state = json.loads(path.read_text())
        except (OSError, ValueError):
            self.state = {}
        if "baseline" not in self.state:
            # First start with What's new: an install that was already there has seen up to BEFORE; a new one has
            # seen this version (so its first admin isn't shown the whole history)
            self.state = {"baseline": BEFORE if existing_install else (self.version or BEFORE), "seen": {}}
            self._save()
        self._entries: list[dict] | None = None

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=1))
        tmp.replace(self.path)

    def entries(self) -> list[dict]:
        if self._entries is None:
            try:
                self._entries = parse(self.changelog.read_text(encoding="utf-8"))
            except OSError:
                self._entries = []
        return self._entries

    def last_seen(self, uid: str) -> str:
        return (self.state.get("seen") or {}).get(uid) or self.state.get("baseline") or BEFORE

    def unseen(self, uid: str) -> list[dict]:
        """The versions after the one this admin last saw, up to the running one, newest first (several skipped
        versions come together). Nothing when the running version is unknown (a development build)."""
        if not uid or not self.version:
            return []
        seen, now = vt(self.last_seen(uid)), vt(self.version)
        return [e for e in self.entries() if seen < vt(e["version"]) <= now and e["lines"]]

    def mark_seen(self, uid: str) -> None:
        if not uid or not self.version:
            return
        with self.lock:
            seen = self.state.setdefault("seen", {})
            seen[str(uid)[:80]] = self.version
            while len(seen) > 500:
                seen.pop(next(iter(seen)))
            self._save()

    def changelog_text(self) -> str:
        try:
            return self.changelog.read_text(encoding="utf-8")
        except OSError:
            return ""
