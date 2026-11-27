"""Ignoring a whole folder of password-scan findings (issue #19): daily log files turn up under a new name every day,
so ignoring one file at a time never stays quiet. A folder ignore ("D:\\Logs\\*") covers every file in it and below it,
including ones found later. Paths are made up.

Run from the repository root:  python3 -m pytest tests/test_secret_folder_ignore.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))
import agents as a  # noqa: E402

STATUS = {"on": True, "done_at": "2026-11-27T09:00:00Z", "files": 120}


def f(path, rule="assign", key="password"):
    return {"path": path, "line": 3, "rule": rule, "key": key, "len": 12, "first": 1}


def test_folder_entry():
    assert a.secret_folder(r"D:\Logs\App\2026-11-27.txt") == "D:\\Logs\\App\\*"
    assert a.secret_folder("/var/log/app/today.txt") == "/var/log/app/*" and a.secret_folder("nofolder.txt") == ""
    assert a.folder_ignore("D:\\Logs\\*") and a.folder_ignore("/var/log/*")
    assert not a.folder_ignore(r"D:\Logs\a.txt|assign|password") and not a.folder_ignore("*") and not a.folder_ignore("D:\\Logs")
    assert a.clean_ignore_item("secret", "D:\\Logs\\*") == "secret:D:\\Logs\\*"


def test_folder_ignore_quietens_new_files_too():
    ign = a.Ignore(["secret:D:\\Logs\\App\\*"])
    today, tomorrow = f(r"D:\Logs\App\2026-11-27.txt"), f(r"d:\logs\app\Archive\2026-11-28.txt")
    other = f(r"D:\Logs\AppOther\notes.txt")
    assert ign.secret(today) and ign.secret(tomorrow)                     # below it, and in any case
    assert not ign.secret(other)                                         # a folder that only starts the same isn't it
    assert a.secrets_state(STATUS, [today, tomorrow], ign) == (a.OK, "None found in 120 files (2 ignored)")
    lvl, detail = a.secrets_state(STATUS, [today, other], ign)
    assert lvl == a.WARN and "notes.txt" in detail and "2026-11-27" not in detail


def test_file_ignores_still_work_and_linux_paths():
    one = f(r"D:\Scripts\deploy.ps1")
    ign = a.Ignore(["secret:" + a.secret_key(one), "secret:/opt/app/logs/*"])
    assert ign.secret(one) and not ign.secret(f(r"D:\Scripts\other.ps1"))
    assert ign.secret(f("/opt/app/logs/2026/11/27.txt")) and not ign.secret(f("/opt/app/config.yml"))
