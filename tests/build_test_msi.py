"""Builds a test agent installer for the Windows MSI check on GitHub (needs msitools: wixl, msibuild).
Usage: python tests/build_test_msi.py OUTPUT.msi"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))
import main  # noqa: E402
import msi  # noqa: E402

script = main.build_agent_script("windows", "http://127.0.0.1:9", "testkey", False)   # nothing listens there
Path(sys.argv[1]).write_bytes(asyncio.run(msi.build(script, main._script_version() or "1.0.0")))
print("built", sys.argv[1])
