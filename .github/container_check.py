"""CI: the add-on's container, built from build.yaml's base image, starts, makes its update-signing key, and a real
Linux agent enrols, is approved and reports into it. Run by the "Add-on container" job after `docker run`."""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

UI, AGENT = "http://127.0.0.1:18099", "http://127.0.0.1:18100"
H = {"X-Remote-User-Id": "u-ci", "X-Remote-User-Name": "ci", "Content-Type": "application/json"}


def call(url, data=None, method=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None, headers=H, method=method)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


for _ in range(120):
    try:
        call(UI + "/api/status")
        break
    except (OSError, urllib.error.URLError):
        time.sleep(1)
else:
    sys.exit("the add-on didn't answer within 2 minutes")
print("add-on answers")

script = call(f"{UI}/api/agents/script?os=linux&server={urllib.request.quote(AGENT, safe='')}").decode()
assert 'UPDATE_KEY = "__PM_UPDATE_KEY__"' not in script and re.search(r'^UPDATE_KEY = "[A-Za-z0-9+/=]{300,}"', script, re.M), \
    "the downloaded agent has no update key built in"
prefix = tempfile.mkdtemp()
path = os.path.join(prefix, "usr/local/lib/pingmonitor/pingmonitor-agent.py")
os.makedirs(os.path.dirname(path))
open(path, "w").write(script)
env = {**os.environ, "PM_PREFIX": prefix}
subprocess.run([sys.executable, path], env=env, timeout=300)            # enrols
for p in json.loads(call(UI + "/api/agents"))["pending"]:
    call(f"{UI}/api/agents/approve/{p['id']}", {}, "POST")
subprocess.run([sys.executable, path], env=env, timeout=300, check=True)  # reports
log = open(os.path.join(prefix, "var/lib/pingmonitor/agent.log")).read()
print(log[-1500:])
assert "Report sent" in log, "the agent's report didn't get through"
assert "without a good signature" not in log, "the add-on's addresses weren't signed"
rows = json.loads(call(UI + "/api/agents"))["agents"]
assert rows and rows[0].get("version"), rows
print("agent reported:", rows[0]["hostname"], rows[0]["version"])
