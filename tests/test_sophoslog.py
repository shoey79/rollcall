"""Sophos firewall mail and attack events from its syslog. Made-up values only."""
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rollcall" / "app"))

import sophoslog  # noqa: E402

# SFOS v18 style
SPAM = ('device="SFW" date=2026-11-20 time=09:15:02 timezone="GMT" device_name="SFW01" log_id=041101618034 '
        'log_type="Anti-Spam" log_component="SMTP" log_subtype="Spam" status="" priority=Information '
        'from_email_address="sender@example.com" to_email_address="user@contoso.local" email_subject="You have \\"won\\"" '
        'mailid="abc123" mailsize=20480 spamaction="Quarantine" reason="Inbound email detected as Spam" '
        'src_domainname="mail.example.com" src_ip=203.0.113.25 src_country_code=USA dst_ip=192.168.1.10 '
        'protocol="TCP" src_port=51515 dst_port=25 quarantine_reason="Spam"')
VIRUS = ('device_name="SFW" timestamp="2026-11-20T10:01:00+0000" log_type="Anti-Virus" log_component="SMTP" '
         'log_subtype="Virus" from_email_address="other@example.net" to_email_address="sales@contoso.local" '
         'subject="Invoice" virus="EICAR-AV-Test" spam_action="Reject" mail_size=1200 src_ip=198.51.100.7 src_country="GBR"')
# SFOS v19.5+ style IPS
IPS = ('device_name="SFW" timestamp="2026-11-20T11:00:00+0000" log_type="IDP" log_component="Signatures" '
       'log_subtype="Drop" severity="Warning" fw_rule_id="5" signature_id=58724 message="SERVER-WEBAPP path traversal attempt" '
       'classification="Web Application Attack" rule_priority=1 src_ip="198.51.100.40" src_country="NLD" '
       'dst_ip="192.168.1.20" dst_port=443 protocol="TCP" victim="Server"')
WAF = ('device_name="SFW" log_type="WAF" log_component="Web Application Firewall" log_subtype="Denied" '
       'reason="Cross-site scripting attack" src_ip=203.0.113.9 url="https://server.example.local/login" action="Blocked"')
TRAFFIC = ('device_name="SFW" log_type="Firewall" log_component="Firewall Rule" log_subtype="Allowed" '
           'src_ip=192.168.1.5 dst_ip=203.0.113.1')
SMTP_OTHER = 'device_name="SFW" log_type="Anti-Spam" log_component="POP3" log_subtype="Clean"'


def test_mail_fields_both_versions():
    kind, d = sophoslog.event(SPAM)
    assert kind == "mail"
    assert d["sender"] == "sender@example.com" and d["recipient"] == "user@contoso.local"
    assert d["subject"] == 'You have "won"' and d["action"] == "Quarantine" and d["reason"] == "Spam"
    assert d["size"] == "20480" and d["src_host"] == "mail.example.com"
    assert d["src_ip"] == "203.0.113.25" and d["src_country"] == "USA"
    kind, d = sophoslog.event(VIRUS)
    assert kind == "mail" and d["kind"] == "Anti-Virus"
    assert d["subject"] == "Invoice" and d["reason"] == "EICAR-AV-Test" and d["action"] == "Reject" and d["size"] == "1200"


def test_attacks():
    kind, d = sophoslog.event(IPS)
    assert kind == "attack" and d["kind"] == "IPS"
    assert d["message"] == "SERVER-WEBAPP path traversal attempt" and d["classification"] == "Web Application Attack"
    assert d["priority"] == "1" and d["fw_rule"] == "5" and d["action"] == "Drop"
    assert (d["src_ip"], d["src_country"], d["dst_ip"], d["dst_port"], d["victim"]) == ("198.51.100.40", "NLD", "192.168.1.20", "443", "Server")
    kind, d = sophoslog.event(WAF)
    assert kind == "attack" and d["kind"] == "WAF" and d["message"] == "Cross-site scripting attack"
    assert d["url"] == "https://server.example.local/login" and d["action"] == "Denied"


def test_everything_else_is_left_alone():
    for m in (TRAFFIC, SMTP_OTHER, "", "plain message", "kernel: log_type=something"):
        assert sophoslog.event(m) is None


def test_store_counts_filter_and_prune():
    db = sqlite3.connect(":memory:")
    s = sophoslog.EventStore(db)
    now = time.time()
    assert s.add("fw", now - 3 * 86400, SPAM) and s.add("fw", now - 60, SPAM) and s.add("fw", now - 30, VIRUS)
    assert s.add("fw", now - 10, IPS) and not s.add("fw", now, TRAFFIC)
    assert s.has("fw") == {"mail": 3, "attack": 1}
    got = s.query("fw", "mail", now=now)
    assert got["total"] == 3 and got["rows"][0]["sender"] == "other@example.net"
    assert got["top"][0] == ("sender@example.com", 2)
    assert sum(n for _, n in got["per_day"]) == 3
    assert s.query("fw", "mail", q="invoice", now=now)["total"] == 1
    assert s.query("fw", "mail", since=now - 86400, now=now)["total"] == 2
    a = s.query("fw", "attack", now=now)
    assert a["top"][0] == ("198.51.100.40 (NLD)", 1) and a["top2"][0][0].startswith("SERVER-WEBAPP")
    s.prune(now - 86400)
    assert s.has("fw") == {"mail": 2, "attack": 1}
    s.clear("fw")
    assert s.has("fw") == {}
