#!/usr/bin/env python3
"""
Send one representative test event per data source (msgid) -- for verifying
the whole pipeline end to end, source by source, without waiting for ambient
traffic. Useful right after standing up the stack, or after pointing it at a
new tenant (see Watchtower's Environments tool), to confirm every source is
actually reaching SDL before you rely on ambient traffic or scenarios.

Run inside the generator container:
  docker exec strongisland-log-generator python3 fire_sources.py

See STRONGISLAND_PIPELINE.md's tagging table for the full msgid -> dataSource
mapping. SentinelOne EDR (msgid S1EDR) bypasses sgcia entirely and posts
straight to SDL -- see STRONGISLAND_PIPELINE.md's "direct-to-SDL" section.
"""
import os
import socket
import generate_logs as g

HOST = os.getenv("SYSLOG_HOST", "sgcia")
PORT = int(os.getenv("SYSLOG_PORT", "601"))

# One representative generator per msgid/data source. Where a msgid has
# multiple generators (PANW, DUO), one representative is enough -- this is a
# per-source pipeline check, not a scenario.
SOURCES = [
    ("PANW", "Palo Alto Networks Firewall", g.gen_panw_traffic),
    ("SSHD", "Linux Audit (sshd)", g.gen_ssh_auth),
    ("SUDO", "Linux Audit (sudo)", g.gen_sudo_event),
    ("PAM", "Linux Audit (PAM)", g.gen_pam_session),
    ("HTTP", "Apache HTTP Server", g.gen_apache_access),
    ("CRON", "Linux Audit (cron)", g.gen_cron_job),
    ("AUDIT", "Linux Audit (kernel/UFW)", g.gen_kernel_audit),
    ("DUO", "Cisco Duo", g.gen_duo_auth),
    ("PROXY", "Zscaler Internet Access", g.gen_web_proxy),
    ("DNS", "ISC BIND", g.gen_dns_query),
    ("EMAIL", "Mimecast", g.gen_email_threat),
    ("DBAUDIT", "PostgreSQL", g.gen_db_audit),
    ("WINEVENT", "Windows Event Logs", g.gen_win_event),
    ("CLOUDTRAIL", "AWS CloudTrail", g.gen_cloudtrail_event),
]


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    for msgid, label, fn in SOURCES:
        line = fn()
        sock.sendall(line.encode("utf-8"))
        print(f"  sent  msgid={msgid:10} {label}")
    sock.close()
    print(f"\n{len(SOURCES)} events sent to {HOST}:{PORT} via sgcia.")

    print("\nmsgid=S1EDR (SentinelOne EDR) bypasses sgcia -- posting directly to SDL...")
    g.gen_s1_edr_event()
    print("  sent  msgid=S1EDR    SentinelOne (direct to SDL via addEvents)")

    print(f"\n{len(SOURCES) + 1} sources total. Check SDL for each msgid (or dataSource.name) "
          f"over the last few minutes to confirm ingestion.")


if __name__ == "__main__":
    main()
