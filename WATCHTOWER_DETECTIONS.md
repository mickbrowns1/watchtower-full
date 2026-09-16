# Watchtower Detections — SentinelOne PowerQuery

Detections for the simulator scenarios. **Scope every query by `msgid`** (the
in-band router that survives DataPipeline on every event, text or JSON), then
query the **expanded fields** — every source is pre-parsed in the DataPipeline
Lua stage (`datapipeline/parse_json_by_msgid.lua`), JSON sources via
`json.decode` and text sources via pattern-match, so no detection needs a
PowerQuery `parse` clause at query time. See `WATCHTOWER_PIPELINE.md`.

## Field reference

DataPipeline expands the JSON sources' keys to top-level fields (confirmed from a
live Duo event); Mimecast, Windows, Zscaler, CloudTrail, and Palo Alto expand the
same way. Text sources get a namespaced field table extracted by the Lua stage's
pattern-matchers (e.g. `dns.qname`, `dbaudit.rows`) — `message` still carries the
raw line too, as a fallback. All field names below are grounded in this tenant's
own deployed rules (`data/extracted.json`) where a real rule exists, or in the
generator's own text format otherwise — see `WATCHTOWER_PIPELINE.md`.

| Source (`msgid`) | Fields you query |
|---|---|
| `DUO` (authentication) | `status`, `status_detail`, `unmapped.event_type`, `unmapped.factor`, `email`, `user.name`, `user.groups`, `access_device.ip`, `access_device.location.city`/`.country`, `auth_device.ip`, `application.name` |
| `DUO` (administrator) | `unmapped.eventtype = 'administrator'`, `unmapped.action`, `unmapped.description`, `user.name` |
| `EMAIL` (Mimecast) | `direction`, `status_detail`, `actor.invoked_by`, `event.type`, `email.from`, `email.to`, `email.subject`, `unmapped.category`, `unmapped.action`, `unmapped.taggedMalicious`, `file.type`, `file.name` |
| `WINEVENT` | `winEventLog.id`, `winEventLog.channel`, `winEventLog.description`, `winEventLog.data.event.eventData.targetUserName`, `.serviceName`, `.ticketEncryptionType`, `.ipAddress`, `.logonType`, `.commandLine`, `.subjectUserName`, `Computer` |
| `CLOUDTRAIL` | `eventName`, `eventSource`, `sourceIPAddress`, `recipientAccountId`, `errorCode`, `userIdentity.type`, `userIdentity.arn`, `userIdentity.sessionContext.attributes.mfaAuthenticated`, `requestParameters.*` |
| `PROXY` (Zscaler) | `action`, `app_name`, `risk_details`, `http_request.url.hostname`, `http_request.url.categories`, `malware.name`, `unmapped.event.threatcat` |
| `PANW` (Palo Alto) | `metadata.log_name` (TRAFFIC/THREAT), `activity_name` (GLOBALPROTECT), `app_name`, `action`, `unmapped.action`, `unmapped.sub_type`, `unmapped.threat_category`, `unmapped.url_category`, `unmapped.severity`, `threat.name`, `src_endpoint.ip`, `dst_endpoint.ip`, `dst_endpoint.port`, `status` |
| `S1EDR` | `event.type`, `endpoint.os`, `endpoint.name`, `tgt.process.cmdline`, `tgt.process.name`, `src.process.cmdline`, `src.process.parent.name`, `tgt.file.path`, `registry.keyPath`, `task.path`, `module.path`, `cmdScript.content`, `event.dns.request`, `indicator.name` |
| `DNS` | `dns.clientIp`, `dns.qname`, `dns.qtype`, `dns.resolver`, `dns.port` |
| `DBAUDIT` | `dbaudit.user`, `dbaudit.db`, `dbaudit.class`, `dbaudit.command`, `dbaudit.table`, `dbaudit.statement`, `dbaudit.rows`, `dbaudit.sessionId` |
| `SSHD` | `sshd.result` (accepted/failed), `sshd.method`, `sshd.user`, `sshd.sourceIp`, `sshd.port`, `sshd.invalidUser` |
| `SUDO` | `sudo.user`, `sudo.tty`, `sudo.runAsUser`, `sudo.command` |
| `PAM` | `pam.service`, `pam.action` (opened/closed), `pam.user` |
| `HTTP` | `http.clientIp`, `http.user`, `http.method`, `http.path`, `http.status`, `http.bytes`, `http.userAgent` |
| `CRON` | `cron.user`, `cron.command` |
| `AUDIT` | `audit.srcIp`, `audit.dstIp`, `audit.proto`, `audit.srcPort`, `audit.dstPort` |
| every source | `dataSource.name`, `dataSource.category` — see `WATCHTOWER_PIPELINE.md`'s tagging table |

> **If a JSON-source query returns zero, it's one of two things:**
> 1. **A numeric ID typed as a string** → change `winEventLog.id = 4769` to `winEventLog.id = '4769'`. (Probe: `msgid='WINEVENT' | group n=count() by winEventLog.id`.)
> 2. **Keys nested under a prefix** (e.g. `unmapped.event_type` not `event_type`) → prefix the field paths. (Probe: `msgid='DUO' | group n=count() by status`.)
>
> Both are also dodgeable entirely by matching the kept raw `message`, e.g.
> `msgid='WINEVENT' | filter message contains '"id":4769'` — works regardless of parsed type.

---

## A. Technique detections

### A1 — Spearphish: malicious inbound email delivered without being blocked  ·  T1566
> `unmapped.action` always has a concrete value in this simulator (`none` vs
> `hold`/`block`/`bounce`), never omitted, so "not blocked" is a clean filter
> rather than a check for field absence. No scenario currently scripts an
> undetected *inbound* phish — kept as a generic hunt; fires against ambient
> traffic if `gen_email_threat`'s rare undetected-phish branch rolls.
```
msgid = 'EMAIL' direction = 'inbound' status_detail = 'malicious' unmapped.action contains 'none'
| group threats=count(),
        categories=array_agg_distinct(unmapped.category, 5),
        senders=array_agg_distinct(email.from, 5)
  by email.to
| sort -threats
```

### A1b — Internal impersonation email not blocked  ·  T1656
```
msgid = 'EMAIL' event.type = 'TTP Impersonation Protection' unmapped.taggedMalicious = true unmapped.action contains 'none'
| group hits=count() by email.from, email.to
| sort -hits
```

### A2 — DNS beaconing to a rival-network / C2 domain  ·  T1071.004  *(text, pipeline-parsed)*
> `dns.qname`/`dns.clientIp` are extracted in the DataPipeline Lua stage
> (`parse_json_by_msgid.lua`'s `parseDNS`), not with a PowerQuery `parse`
> clause at query time — see `WATCHTOWER_PIPELINE.md`'s text-parsing section.
```
msgid = 'DNS'
| filter dns.qname contains ('c2.', 'beacon.', 'exfil-relay', 'mastersvault', 'vault-leak', 'federation-trust', 'recon.')
| group queries=count() by dns.clientIp, dns.qname
| filter queries >= 3
| sort -queries
```

### A3 — DNS tunneling exfiltration (long high-entropy labels)  ·  T1048.003  *(text, pipeline-parsed, ambient-only)*
> No scripted scenario currently fires this on demand — `gen_dns_query`'s
> ambient tunneling branch (15% of DNS traffic) is the only source.
```
msgid = 'DNS'
| filter dns.qname matches '[a-z2-7]{20,}\\.[a-z2-7]{6,}\\.exfil'
| group lookups=count(), sample=any(dns.qname) by dns.clientIp
| sort -lookups
```

### A4 — Kerberoasting (RC4 service ticket)  ·  T1558.003
```
msgid = 'WINEVENT' winEventLog.id = 4769 winEventLog.data.event.eventData.ticketEncryptionType = '0x17'
| group tickets=count(), services=array_agg_distinct(winEventLog.data.event.eventData.serviceName, 10)
  by winEventLog.data.event.eventData.targetUserName
| sort -tickets
```

### A5 — Mass database extraction  ·  T1213  *(text, pipeline-parsed)*
> `dbaudit.*` is extracted in the DataPipeline Lua stage (`parseDBAUDIT`),
> not with PowerQuery `parse` clauses at query time.
```
msgid = 'DBAUDIT'
| filter dbaudit.command = 'SELECT' && dbaudit.rows >= 1000
| group big_reads=count(), tables=array_agg_distinct(dbaudit.table, 10) by dbaudit.user
| sort -big_reads
```

### A6a — Password spray (one source IP, many accounts failing)  ·  T1110.003  *(ambient-only)*
```
msgid = 'WINEVENT' winEventLog.id = 4625
| group fails=count() by winEventLog.data.event.eventData.ipAddress, winEventLog.data.event.eventData.targetUserName
| group distinct_users=count(), total_fails=sum(fails) by winEventLog.data.event.eventData.ipAddress
| filter distinct_users >= 3
| sort -total_fails
```

### A6b — Credential dumping via mimikatz, Windows Event view  ·  T1003  *(ambient-only — see E1 for the scripted EDR view)*
```
msgid = 'WINEVENT' winEventLog.id = 4688
| filter winEventLog.data.event.eventData.commandLine contains 'mimikatz' || winEventLog.data.event.eventData.commandLine contains 'sekurlsa'
| group hits=count(), commands=array_agg_distinct(winEventLog.data.event.eventData.commandLine, 5)
  by Computer, winEventLog.data.event.eventData.subjectUserName
| sort -hits
```

### A7 — Login/financial-transaction burst to one app  ·  T1078  *(Multiverse Travel Anomaly)*
```
msgid = 'DUO' status = 'success'
| group approvals=count() by user.name, application.name, city=access_device.location.city
| filter approvals >= 3
| sort -approvals
```

### A8 — Credential correlation across many hosts, one source IP  ·  T1078  *(X-Men Solo Ops Sprawl)*
```
msgid = 'SSHD' sshd.result = 'accepted'
| group hosts=array_agg_distinct(host, 10), n_hosts=count_distinct(host) by sshd.sourceIp
| filter n_hosts >= 3
| sort -n_hosts
```

### A9 — Cross-application credential rotation (denied on one app, approved on another)  ·  T1098  *(HYDRA Defection)*
```
| join
    (msgid = 'DUO' status = 'denied' | group 1 by user=user.name, denied_app=application.name),
    (msgid = 'DUO' status = 'success' | group 1 by user=user.name, approved_app=application.name)
  on user
| filter denied_app != approved_app
```

---

## B. Cross-source correlations

### B1 — Impossible travel: one identity, successful MFA from 2+ cities  ·  T1078
```
msgid = 'DUO' status = 'success'
| group logins=count() by user.name, city=access_device.location.city
| group distinct_cities=count(), cities=array_agg_distinct(city, 10) by user.name
| filter distinct_cities >= 2
| sort -distinct_cities
```

### B2 — Impersonation/phish → suspicious auth (same mailbox)  ·  T1566 → T1078  *(no current scripted trigger)*
> Joins on `email`. Works because Duo's `email` is the canonical corporate
> identity (matches Mimecast `email.to`).
```
| join
    (msgid = 'EMAIL'
       | group 1 by email=email.to),
    (msgid = 'DUO'
       | filter status = 'fraud' || status_detail = 'anomalous_push'
       | group bad_auths=count() by email)
  on email
```

### B3 — Rival-faction beacon + fraud from the same foreign IP  *(no current scripted trigger — kept generic)*
```
| join
    (msgid = 'PANW' unmapped.sub_type = 'vulnerability' threat.name = 'Rival Faction Network Beacon Detected'
       | group beacons=count() by ip=src_endpoint.ip),
    (msgid = 'DUO' status = 'fraud'
       | group frauds=count() by ip=access_device.ip)
  on ip
```

### B4 — Exfil chain: large DB read → large outbound proxy transfer, same user  ·  T1213 → T1041  *(Nexus Registry Mass Pull)*
> `bytes` is a real numeric field on the Zscaler event (not a string to regex-match).
```
| join
    (msgid = 'DBAUDIT'
       | filter dbaudit.rows >= 1000
       | group reads=count() by dbuser=dbaudit.user),
    (msgid = 'PROXY'
       | filter action = 'Allowed' && bytes >= 1000000
       | group egress=count(), hosts=array_agg_distinct(http_request.url.hostname, 5) by user=user.name)
  on dbuser = user
```

---

## C. Named-signature detections  *(PANW Threat log, `unmapped.sub_type = 'vulnerability'`)*

Each of these is a custom/fictional IPS signature name emitted only inside a
scripted scenario (`PANW_NARRATIVE_SIGNATURES` in `generate_logs.py`) — never
by ambient traffic, so any hit is scenario fire, not noise.

### C1 — Cosmic cube vault exfiltration signature  *(Cosmic Cube Heist)*
```
msgid = 'PANW' unmapped.sub_type = 'vulnerability' threat.name = 'Cosmic Cube Vault Exfiltration Signature'
| group hits=count(), dsts=array_agg_distinct(dst_endpoint.ip, 5) by src=src_endpoint.ip
| sort -hits
```

### C2 — Rival-faction network beacon signature  *(Avengers/X-Men Beacon, Gotham Rogue vs. Wakanda Rivalry)*
```
msgid = 'PANW' unmapped.sub_type = 'vulnerability' threat.name = 'Rival Faction Network Beacon Detected'
| group hits=count(), dsts=array_agg_distinct(dst_endpoint.ip, 5) by src=src_endpoint.ip
| sort -hits
```

### C3 — Insider leak / defector signature  *(Skrull Infiltration, S.H.I.E.L.D. Internal Watchdog)*
```
msgid = 'PANW' unmapped.sub_type = 'vulnerability' threat.name = 'Insider Leak Pattern - Defector Signature'
| group hits=count() by src=src_endpoint.ip, dst=dst_endpoint.ip
| sort -hits
```

### C4 — Solo-deal credential sprawl signature  *(X-Men Solo Ops Sprawl)*
```
msgid = 'PANW' unmapped.sub_type = 'vulnerability' threat.name = 'Solo-Deal Credential Sprawl Signature'
| group hits=count() by src=src_endpoint.ip
| sort -hits
```

### C5 — Excessive trust-relationship signature  *(Asgard/Avengers Trust Pact)*
```
msgid = 'PANW' unmapped.sub_type = 'vulnerability' threat.name = 'Excessive Trust-Relationship Signature'
| group hits=count() by src=src_endpoint.ip, dst=dst_endpoint.ip
| sort -hits
```

### C6 — Independent infra recon signature  *(Wakanda Infra Standup)*
```
msgid = 'PANW' unmapped.sub_type = 'vulnerability' threat.name = 'Independent Infra Recon Signature'
| group hits=count() by src=src_endpoint.ip
| sort -hits
```

### C7 — Access-revocation / credential-rotation admin commands  *(Civil War Access Revocation, HYDRA Defection)*
```
msgid = 'SUDO'
| filter sudo.command contains 'revoke_access.sh' || sudo.command contains 'rotate_creds.py'
| group hits=count(), commands=array_agg_distinct(sudo.command, 5) by host
| sort -hits
```

---

## D. AWS (CloudTrail) detections

The simulated AWS org is intentionally hardened by default (MFA-enforced
AssumedRole sessions, no long-lived keys, encrypted S3, trusted-IP-only
egress) — see `generate_logs.py`'s `AWS_*` constants. Every query below
should return **zero** hits against ambient traffic; a hit means a scripted
scenario actually fired (or something real happened).

### D1 — Root account usage  ·  T1078.004  *(no current scripted trigger — kept as a zero-expected guardrail)*
```
msgid = 'CLOUDTRAIL' userIdentity.type = 'Root'
| group actions=count(), events=array_agg_distinct(eventName, 10) by recipientAccountId
| sort -actions
```

### D2 — CloudTrail logging disabled or deleted  ·  T1562.008  *(no current scripted trigger — kept as a zero-expected guardrail)*
```
msgid = 'CLOUDTRAIL' (eventName = 'StopLogging' || eventName = 'DeleteTrail' || eventName = 'UpdateTrail')
| group actions=count(), events=array_agg_distinct(eventName, 10) by recipientAccountId, sourceIPAddress
| sort -actions
```

### D3 — IAM privilege escalation via policy attachment  ·  T1098.003  *(Oscorp Shell Entity Privesc)*
```
msgid = 'CLOUDTRAIL' (eventName = 'AttachUserPolicy' || eventName = 'AttachRolePolicy' || eventName = 'PutRolePolicy' || eventName = 'PutUserPolicy')
| group actions=count(), events=array_agg_distinct(eventName, 10) by userIdentity.arn
| sort -actions
```

### D4 — Console login without MFA  ·  T1078  *(no current scripted trigger — kept as a zero-expected guardrail)*
```
msgid = 'CLOUDTRAIL' eventName = 'ConsoleLogin' userIdentity.sessionContext.attributes.mfaAuthenticated = 'false'
| group logins=count() by userIdentity.arn, sourceIPAddress
| sort -logins
```

---

## E. SentinelOne EDR detections

Field names and the `event.type` set here are grounded directly in this
tenant's own deployed detection library (746 real `SentinelOne`-sourced
rules in `data/extracted.json`) rather than guessed — `event.type` is
overwhelmingly `Process Creation` in practice. Ambient traffic is signed,
known-publisher, ordinary parent/child process trees (see `EDR_BENIGN_PROCS`
in `generate_logs.py`); credential dumping only appears in a dedicated
scenario, and reverse-shell/persistence event types are not currently
emitted by any scenario (kept below as zero-expected guardrails).

Unlike every other source in this simulator, `S1EDR` events bypass
syslog-ng/DataPipeline and are ingested directly into SDL — see
[WATCHTOWER_PIPELINE.md](WATCHTOWER_PIPELINE.md#sentinelone-edr-direct-to-sdl-not-datapipeline).
No console pipeline changes are needed for these queries to work.

### E1 — Credential dumping via mimikatz  ·  T1003.001  *(Accords Breach Lateral Movement)*
```
dataSource.name = 'SentinelOne' event.type = 'Process Creation' tgt.process.cmdline contains 'sekurlsa::logonpasswords'
| group hits=count(), hosts=array_agg_distinct(endpoint.name, 5) by tgt.process.user
| sort -hits
```

### E2 — Reverse shell via netcat  ·  T1059  *(no current scripted trigger — kept as a zero-expected guardrail)*
```
dataSource.name = 'SentinelOne' event.type = 'Process Creation' tgt.process.name = 'nc' tgt.process.cmdline contains ' -e'
| group hits=count(), targets=array_agg_distinct(tgt.process.cmdline, 5) by endpoint.name
| sort -hits
```

### E3 — Suspicious scheduled task registration  ·  T1053.005  *(no current scripted trigger — kept as a zero-expected guardrail)*
```
dataSource.name = 'SentinelOne' event.type = 'Task Register'
| group hits=count(), tasks=array_agg_distinct(task.path, 5) by src.process.user
| sort -hits
```

### E4 — DNS resolution to known exfil infrastructure (EDR view)  ·  T1071.004  *(no current scripted trigger — kept as a zero-expected guardrail)*
```
dataSource.name = 'SentinelOne' event.type = 'DNS Resolved' event.dns.request contains ('exfil-relay', 'mastersvault', 'c2.eastcoast', 'c2.westcoast')
| group hits=count() by endpoint.name, event.dns.request
| sort -hits
```

---

## F. New-account / provisioning detections

### F1 — First login immediately following account provisioning  ·  T1078  *(New Recruit Onboarding, Kyle Rayner Onboarding)*
> Correlates a Windows "account created" event (4720) with a Duo success for
> the same identity — legitimate onboarding produces exactly this pair; an
> attacker-created account logging in unusually fast is the same signal.
```
| join
    (msgid = 'WINEVENT' winEventLog.id = 4720 | group provisioned_n=count() by user=winEventLog.data.event.eventData.targetUserName),
    (msgid = 'DUO' status = 'success' | group logins=count() by user=user.name)
  on user
```

---

## G. Informational / baseline-tracking detections

### G1 — Single restricted-asset access (informational)  ·  *(Infinity Vault Access)*
> Not a threat signal by itself — this tracks legitimate, rare, one-off reads
> of assets flagged as uniquely restricted (e.g. a single-copy release under
> unusual contract terms). Severity Info; useful for an audit trail, not
> paging anyone.
```
msgid = 'CLOUDTRAIL' eventName = 'GetObject' requestParameters.key contains 'singular/'
| group hits=count(), keys=array_agg_distinct(requestParameters.key, 5) by userIdentity.arn
| sort -hits
```

---

## H. Cross-label scope detections

### H1 — Auditor account touching 3+ factions' power-registry schemas in one session  ·  T1078  *(Multiverse Nexus Audit)*
> Two-stage `group` (not `count_distinct`) — see `WATCHTOWER_PIPELINE.md`'s
> note on the scheduled-rule validator rejecting `count_distinct` inline.
```
msgid = 'DBAUDIT'
| filter dbaudit.table = 'public.power_registry' && dbaudit.command = 'SELECT'
| group n=count() by dbaudit.user, dbaudit.statement
| group distinct_reads=count(), statements=array_agg_distinct(dbaudit.statement, 5) by dbaudit.user
| filter distinct_reads >= 3
| sort -distinct_reads
```

---

## Promoting to detection rules

To turn a hunt into a STAR / Custom Detection / PowerQuery Alert:
- **Must include a `group` command** — the alert engine thresholds on its count.
  A body that ends in `columns … | limit` (hunt style) is rejected with
  *"This PowerQuery cannot be used in an alert: must include a 'group' command."*
  All detections here end in `group … | sort`, so they're alert-ready.
- Keep intermediate and output ≤ **1,000 rows / 1 MB**; no `nolimit`, `compare`, `transpose`.
- Emit **one row per finding** with stable columns the engine maps to alert fields
  (e.g. `timestamp`, `host`, and the entity — `email` / `src_endpoint.ip` / `dbuser`).
- Keep the initial filter tight (`msgid = '…'` is exactly that) — it gates cost.
- Tune the thresholds (`queries >= 3`, `distinct_users >= 3`, `rows >= 1000`,
  `distinct_cities >= 2`) to your baseline once you see normal volume.

## Firing detections on demand

Ambient scenarios are rare (`SCENARIO_CHANCE=0.02`), so to test/demo a
detection without waiting, fire its scenario straight into syslog-ng:

```bash
docker exec watchtower-log-generator python3 fire_scenario.py                     # list all scenarios
docker exec watchtower-log-generator python3 fire_scenario.py nexus_registry_pull # fire one (partial name OK)
docker exec watchtower-log-generator python3 fire_scenario.py all                 # fire every scenario once
```

Scenario (`fire_scenario.py` name, i.e. the function name without its `sc_`
prefix) → detection it lights up:

| Fire this scenario | Triggers |
|---|---|
| `cosmic_cube_heist_thanos` | **C1** (cosmic-cube vault exfil signature) |
| `oscorp_privesc` | **D3** (IAM privesc via policy attachment) |
| `nexus_registry_pull` | **A5** (mass DB read), **B4** (DB read → proxy exfil, same user) |
| `skrull_infiltration_talos` | **A1b** (internal impersonation not blocked), **A5** (1,204-row DB read) |
| `avengers_xmen_beacon` | **A2** (DNS beaconing), **C2** (rival-faction beacon signature) |
| `multiverse_travel_anomaly` | **A7** (login/app burst), **B1** (impossible travel — pair with any other-city scenario) |
| `accords_breach_lateral` | **A4** (kerberoasting), **E1** (EDR mimikatz) |
| `xmen_solo_ops_sprawl` | **A8** (SSH fan-out, one IP → 3+ hosts), **C4** (solo-op sprawl signature) |
| `hydra_defection` | **A9** (cross-app credential rotation), **C7** (rotate_creds.py) |
| `civil_war_access_revocation` | **C7** (revoke_access.sh) |
| `green_lantern_recharge_anomaly` | **F1**-style credential-lifecycle + new-host login join |
| `jleague_financial_audit` | **A5** (1,847-row DB read) |
| `wakanda_infra_standup` | **C6** (independent cell recon signature) |
| `gotham_wakanda_rivalry` | **A2** (DNS beaconing), **C2** (rival-faction beacon signature) |
| `shield_internal_watchdog` | **A1b** (internal impersonation not blocked), **C3** (insider/rogue-agent signature) |
| `asgard_avengers_trust_pact` | **C5** (excessive alliance trust signature) |
| `new_recruit_onboarding` | **F1** (first login after provisioning) |
| `infinity_vault_access` | **G1** (single restricted-asset access, informational) |
| `banner_legal_hold` | **A5** (1,847-row DB read — legitimate e-discovery, same signal as an illegitimate mass extraction; SOC context is what tells them apart) |
| `shield_shutdown` | **C7** (revoke_access.sh) |
| `kyle_rayner_onboarding` | **F1** (first login after provisioning) |
| `squad_doom_rivalry` | **A2** (DNS beaconing), **C2** (rival-faction beacon signature) |
| `multiverse_nexus_audit` | **H1** (cross-faction auditor scope creep) |
| `hawkeye_shield_dispute` | intentionally below every threshold (12-row DB read) — illustrates why A5's `rows >= 1000` cutoff needs tuning to your real baseline, not a detection gap |
| (any 2+ scenarios with Duo logins in different cities) | **B1** (impossible travel) |

**Zero-expected guardrails with no current scripted trigger** — these
detections stay valid and should return zero hits against ambient traffic;
they exist so a real incident (or a future scenario) has something to fire:
**A1** (undetected inbound phish), **A3** (DNS tunneling — ambient-only),
**A6a** (password spray — ambient-only), **A6b** (WinEvent-view mimikatz —
ambient-only, see E1 for the scripted EDR view), **B2** (phish→auth),
**B3** (beacon+fraud), **D1/D2/D4** (AWS root usage / logging disabled /
MFA-less login), **E2/E3/E4** (reverse shell / scheduled task / EDR-view DNS
exfil).

Then run the detection over the last few minutes and confirm the hits.
