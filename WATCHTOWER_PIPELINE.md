# DataPipeline Integration Notes

Hard-won rules for how the Watchtower Log Simulator's events flow into
SentinelOne DataPipeline and the Singularity Data Lake. Read this before
wiring up the DataPipeline pipeline — most of these were discovered the hard
way (carried over unchanged from the FoundStone/Treadstone build this project
was forked from; only the *content* is Watchtower-themed, the pipeline
mechanics are identical).

**The forwarder is [sgcia](https://github.com/mickbrowns1/securitygingercia)**
(Security Ginger Collect It All — Mick's own OpenTelemetry Collector fork),
**not syslog-ng** — see [sgcia's field-mapping mechanics](#sgcias-field-mapping-mechanics)
below for why that swap needed zero changes here or in
[`WATCHTOWER_DETECTIONS.md`](WATCHTOWER_DETECTIONS.md): `sgcia/config.yaml`
reproduces syslog-ng.conf's exact HEC body shape, field name for field name.

**This covers every source except SentinelOne EDR** (`msgid = S1EDR`), which
deliberately bypasses DataPipeline entirely — see
[SentinelOne EDR: direct-to-SDL, not DataPipeline](#sentinelone-edr-direct-to-sdl-not-datapipeline)
at the bottom.

## Flow

```
log-generator ──RFC 5424 / RFC 6587 octet-counting──▶ sgcia ──HEC (one POST/event)──▶ DataPipeline ──▶ SDL
```

## What sgcia sends (HEC body)

A minimal HEC envelope per event (see [`sgcia/config.yaml`](sgcia/config.yaml)):

```json
{ "time": <epoch>, "host": "...", "event": "<raw log line>",
  "fields": { "sourcetype": "...", "datasource": "...", "msgid": "...",
              "agent": "...", "tags": "...", "syslog_severity": "...", "syslog_facility": "..." } }
```

`event` is the raw log line — **plain text** for most sources, a **JSON string**
for the JSON sources (Duo, Mimecast, CloudTrail, Zscaler, Palo Alto), and
genuine **Windows Event Log XML** for Windows Security events (see
"Windows Event Logs: real XML, not JSON" below).

## How DataPipeline reshapes it (verified on the wire)

- `fields.*` are **flattened to top-level** fields: `msgid`, `datasource`, `sourcetype`, `agent`, `tags`, `syslog_severity`, `syslog_facility`.
- `event` → **`message`**.
- `time` → normalized into the canonical **`timestamp`** (this is the field "rewrite" you see in the pipeline UI — expected, not a bug).

**`msgid` is the routing key.** It's set explicitly per source and survives intact, so use it to scope everything (queries *and* pipeline conditionals):

| `msgid` | source | `message` is |
|---|---|---|
| `DUO`, `EMAIL`, `CLOUDTRAIL`, `PROXY`, `PANW` | Cisco Duo, Mimecast, AWS CloudTrail, Zscaler Internet Access, Palo Alto Networks Firewall | **JSON** |
| `WINEVENT` | Windows Security | genuine **Windows Event Log XML** (`<Event xmlns="...">`) |
| `SSHD`, `SUDO`, `PAM`, `HTTP`, `CRON`, `AUDIT`, `DNS`, `DBAUDIT` | everything else | **plain text** |

## Pipeline requirements (DataPipeline side)

### 1. Keep `message` — don't drop it
The text sources carry all their content in `message`. Dropping it empties them in
SDL (and the message-based detections stop working). Keep `message` for every source.

### 2. Gate parse-json — don't run it on text sources
A parse-json applied to the whole feed throws
`unable to parse json: expected value at line 1 column 1` on every text source
(their `message` starts with `client @…`, `Accepted publickey…`, etc., not `{`). Run it **only** on JSON:

```
parse_json(message)  WHEN  msgid in ('DUO','EMAIL','CLOUDTRAIL','PROXY','PANW')
# or, source-agnostic (auto-handles future JSON sources):
parse_json(message)  WHEN  message starts_with '{'
```

**Don't add `WINEVENT` to this list** — its `message` is XML (`<Event ...`),
not JSON; `parse_json` throws on it same as any text source. It's handled
by `parse_json_by_msgid.lua`'s dedicated `parseWINEVENT` string-pattern
parser instead (see "Windows Event Logs: real XML, not JSON" below).

### 3. Avoid root-merge field collisions
DataPipeline merges the parsed JSON onto the document root, so any JSON key that
matches an envelope/reserved key collides (type conflicts, duplicate keys).

- Reserved/envelope keys to avoid in any JSON payload root: `timestamp`, `time`, `host`, `message`, `datasource`, `msgid`, `sourcetype`, `tags`, `agent`, `syslog_facility`, `syslog_severity`, `dataPipeline`.
- Already handled in the generator: Duo's native epoch field was renamed `timestamp` → **`auth_timestamp`** to dodge the `timestamp` collision. Email and Windows payloads are already collision-free.
- If you prefer, parse JSON into a **single shared subtree** (e.g. `event`) instead of root — one uniform rule, no per-source branching, and collisions become impossible (`event.timestamp` ≠ envelope `timestamp`). Detections would then use `event.result`, `event.EventID`, etc.

## What the repo already handles (sgcia side — don't re-fix these)

- **No batch coalescing:** sgcia's splunkhecexporter posts one event per request — every syslog line lands as its own distinct DataPipeline event, same as before.
- **Octet-counting framing:** generator → sgcia uses RFC 6587 octet counts with **no trailing delimiter** (a trailing `\n` would desync the strict framing the same way it did against syslog-ng's `syslog()` source).
- **Reliability:** `sending_queue` (in-memory, 1000 events, 10 consumers) + `retry_on_failure` (exponential backoff, 500ms–30s) absorb DataPipeline outages — **this is the one real behavioral difference from syslog-ng**, which buffered to a 256 MB on-disk queue. sgcia's queue is in-memory only, so a sustained outage that outlasts the queue (or a container restart mid-outage) drops events rather than replaying them on reconnect. Fine for this simulator (synthetic, replayable-on-demand data); worth knowing if you ever pointed sgcia at a real production source.

## sgcia's own web UI

sgcia ships its own health/config/topology/log-viewer web UI, served by the
`statuscfg` extension at **port 7801** (published in `docker-compose.yml` —
open `http://localhost:7801/` directly, nothing to do with Watchtower's
dashboard on 8092). Three tabs:

- **Health** — uptime, per-pipeline/receiver/exporter event counts (scraped
  from the collector's own Prometheus metrics — see `service.telemetry.metrics`
  in `sgcia/config.yaml`, which must be `level: basic` with a `readers` block
  or this whole tab 503s).
- **Logs** — a live-tailing viewer over the most recent 500 events (search,
  severity filter, click-a-badge-to-correlate). This tab is fed by a
  **second exporter**, `logbuffer`, wired into the `logs/syslog` pipeline
  alongside `splunk_hec/datapipeline` — it POSTs every record to statuscfg's
  own loopback `/internal/logs`, which keeps the ring buffer. Without that
  exporter in the pipeline's `exporters:` list, this tab stays permanently
  empty (Health/Topology still work fine — they don't depend on it).
- **Topology** — a live sankey of receivers → pipelines → exporters.

`logbuffer` is a small collector-native exporter local to the sgcia repo
(`otelcol/exporters/logbufferexporter/`, already in `builder-config.yaml`,
no rebuild needed to enable it) — plain JSON-over-HTTP to `statuscfg`, no
Go-level coupling between the two.

## sgcia's field-mapping mechanics

`sgcia/config.yaml` runs the same RFC 5424 payload through a `syslog`
receiver (stanza's parser under the hood), then an inline **operators**
chain that reproduces syslog-ng.conf's rewrite rules exactly:

1. **`msgid` → `sourcetype`** — a `router` operator with the same 14 routes
   + fallback syslog-ng.conf had, each branch explicitly outputting to a
   shared `noop` operator (`converge`). That explicit output matters: stanza's
   default behavior is "each operator without one auto-wires to the *next*
   operator in the list," so without it every branch falls through into
   whichever `add`-sourcetype operator is listed last, and that one always
   wins regardless of which route actually matched — a real bug hit and
   fixed while building this, not a hypothetical.
2. **Attribute renames** — stanza's parser names things `msg_id`/`appname`/
   `facility`; three `move` operators rename them to what
   `parse_json_by_msgid.lua` and every detection actually expect at the top
   level: `msgid`/`datasource`/`syslog_facility`.
3. **Static enrichment** — two `add` operators set `tags`/`agent`, matching
   syslog-ng.conf's `r_add_tags` rewrite rule (`agent` is now
   `sgcia-forwarder` instead of `syslog-ng-forwarder` — the only field
   *value* that changed, and nothing reads it for routing).
4. **Body** — a final `move` puts the actual message payload (not the full
   raw RFC 5424 line) into the record body, so `event` in the HEC body is
   the JSON/text payload alone, same as syslog-ng's `event=${MESSAGE}`.

Two fields are an intentional, documented approximation rather than a
byte-for-byte match — **neither is read by any current detection or by the
Lua stage**, confirmed by grep before making this call:

- **`fields.syslog_severity`**: this collector build has no
  transform/OTTL processor (`otelcol/builder-config.yaml` only pulls in
  receivers/exporters/extensions), so the exact 0–7 syslog severity number
  can't be recomputed inline from `priority`. Ships the parser's *native*
  severity instead — `fields.severity_text` ("info", "warning", ...) and
  `fields.severity_number` (OTel's own scale). `fields.syslog_facility` is
  still exact.
- **`HEC_INDEX`**: syslog-ng.conf's own destination body never actually
  referenced `${HEC_INDEX}` either — grep it, it's not there — so no index
  was ever being sent even before this swap. `sgcia/config.yaml` preserves
  that (non-)behavior rather than "fixing" a pre-existing gap as part of an
  unrelated change.

Verified empirically against a live mock HEC endpoint before this ever
touched `docker-compose.yml`: fired real PANW/SSHD/DUO/unknown-msgid test
events through a locally-built `sgcia-otelcol` binary and inspected the
decompressed HEC POST bodies field by field.

## dataSource.name / dataSource.category tagging

Every source gets `dataSource.name` (grounded in this tenant's own deployed
rule library where a real value exists -- see `data/extracted.json`) and
`dataSource.category = "security"` (not used by any deployed rule as a
filter, but drives SDL's own data-view bucketing).

This is applied **centrally in the Lua processor stage**
(`datapipeline/parse_json_by_msgid.lua`'s `DATASOURCE_BY_MSGID` lookup),
not in the Python generator, and applies to *every* msgid -- JSON or plain
text -- before the JSON-only gating happens. This was a deliberate choice
over setting it via the forwarder's `fields.*` HEC mechanism: that would create
the field at the envelope level for every event (including JSON ones,
which build their own nested `dataSource` structure via `parse_json`),
risking a duplicate/conflicting `dataSource.name` value between the
envelope and the parsed JSON. Centralizing it in the one Lua stage that
already runs last avoids that risk entirely, and means adding a new source
only requires one line in `DATASOURCE_BY_MSGID`.

SentinelOne EDR is the exception (see below) -- it sets `dataSource`
directly in the Python event builder, since it bypasses this Lua stage
(and DataPipeline) entirely.

| `msgid` | `dataSource.name` | Real rule match? |
|---|---|---|
| `S1EDR` | `SentinelOne` | Yes (973 rules) -- name and field shape both match |
| `CLOUDTRAIL` | `CloudTrail` | Yes (435 rules) -- name and field shape both match |
| `WINEVENT` | `Windows Event Logs` | Yes (59 rules) -- name and field shape both match (nested `winEventLog.*`) |
| `DUO` | `Cisco Duo` | Yes (24 rules) -- name and field shape both match (`status`/`status_detail`/`unmapped.*`) |
| `PANW` | `Palo Alto Networks Firewall` | Yes (16 rules) -- name and field shape both match (`metadata.log_name`, `unmapped.*`) |
| `PROXY` | `Zscaler Internet Access` | Yes (49 rules) -- name and field shape both match |
| `EMAIL` | `Mimecast` | Yes (15 rules) -- name and field shape both match |
| `SSHD`, `SUDO`, `PAM`, `CRON`, `AUDIT` | `Linux Audit` | No real match in this tenant's library -- invented |
| `HTTP` | `Apache HTTP Server` | No real match -- invented |
| `DNS` | `ISC BIND` | No real match -- invented |
| `DBAUDIT` | `PostgreSQL` | No real match -- invented |

None of this mapping changed for the Watchtower reskin — only the literal
field *values* (hostnames, usernames, app names, table names) changed. The
field *shapes* and the `DATASOURCE_BY_MSGID` lookup are untouched from the
FoundStone/Treadstone build, so no Lua changes were required for the theme
swap.

## Windows Event Logs: real XML, not JSON

`WINEVENT`'s `message` is genuine Windows Event Log XML — the real
`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">`
schema Event Viewer and Windows Event Collector actually produce (see
`generate_logs.py`'s `_win_event_xml`, built with `xml.etree.ElementTree`),
**not** a JSON approximation the way it briefly was. A real
`wevtutil qe /f:xml` dump looks exactly like this.

`parse_json_by_msgid.lua`'s `parseWINEVENT` handles it the same way the
8 plain-text sources are handled — Lua string patterns, not a DOM/XML
library (a real XML parser may not be available in every DataPipeline Lua
sandbox, and this XML's shape is fully deterministic since it's always
produced by that one serializer, same element order every time). It
rebuilds the **exact same** `winEventLog.data.event.eventData.<lowerCamelCase>`
nesting the old JSON-decode path used to produce — `winEventLog.id`,
`.channel`, `.providerName`, `.description`, and every
`winEventLog.data.event.eventData.*` field WATCHTOWER_DETECTIONS.md's
queries and this tenant's real deployed Windows Event Logs rules already
reference — so **no detection needs to change**, even though the wire
format switched from JSON to XML.

One real difference: genuine Windows Event XML never carries the
human-readable description text on the wire (Event Viewer renders that
client-side from a message-table DLL) — `parseWINEVENT` fills
`winEventLog.description` from a small static lookup keyed by EventID
instead, covering the fixed set of event IDs `generate_logs.py` emits
(4624, 4625, 4672, 4688, 4740, 4768, 4769).

`<Data Name="...">` element names are the real Microsoft schema
(PascalCase — `TargetUserName`, `LogonType`, ...); `parseWINEVENT`
lowercases just the first letter of each to match the existing
`eventData.targetUserName`-style field paths.

## Text-source field extraction (pipeline-side parsing)

The 8 plain-text sources (`SSHD`, `SUDO`, `PAM`, `HTTP`, `CRON`, `AUDIT`,
`DNS`, `DBAUDIT`) get a namespaced field table extracted at ingest time
instead of requiring a PowerQuery `parse '...' from message` clause in every
detection: each text `msgid` has a dedicated Lua pattern-match function
(`parseSSHD`, `parseSUDO`, `parsePAM`, `parseHTTP`, `parseCRON`, `parseAUDIT`,
`parseDNS`, `parseDBAUDIT`) that extracts the fields `generate_logs.py`
actually emits and attaches them as a **namespaced field table** on the event
-- `dns.qname`, `dbaudit.rows`, `sshd.sourceIp`, etc. -- rather than merging
at root (avoids collision risk and keeps each source's fields visually
grouped). `message` is left intact either way, so raw-text fallback queries
still work.

If a message doesn't match its parser's expected pattern, the parser returns
nil and the event just doesn't get that field table -- no crash, no dropped
event, same posture as a JSON decode failure.

| `msgid` | Namespaced fields | Real format modeled |
|---|---|---|
| `SSHD` | `sshd.result`, `.method`, `.user`, `.sourceIp`, `.port`, `.invalidUser` | genuine OpenSSH auth log |
| `SUDO` | `sudo.user`, `.tty`, `.pwd`, `.runAsUser`, `.command` | genuine sudo log |
| `PAM` | `pam.service`, `.action`, `.user` | genuine PAM session log |
| `HTTP` | `http.clientIp`, `.user`, `.method`, `.path`, `.status`, `.bytes`, `.userAgent` | genuine Apache Combined Log Format |
| `CRON` | `cron.user`, `.command` | genuine cron syslog line |
| `AUDIT` | `audit.srcIp`, `.dstIp`, `.proto`, `.srcPort`, `.dstPort` | UFW/netfilter kernel log (not true auditd -- see the `Linux Audit` naming note above) |
| `DNS` | `dns.clientIp`, `.qname`, `.qtype`, `.resolver`, `.port` | genuine ISC BIND querylog |
| `DBAUDIT` | `dbaudit.user`, `.db`, `.class`, `.command`, `.table`, `.statement`, `.rows`, `.sessionId` | genuine pgAudit log line |

## Identity correlation

For cross-source identity joins (e.g. impersonation email → suspicious auth), the
canonical identity is `<name>@starkindustries.com` (Marvel factions) or
`<name>@waynetech.com` (DC factions) — `email_domain(clearance)` in
`generate_logs.py` picks the right one; Watchmen/Vought/The Boys route
through the shared `lexcorp.com` back-office domain instead (see the
"Marvel/DC Universe Data" section at the top of `generate_logs.py`). Duo
`email`, Mimecast `email.to`, and Windows
`winEventLog.data.event.eventData.targetUserName` all align on it. Duo's
`user.name` retains the **cover identity** (superhero/villain alter ego) for
flavor — don't join on it.

## Verified against the reskinned generator

The Lua processor stage is data-shape-agnostic — it keys entirely off
`msgid`, never off literal field values — so swapping the generator's content
from the Bourne universe to the Watchtower roster required **zero**
changes to `parse_json_by_msgid.lua`. This was confirmed directly: one real
sample line per `msgid` was generated from the current `generate_logs.py`
(ambient generators *and* all 24 scripted scenarios) and run through the
actual `processEvent()` function. Every one of the 14 syslog-forwarded
`msgid` types got tagged with the correct `dataSource.name` and — for the
8 text sources — the correct namespaced field table, with zero decode
warnings. If you point a new console Data Pipeline at this generator's
output with this Lua file as its processor stage, it will behave exactly as
documented above.

## SentinelOne EDR: direct-to-SDL, not DataPipeline

```
log-generator ──POST /api/addEvents (SDL_WRITE_TOKEN)──▶ SDL   (no sgcia, no DataPipeline)
```

Real SentinelOne EDR telemetry never flows through a customer's DataPipeline
HEC pipeline — the agent reports straight to the S1 backend and into SDL.
DataPipeline HEC is for *third-party* log sources (AWS, Okta, Duo, etc.), not
native agent telemetry. Modeling EDR events the same way would be both less
realistic and would require console-side Lua maintenance every time a new
`event.type` gets added.

So `msgid = S1EDR` events skip `sgcia`/DataPipeline entirely:
`generate_logs.py`'s `_edr_line()` flattens the nested event dict into SDL's
dotted-key `attrs` shape (`_flatten()`) and POSTs directly to
`{SDL_BASE_URL}/api/addEvents` using `SDL_WRITE_TOKEN` — the same credential
already configured for the verifier app itself (see `docker-compose.yml`'s
`log-generator` service). Events are tagged `watchtower-simulation`. No
console pipeline changes needed when adding new EDR event types.

Because there's no envelope/root-merge step for these events, the field
collision rules above don't apply to EDR — whatever key names appear in
`generate_logs.py`'s `_edr_event()` builder are exactly what lands in SDL.

## See also

- [`WATCHTOWER_DETECTIONS.md`](WATCHTOWER_DETECTIONS.md) — PowerQuery detections, scoped by `msgid`.
- [`sgcia/config.yaml`](sgcia/config.yaml) — the forwarder config (sourcetype mapping, HEC destination). Not used by `S1EDR`.
- [github.com/mickbrowns1/securitygingercia](https://github.com/mickbrowns1/securitygingercia) — sgcia itself (the OpenTelemetry Collector fork + Rust dashboard/edit TUI). `docker-compose.yml` builds it directly from that repo's `main` branch via a git-context build (its own root-level `Dockerfile`, not `sgcia/Dockerfile` — that file no longer exists here), so no local checkout is required.
