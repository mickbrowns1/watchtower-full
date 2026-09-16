# Watchtower

**Watchtower** is a detection rule verification tool for SentinelOne. It takes real log events, overlays only the fields each detection rule requires, replays the synthetic events into the Singularity Data Lake (SDL), and verifies that alerts fire — giving you a ground-truth pass/fail result for every rule in your deployed library.

This repo also ships the **Watchtower Log Simulator** — a standalone synthetic security-event generator (Marvel, DC, Watchmen, and The Boys themed) that continuously feeds realistic on-prem *and* AWS telemetry through SentinelOne DataPipeline into SDL, for building and testing detections against a living dataset instead of one-off overlays. See [Watchtower Log Simulator](#watchtower-log-simulator) below.

> Superhero/villain factions map to a fictionalized corporate-espionage
> narrative — financial disputes, insider leaks, credential hygiene, identity
> theft — never violence. See [`CLAUDE.md`](CLAUDE.md) for the full content
> guidelines and roster.

---

## How it works

For each detection rule, Watchtower:

1. Reads the rule's filter logic (`pair_list`) to determine the minimal set of fields required to trigger it
2. Takes a real ingested event as a base template (uploaded by you, or pulled from SDL)
3. Overlays **only** the detection-required field values onto the real event — everything else stays genuine
4. Ingests the synthetic event(s) into SDL
5. Waits and queries the `alert` dataset to confirm the rule fired

> **Change only what the detection reads. Keep everything else real.**

---

## Requirements

- Docker + Docker Compose (OrbStack works great on macOS)
- A `data/extracted.json` file — the parsed detection library (see [Data setup](#data-setup))
- A SentinelOne tenant for testing (POC/demo only — never production)
- `SDL_BASE_URL` must point at your tenant's actual **SDL/XDR host** (e.g. `https://xdr.us1.sentinelone.net`), **not** the Management Console URL — the two are different hosts, and pointing at the console will silently break ingestion (404s on `/api/query` / `/api/addEvents`)

---

## Quick start

```bash
git clone https://github.com/mickbrowns1/watchtower
cd watchtower

# Add your extracted.json to data/
cp /path/to/extracted.json data/

# Fill in .env — see .env.example (SDL_BASE_URL/tokens, and optionally
# HEC_URL/HEC_TOKEN if you also want the Watchtower Log Simulator running)
cp .env.example .env

# Start the verifier container (add the log simulator services too if you want them —
# see "Watchtower Log Simulator" below)
docker compose up -d verifier
```

Open **http://localhost:8091**

---

## Data setup

`data/extracted.json` is the parsed detection library. It is **not** included in this repo (it contains proprietary rule logic). It should have this shape:

```json
{
  "results": [
    {
      "id": "uuid",
      "name": "Rule Name",
      "description": "...",
      "app": "STAR",
      "file": "/rules/...",
      "queries": [
        {
          "query": "dataSource.name = 'Okta' and ...",
          "pair_list": [
            { "key": "dataSource.name", "op": "=", "value": "Okta" }
          ]
        }
      ]
    }
  ]
}
```

---

## Configuration

All configuration is done through the **Environments** tab in the UI. No editing files.

### Add an environment

1. Go to **Environments → New Environment**
2. Fill in:
   - **Name** — e.g. `POC - Acme Corp`
   - **Console Base URL** — e.g. `https://your-tenant.sentinelone.net`
   - **SDL Read Token** — Singularity Data Lake log read key
   - **SDL Write Token** — Singularity Data Lake log write key
   - **SDL Account ID**
   - **S1 API Token** — account-level API token (for library sync)
3. Set as active and save

> **Note:** the actual `/api/run` verification pipeline reads its SDL connection from `.env` (`SDL_BASE_URL`/`SDL_READ_TOKEN`/`SDL_WRITE_TOKEN`/`SDL_ACCOUNT_ID`/`DRY_RUN`), not from the DB-stored environment above — that UI environment is used for template fetching and status display. Keep both in sync. `SDL_BASE_URL` is the **SDL/XDR host**, not the console host — see [Requirements](#requirements).

### Sync the detection library

Click **↓ Sync from Active Environment** — this pulls all deployed rules from `/web/api/v2.1/detection-library/platform-rules` and filters the Rules tab to show only what's active on your tenant.

The sync result persists across restarts (stored in SQLite).

### Upload real log templates (recommended)

Instead of pulling templates from SDL (which may contain private data), upload your own:

1. Go to **Environments → Real Log Templates**
2. Drag-drop a `.jsonl` or `.json` file of real log events
3. Events are indexed by `dataSource.name` automatically

Supported formats:
- JSONL (one JSON object per line)
- JSON array (`[{...}, {...}]`)
- JSON object with `events` or `results` key (`{"events": [...]}`)

---

## Running verifications

1. Go to **Rules** — rules are grouped by data source, collapsed by default
2. Check individual rules or select all rules for a source
3. Click **Run →** or go to the **Run** tab
4. Enable **Dry Run** to preview what would be ingested without sending anything
5. Hit **Run** — progress updates live, results show fired/not fired per rule

---

## Watchtower Log Simulator

A separate, always-on synthetic security-event generator — themed around
Marvel, DC, Watchmen, and The Boys (Avengers, S.H.I.E.L.D., Justice League,
X-Men, Wakanda, Gotham Rogue, Legion of Doom, Suicide Squad, HYDRA,
Green Lanterns, Vought/The Boys, and the Watchmen audit/oversight layer) —
that ships a steady stream of realistic telemetry through SentinelOne
DataPipeline into SDL. Use it to build and validate PowerQuery detections
against a living dataset (with scripted, correlated scenarios you can fire on
demand) rather than one-off overlaid events.

```
log-generator ──RFC 5424/6587 over TCP──▶ sgcia ──HEC (one POST/event)──▶ DataPipeline ──▶ SDL
```

The forwarder is [sgcia](https://github.com/mickbrowns1/securitygingercia)
(Security Ginger Collect It All — a custom OpenTelemetry Collector
distribution), not syslog-ng — see [WATCHTOWER_PIPELINE.md](WATCHTOWER_PIPELINE.md#sgcias-field-mapping-mechanics)
for the swap and why it needed zero changes to the Lua stage or any
detection.

### What it generates

**On-prem / SaaS security sources:** Palo Alto Networks Firewall (Traffic/Threat/GlobalProtect logs), Linux Audit (sshd/sudo/PAM/cron/kernel), Apache HTTP Server access logs, Cisco Duo MFA (authentication + administrator logs), Zscaler Internet Access, ISC BIND DNS, Mimecast email security, PostgreSQL, Windows Event Logs. Every source is tagged with a real `dataSource.name`/`dataSource.category` grounded in this tenant's own deployed rule library where a match exists, and field shapes for Palo Alto, Duo, and Windows Event Logs are grounded in that same rule library rather than raw vendor wire formats (see `WATCHTOWER_PIPELINE.md`'s tagging table).

**AWS (CloudTrail):** modeled as a **hardened** AWS Organization on purpose, one account per faction (Avengers, Justice League, X-Men, Wakanda) — MFA-enforced `AssumeRole` sessions only (no root usage, no long-lived access keys in normal traffic), encrypted S3 (SSE-KMS), least-privilege roles per program, and API calls only ever from known corporate egress IPs. Root usage, disabled logging, privilege escalation, and MFA-less logins are deliberately **never** ambient — they only appear inside the dedicated attack scenarios, so a detection firing on them means something actually happened.

**SentinelOne EDR:** schema grounded directly in this tenant's own deployed detection library (746 real `SentinelOne`-sourced rules in `data/extracted.json`) rather than guessed — `event.type` distribution mirrors real usage (`Process Creation` dominant, plus File/Registry/Task/Network/DNS/Behavioral Indicator events). Ambient traffic is signed, known-publisher, ordinary parent/child process trees; credential dumping only appears in a dedicated scenario.

24 scripted, correlated scenarios grounded in well-known Marvel/DC/Watchmen/
Boys story beats reframed as a corporate-espionage narrative — cosmic-cube
vault exfiltration, AWS privilege escalation via an Oscorp shell entity,
a Skrull impersonating Nick Fury to leak internal financials, an Ultron-7
rogue-AI service identity seizing the power registry, the Avengers' Civil
War access-revocation split, a HYDRA operative's credential-rotation
defection, a Green Lantern ring reissued and re-authenticating from an
unfamiliar recharge station, and cross-faction rivalry beaconing between
Gotham Rogue/Wakanda and Suicide Squad/Legion of Doom — each emits a short
burst of events across multiple sources sharing actors/hosts/IPs, so you can
pivot host→user→IP across firewall, identity, proxy, DB, cloud, and EDR
telemetry. Full list and detection mappings:
[WATCHTOWER_DETECTIONS.md](WATCHTOWER_DETECTIONS.md).

### Starting it

```bash
# In .env, add (found in DataPipeline UI: Pipelines > Sources > + Add Source > HTTP Event Collector):
HEC_URL=https://ingest.<region>.sentinelone.net/services/collector/event
HEC_TOKEN=<your DataPipeline HEC token>
HEC_INDEX=watchtower

docker compose up -d --build sgcia log-generator
```

You'll also need a **Lua processor stage** in the DataPipeline pipeline itself — the built-in `parse_json` step has no per-source gating and throws on the plain-text sources. Use [datapipeline/parse_json_by_msgid.lua](datapipeline/parse_json_by_msgid.lua) (verified locally with `datapipeline/test_parse_json_by_msgid.lua`, and against real reskinned generator output — see [WATCHTOWER_PIPELINE.md](WATCHTOWER_PIPELINE.md)'s "Verified against the reskinned generator" section); see [WATCHTOWER_PIPELINE.md](WATCHTOWER_PIPELINE.md) for the full integration notes (field collisions, sourcetype routing, reliability behavior).

**SentinelOne EDR events don't go through any of this** — they bypass sgcia/DataPipeline entirely and post straight into SDL (matching how real EDR telemetry actually arrives), reusing the `SDL_BASE_URL`/`SDL_WRITE_TOKEN` already in `.env` for the verifier app itself. No console changes needed for these.

### Firing scenarios on demand

Ambient scenario firing is rare (`SCENARIO_CHANCE=0.02`). To test/demo a detection immediately:

```bash
docker exec nexus-log-generator python3 fire_scenario.py                        # list all scenarios
docker exec nexus-log-generator python3 fire_scenario.py nexus_registry_pull    # fire one (partial name OK)
docker exec nexus-log-generator python3 fire_scenario.py all                    # fire every scenario once
docker exec nexus-log-generator python3 fire_scenario.py --category A           # fire every scenario that
                                                                                         # triggers an A-category detection
docker exec nexus-log-generator python3 fire_sources.py                         # one test event per data source
```

See [WATCHTOWER_DETECTIONS.md](WATCHTOWER_DETECTIONS.md) for the full PowerQuery detection library and the scenario → detection mapping table. [Watchtower Ops Console](#watchtower-ops-console--stack-diagnostics--remediation-dashboard) below wraps all three of these as menu options.

---

## Optional: local Splunk sink via Tailscale Funnel

An optional add-on pair of containers (`ts-splunk`, `splunk`) runs a free-license
Splunk Enterprise instance and exposes its HTTP Event Collector publicly
through [Tailscale Funnel](https://tailscale.com/kb/1223/funnel), so a
SentinelOne Data Pipelines "Splunk HEC Logs" destination can forward a copy
of your events there. Not started by default. See
[splunk/README.md](splunk/README.md) for full install steps, the
`tailscale funnel` command, and the pipeline wiring/gotchas.

---

## Watchtower Ops Console — stack diagnostics & remediation dashboard

A glowing Green-Lantern-green ops-console dashboard for inspecting and controlling the
whole Compose stack from one place, instead of juggling `docker ps`/`logs`/
`exec` by hand. The container's main process serves it over plain HTTP — no
Node/npm build step, just FastAPI serving static HTML/CSS/JS directly:

```bash
docker compose up -d watchtower
open http://localhost:8092
```

The three services get themed names throughout Watchtower (both the web
dashboard and the terminal tool) — the real container name is always shown
alongside, never replaced:

| Themed name | Container | Role |
|---|---|---|
| **Mission Control** | `log-generator` | writes the synthetic events & 24 scripted scenarios |
| **Comms Relay** | `sgcia` | receives Mission Control's output, forwards it to DataPipeline |
| **Debrief** | `verifier` | reviews the mission — verifies detection rules actually fire |

(Everywhere else in this doc, and in `docker-compose.yml`/`docker exec`/API
paths, the real container names are still what you actually use — this
naming is a presentation layer in `core.py`, purely for the dashboard/TUI;
the container/service name itself is `watchtower` (`nexus-watchtower`).)

The tabs and a few tools get the same treatment — themed name up front, real
function in parens, never just the pun on its own:

| Tab | What it is |
|---|---|
| **Ops Floor** | Dashboard — live service health + resource stats, auto-refreshing |
| **Diagnostics** | environment summary, TLS, DNS, volume/disk |
| **Signal Intercepts** | Sources — sources/destinations, connectivity, ports, **Signal Check** (syslog tester), live syslog stream |
| **Mission Briefing** | Scenarios — fire by name/category, send test logs per source (each with a confirmation before it actually sends anything) |
| **Field Outposts** | Environments — the SDL/HEC profile manager below |
| **The Vault** | Logs — tail any container, with a "Follow" toggle that polls every 2s and auto-scrolls |

Field Outposts' verbs follow the same bit: **Register outpost** (add),
**Snapshot current config** (capture current `.env`), **Reconfigure** (edit —
see below), **Activate** (apply — rewrites `.env` and recreates containers),
**Decommission** (delete).

Prefer a terminal? The original interactive tool (`rich` + `pyfiglet`) is
still there, sharing the exact same underlying logic (`core.py`) as the web
dashboard so the two never drift apart — it's just not the container's main
process anymore:

```bash
docker exec -it nexus-watchtower python3 watchtower.py
```

It also still has one thing the web UI intentionally doesn't: an interactive
shell into any container (option 9) — a real TTY doesn't translate to a web
button, so that stays terminal-only.

**Diagnostics:** full scan, service health (status/health per container),
container CPU/memory/network stats, TLS certificate checks against your
configured `HEC_URL`/`SDL_BASE_URL`, DNS resolution (internal service names
and external hosts), volume/disk usage, and an **environment summary** — the
live, redacted `HEC_*`/`SDL_*` values the stack is currently pointed at, and
which saved environment (if any) they match.

**Tools:** tail logs, an interactive shell into any container, restart a
container, view sources/destinations (with `HEC_TOKEN`/`SDL_WRITE_TOKEN`
always redacted — never printed in full), TCP connectivity + latency checks,
published-port inventory, a syslog tester that sends a probe message and
confirms `sgcia`'s `events_in` counter actually increments, a continuous
live-updating syslog throughput view, and three ways to generate on-demand
traffic:

- **Fire a scenario** — any one of the 24 by (partial) name, or all of them (wraps `fire_scenario.py`, same as [Firing scenarios](#firing-scenarios-on-demand) above).
- **Fire scenarios by detection category (A–H)** — fires every scenario that triggers at least one detection in a given `WATCHTOWER_DETECTIONS.md` category (e.g. category `C` fires everything that lights up a named-signature detection). Good for exercising a whole category's detections in one shot instead of naming scenarios one at a time.
- **Send one test log per source** — fires one representative event for each of the 15 data sources (all 14 syslog-forwarded `msgid`s plus the direct-to-SDL `S1EDR` path), for confirming every source is actually reaching SDL — most useful right after standing up the stack or switching environments, before waiting on ambient traffic or a full scenario.

**Field Outposts (Environments) — swap which SentinelOne tenant this stack
talks to,** backed by a small SQLite database (`watchtower-db` volume,
independent from the Verifier's own `data/extracted.json`/`watchtower.db`):

- **Snapshot current config** (capture current) — snapshots the live `.env`'s `HEC_URL`/`HEC_TOKEN`/`HEC_INDEX`/`SDL_BASE_URL`/`SDL_READ_TOKEN`/`SDL_WRITE_TOKEN`/`SDL_ACCOUNT_ID` as a named profile — the safe way to save "what's running right now" before trying something else.
- **Register outpost** (add) — manually enter a profile for a different tenant (token fields are masked on input).
- **List registered outposts** — shows every saved profile (redacted) and flags which one (if any) matches the live `.env`.
- **Reconfigure** (edit) — update an existing profile's fields. Secret inputs are left blank on the edit form (never round-tripped back through the browser as their redacted display value) — leaving one blank keeps its current stored value, only fields you actually fill in change.
- **Activate** (apply) — rewrites `.env` with the chosen profile's values (every other line/var untouched) and runs `docker compose up -d --force-recreate` on `verifier`, `sgcia`, and `log-generator` so the change actually takes effect, not just sits in a file. Requires confirming first (a prompt in the TUI, a browser confirm() in the web UI).
- **Decommission** (delete) — removes a saved profile (doesn't touch `.env`).

This is how you rebuild and test against a different environment without
hand-editing `.env` and remembering which containers to restart — capture
your current setup, add a second tenant's profile, and switch between them
with a couple of menu choices.

> **Privilege note:** Watchtower's container has `/var/run/docker.sock`
> mounted read-write so it can inspect/restart/exec into the other 3
> containers, **and** the project directory bind-mounted read-write at the
> identical absolute path it lives at on the host (`HOST_PROJECT_DIR`,
> defaulted in `docker-compose.yml`) — required so `docker compose`, run from
> inside Watchtower against the mounted host socket, resolves `./.env` and
> friends against real host paths instead of this container's own
> filesystem. Altogether that's equivalent to root on the Docker host plus
> write access to this repo. The web dashboard on port 8092 has **no
> authentication** and exposes all of this over plain HTTP — only run this
> stack on a machine you trust, and don't publish port 8092 (or
> `docker exec`/`docker attach` access) any more broadly than your own local
> access.

---

## Ports

| Service | Port | Purpose |
|---|---|---|
| `verifier` | 8091 → 8000 | Web UI / API |
| `sgcia` | 515/udp → 514/udp, 602/tcp → 601/tcp | Watchtower Log Simulator ingest |
| `sgcia` | 7811 → 7801 | sgcia's own web UI (health/config/topology/live log viewer) — plain HTTP, no auth |
| `watchtower` | 8092 → 8000 | Watchtower web dashboard |

Change in `docker-compose.yml`.

---

## Data persistence

The following are mounted from your host into the container so they survive rebuilds:

| Path | Contents |
|---|---|
| `data/watchtower.db` | SQLite — Verifier's environments, deployed rule names |
| `.env` | Fallback env vars (config via UI is preferred); also read/written by Watchtower's Environments tool |
| `watchtower-db` (named volume) | SQLite — Watchtower's saved SDL/HEC environment profiles |

`data/extracted.json` is baked into the image at build time.

---

## Architecture

```
watchtower/
  api.py                  # FastAPI backend
  watchtower/
    classifier.py         # Rule class detection (simple/volume/correlation/first_seen/scheduled)
    rule_parser.py         # pair_list → minimal field overlay
    event_builder.py       # Deep-merge overlay onto real template
    ingester.py            # SDL addEvents
    verifier.py            # Query alert dataset, match rule names (PowerQuery via /api/powerQuery)
    runner.py              # Full pipeline orchestrator
    template_fetcher.py    # SDL V1 query for real event templates
    db.py                  # SQLite — environments + deployed rule names
  ui/                     # React + Vite + Tailwind frontend
  Dockerfile              # Multi-stage: Node builds UI, Python serves it
  docker-compose.yml

log-generator/            # Watchtower Log Simulator — synthetic event generator
  generate_logs.py         # Ambient generators + 24 scripted scenarios
  fire_scenario.py         # CLI to fire scenarios on demand, by name or detection category
  fire_sources.py          # CLI to fire one test event per data source (msgid)
  preview.py

sgcia/                    # OTel Collector fork (https://github.com/mickbrowns1/securitygingercia) --
                          # receives generator output, forwards to DataPipeline via HEC
  config.yaml
  Dockerfile

syslog-ng/                # Legacy forwarder, superseded by sgcia above -- no longer wired into
                          # docker-compose.yml, kept on disk for reference only
  syslog-ng.conf

datapipeline/               # DataPipeline pipeline processor stage
  parse_json_by_msgid.lua   # Per-source JSON parsing/field-promotion Lua stage
  test_parse_json_by_msgid.lua  # Local verification harness

watchtower/                   # Stack diagnostics & remediation -- web dashboard (:8092) + TUI
  core.py                    # Shared logic -- docker.sock, .env/SQLite environment
                              # profiles, docker compose apply. No printing/prompting;
                              # both frontends below just render this.
  web.py                     # FastAPI app -- the container's main process
  static/                    # Plain HTML/CSS/JS frontend (no build step)
    index.html, styles.css, app.js
  watchtower.py              # rich + pyfiglet interactive tool (docker exec only now)
  Dockerfile                 # python:3.12-slim + the docker CLI + compose plugin (no daemon)

WATCHTOWER_DETECTIONS.md   # PowerQuery detection library + scenario mapping
WATCHTOWER_PIPELINE.md     # DataPipeline integration notes (hard-won)
CLAUDE.md                    # Theme/content brief — roster, factions, guidelines
```

---

## Guardrails

- All synthetic events are tagged `_watchtower_test: true` for easy cleanup
- Config UI warns when no active environment is set
- Dry run mode is on by default — no events are ingested until you explicitly disable it
- Never use against a production tenant

---

## License

Internal tooling — SentinelOne.
