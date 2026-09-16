# StrongIsland Log Simulator — Project Brief

This is a from-scratch synthetic security-event generator, built on the same
architecture as `../FoundStone`'s "Treadstone Log Simulator" (Jason Bourne
universe), re-themed around Marvel, DC, Watchmen, and The Boys.
**FoundStone is untouched** — this is a separate project in its own
directory so nothing there gets disturbed.

**Note:** this project was originally rap/hip-hop themed (90s/2000s rap
artists, labels, and industry figures) and has since been fully converted to
the superhero theme below. The reskin is **complete** — `generate_logs.py`,
`fire_scenario.py`, `STRONGISLAND_DETECTIONS.md`, `STRONGISLAND_PIPELINE.md`,
`README.md`, and the `watchtower/` dashboard have all
been updated. Check the actual file state before assuming anything below is
still TODO — this doc may lag behind real progress.

## Content guidelines — read this first

- **Zero violence, ever.** The "crimes and espionage" angle is **strictly
  corporate/financial/network-security**: fictionalized operational
  narrative (insider leaks, credential theft, privilege escalation,
  identity impersonation), not violence — same posture FoundStone takes with
  its CIA-black-ops framing.
- Civilian identities are paired with each character's own established
  superhero/villain alter ego as the "cover identity" (mirrors FoundStone's
  `david.webb → jason.bourne` mechanic) — this is now entirely fictional
  characters, so there's no real-person sensitivity to manage (unlike the
  original rap-theme version, which used real artists' own public stage
  names).
- Keep the same secure-by-default philosophy as FoundStone: ambient traffic is
  clean/expected; anomalies only appear in dedicated scripted scenarios.

## Current state

```
StrongIsland/
  log-generator/          # Python generator — reskin COMPLETE
    generate_logs.py       # 102 operatives across 18 factions, 24 scenarios
    fire_scenario.py        # scenario-name → detection-category mapping, updated
    preview.py
    Dockerfile
  syslog-ng/               # legacy forwarder config, superseded by sgcia below
    syslog-ng.conf
    Dockerfile
  datapipeline/             # Lua processor stage — data-shape-agnostic, no reskin needed
    parse_json_by_msgid.lua
    test_parse_json_by_msgid.lua
  foundstone/                # rule-verification backend package -- copied as-is from FoundStone,
    ...                      # NOT theme-specific, no reskin needed
  ui/                        # rule-verification React/Vite frontend -- copied as-is (source only;
    src/                     # node_modules/ and dist/ are gitignored, need `npm install && npm run build`)
    ...
  api.py                     # FastAPI backend for the verifier app (copied as-is, no theme content)
  requirements.txt
  bandit.toml
  data/                       # empty -- you must supply your own extracted.json here (gitignored,
                               # same as FoundStone: it's your tenant's proprietary rule library)
  docker-compose.yml          # 4 services: verifier + sgcia + log-generator + watchtower
  .env.example                # covers both the verifier's SDL/verification vars and the simulator's HEC vars
  .gitignore
  watchtower/                  # stack diagnostics dashboard
```

Data sources (12 total) are **reused unchanged** from FoundStone — same
technical shape (Palo Alto Networks Firewall, Windows Event Logs, Cisco Duo,
Zscaler Internet Access, Mimecast, AWS CloudTrail, SentinelOne EDR, Linux
Audit, Apache HTTP Server, ISC BIND, PostgreSQL). Only the *content* (asset
names, hostnames, operatives, scenario narratives) changed — the Lua
pipeline's dataSource tagging engine, JSON/text-parsing logic, and
`docker-compose.yml` wiring never needed to change.

**Rule verification (the `verifier` container/service) is a separate,
non-theme-specific capability** — mirrors FoundStone's own tool exactly (same
`foundstone/` package name internally, not renamed). It tests your tenant's
*real deployed detection rules*, which have nothing to do with the theme — it
works identically regardless of which log simulator is feeding synthetic
data into SDL. To actually run it you still need to: supply your own
`data/extracted.json` in `data/` (not committed, same as FoundStone), fill in
`.env` (copy from `.env.example`), and build the UI locally first
(`cd ui && npm install && npm run build`) since the Dockerfile copies a
pre-built `ui/dist/` rather than running npm inside the container.

## Faction roster (civilian identity → superhero/villain alter ego)

**Avengers** (Marvel) — Tony Stark → Iron Man, Steve Rogers → Captain
America, Natasha Romanoff → Black Widow, Bruce Banner → The Hulk, Clint
Barton → Hawkeye, Wanda Maximoff → Scarlet Witch, Sam Wilson → The Falcon,
Carol Danvers → Captain Marvel, Peter Parker → Spider-Man, Pepper Potts

**S.H.I.E.L.D.** (Marvel) — Phil Coulson, James Rhodes → War Machine, Daisy
Johnson → Quake, Grant Ward → Agent Ward, Nicholas Fury, Maria Hill

**Justice League** (DC) — Bruce Wayne → Batman, Clark Kent → Superman, Diana
Prince → Wonder Woman, Barry Allen → The Flash, Arthur Curry → Aquaman, J'onn
J'onzz → Martian Manhunter, Lucius Fox

**X-Men** (Marvel) — dual-alias solo-op mechanic (mirrors Wu-Tang's original
solo-deal identities): Charles Xavier → Professor X, Logan Howlett →
Wolverine/Weapon X, Scott Summers → Cyclops, Ororo Munroe → Storm, Hank McCoy
→ Beast, Jean Grey → Phoenix/Marvel Girl

**Wakanda** (Marvel) — T'Challa → Black Panther, Shuri, Erik Killmonger,
Ramonda

**Gotham Rogue** (DC) — Harley Quinn/Harleen Quinzel, Pamela Isley → Poison
Ivy, Jonathan Crane → Scarecrow

**Asgard** (Marvel) — Thor, Loki, Sif, Heimdall, Volstagg

**Guardians of the Galaxy** (Marvel) — Peter Quill → Star-Lord, Gamora,
Rocket Raccoon, Drax, Groot, Mantis, Nebula, Adam Warlock, Yondu, and others

**Legion of Doom** (DC) — Lex Luthor, Brainiac, Darkseid, Grodd

**Suicide Squad** (DC) — Floyd Lawton → Deadshot, Rick Flag, Amanda Waller →
The Wall

**HYDRA** (Marvel) — Bucky Barnes → Winter Soldier (a brainwashed defector,
not a willing villain)

**Brotherhood of Mutants** (Marvel) — Erik Lehnsherr → Magneto, Rogue,
Mystique, Cain Marko → Juggernaut

**Watchmen** — the audit/oversight layer, replacing what would otherwise be
a generic "compliance" faction: Walter Kovacs → Rorschach, Jon Osterman →
Doctor Manhattan, Adrian Veidt → Ozymandias, Dan Dreiberg → Nite Owl, Laurie
Juspeczyk → Silk Spectre. Thematically apt — "who watches the watchmen" is
exactly the audit-layer question.

**Vought International** (The Boys) — corporate-controlled supes ("The
Seven"): John Gillman → Homelander, Annie January → Starlight, Kevin
Moskowitz → The Deep, Maggie Shaw → Queen Maeve, Reggie Franklin → A-Train,
Black Noir

**The Boys** (The Boys) — vigilante insiders opposing Vought: Billy Butcher,
Hughie Campbell, Marvin Milk → Mother's Milk, Serge Cochon → Frenchie, Kimiko
Miyashiro → The Female

**Teen Titans** (DC) — Dick Grayson → Robin, Kory Anders → Starfire, Raven
Roth, Victor Stone → Cyborg, Garfield Logan → Beast Boy

**Doom Patrol** (DC) — Clifford Steele → Robotman, Rita Farr → Elasti-Woman,
Larry Trainor → Negative Man, Kay Challis → Crazy Jane

**Green Lantern Corps** (DC) — added as a standalone faction (no equivalent
in the original rap theme): Hal Jordan → Green Lantern/Emerald Knight, Kyle
Rayner → Ion/Torchbearer, John Stewart, Guy Gardner → Warrior, Jessica Cruz →
Power Ring, Simon Baz

## Infrastructure

- Shared back-office org: **LexCorp**, all hosts on `lexcorp.com`
- Email domains by universe: `@starkindustries.com` (Marvel), `@waynetech.com`
  (DC), `@lexcorp.com` (Watchmen, Vought, The Boys) — see `email_domain()` in
  `generate_logs.py`
- DB name `nexus_registry`, key table `public.power_registry` (was
  `royalty_ledger`), vault table `public.cosmic_vault` (was `masters_vault`)

## Scenarios (all corporate/financial/network-security framed, zero violence)

24 scripted scenarios — see [STRONGISLAND_DETECTIONS.md](STRONGISLAND_DETECTIONS.md)
for the full scenario → detection mapping. Highlights:

- **Cosmic Cube Heist** (Thanos) — vault exfiltration
- **Oscorp Shell Entity Privesc** — AWS privilege escalation, financial-crimes framing
- **Nexus Registry Mass Pull** (Ultron-7) — rogue-AI service identity mass DB extraction
- **Skrull Infiltration** (Talos impersonating Fury) — insider-leak mechanic reframed as literal identity theft
- **Avengers/X-Men Beacon**, **Gotham Rogue vs. Wakanda Rivalry**, **Suicide Squad vs. Legion of Doom Rivalry** — rival-faction network beaconing
- **Multiverse Travel Anomaly** — correlated login/financial-transaction burst
- **Sokovia Accords Breach Lateral Movement** — kerberoasting/lateral movement
- **X-Men Solo Ops Sprawl** — credential correlation across individually-run solo-op identities
- **HYDRA Defection** (Bucky Barnes) — credential-rotation scenario
- **Civil War Access Revocation** — Sokovia Accords enforcement, access-revocation scenario
- **Green Lantern Recharge Anomaly** — a ring credential reissued and immediately re-authenticating from an unfamiliar station (Green Lantern's dedicated showcase scenario)
- **Justice League Financial Audit**, **Wakanda Infra Standup**, **S.H.I.E.L.D. Internal Watchdog**, **Asgard/Avengers Trust Pact** — audit/recon/insider-threat/trust-relationship scenarios
- **New Recruit Onboarding** (Spider-Man), **Kyle Rayner Onboarding** — first-login-after-provisioning pattern
- **Infinity Vault Access**, **Banner Legal Hold**, **S.H.I.E.L.D. Shutdown**, **Multiverse Nexus Audit** (Ozymandias) — informational/legal-hold/cross-faction-audit scenarios
- **Hawkeye vs. S.H.I.E.L.D. Access Dispute** — intentionally below every threshold, illustrates why detection thresholds need tuning to your real baseline

## Watchtower — full rename, not just a reskin

The `watchtower/` stack-diagnostics dashboard (originally `soundcheck/`)
has been fully renamed to match the theme, not just visually reskinned:
directory `soundcheck/` → `watchtower/`, terminal script `soundcheck.py` →
`watchtower.py`, compose service key `soundcheck:` → `watchtower:`,
container name `nexus-soundcheck` → `nexus-watchtower`, and the named
volume `soundcheck-db` → `watchtower-db` (mounted at `/mnt/watchtower-db`,
tracked by `core.py`'s `WATCHTOWER_DB` constant). Steel-blue/cyan
ops-console palette, hex-shield icon — see
[README.md](README.md#watchtower-ops-console--stack-diagnostics--remediation-dashboard)
for the full tab/copy mapping.

## How to pick this up in a new session

The reskin is complete. If you need to extend it (new scenarios, new
factions, further doc polish), say something like: *"Read CLAUDE.md, then
let's add [whatever's next] to the superhero-themed StrongIsland
simulator."* That gives a fresh session the current state without
re-deriving any of it.
