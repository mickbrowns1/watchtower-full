"""
Watchtower — shared logic, used by both the terminal tool (watchtower.py)
and the web dashboard (web.py). Nothing in here prints or prompts; every
function takes plain arguments and returns plain data (dicts/lists/strings)
or raises, so both frontends can render it their own way.
"""
from __future__ import annotations

import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import time
from datetime import datetime, timezone

import http.client
import json

import docker
import docker.errors

CONTAINERS = {
    "verifier": "nexus-verifier",
    "sgcia": "nexus-sgcia",
    "log-generator": "nexus-log-generator",
}

# sgcia (Security Ginger Collect It All -- Mick's own OpenTelemetry
# Collector fork) replaced syslog-ng as the log-generator -> DataPipeline
# HEC forwarder. Its statuscfg extension serves a JSON /status endpoint on
# this port -- see sgcia_status() below, used in place of the old
# `syslog-ng-ctl stats` CLI parsing.
SGCIA_STATUS_HOST = "sgcia"
SGCIA_STATUS_PORT = 7801

# Themed display name + one-line role, keyed by the same technical label
# used everywhere else (CONTAINERS, API paths, exec targets) -- this is a
# presentation-only layer, so nothing above ever has to change.
DISPLAY_NAMES = {
    "verifier": ("Debrief", "reviews the mission — verifies detection rules actually fire"),
    "sgcia": ("Comms Relay", "receives log-generator's output, forwards it to DataPipeline (via sgcia-otelcol)"),
    "log-generator": ("Mission Control", "writes the synthetic events & 24 scripted scenarios"),
}


def display_name(label: str) -> str:
    return DISPLAY_NAMES.get(label, (label, ""))[0]


def display_tagline(label: str) -> str:
    return DISPLAY_NAMES.get(label, (label, ""))[1]

SECRET_ENV_KEYS = {
    "HEC_TOKEN", "SDL_WRITE_TOKEN", "SDL_READ_TOKEN", "S1_API_TOKEN",
    "SDL_ACCOUNT_ID",
}

DATA_MOUNT = "/mnt/data"

# Environments (SDL/HEC profile) support -- see PRIVILEGE NOTE in
# docker-compose.yml for why the project directory is mounted at the same
# absolute path it lives at on the host (Docker-outside-of-Docker path
# parity, needed for `docker compose` invoked from in here to resolve
# ./.env / ./docker-compose.yml against the real host filesystem).
HOST_PROJECT_DIR = os.getenv("HOST_PROJECT_DIR", "")
ENV_FILE = os.path.join(HOST_PROJECT_DIR, ".env") if HOST_PROJECT_DIR else None
COMPOSE_FILE = os.path.join(HOST_PROJECT_DIR, "docker-compose.yml") if HOST_PROJECT_DIR else None
COMPOSE_PROJECT = "superheroes"
WATCHTOWER_DB = "/mnt/watchtower-db/environments.db"

# .env keys that fully describe "which tenant is this stack pointed at" --
# managed by the Environments tool. Everything else in .env (DRY_RUN,
# LOG_INTERVAL_MS, ...) is left untouched.
MANAGED_ENV_KEYS = [
    "HEC_URL", "HEC_TOKEN", "HEC_INDEX",
    "SDL_BASE_URL", "SDL_READ_TOKEN", "SDL_WRITE_TOKEN", "SDL_ACCOUNT_ID",
]
ENV_SECRET_KEYS = {"HEC_TOKEN", "SDL_READ_TOKEN", "SDL_WRITE_TOKEN"}

CATEGORY_LABELS = {
    "A": "Technique detections", "B": "Cross-source correlations",
    "C": "Named-signature detections", "D": "AWS / CloudTrail",
    "E": "SentinelOne EDR", "F": "New-account / provisioning",
    "G": "Informational / baseline", "H": "Cross-label scope",
}


class NotFoundError(Exception):
    pass


def redact(key: str, value: str) -> str:
    if key in SECRET_ENV_KEYS and value:
        return f"{value[:4]}…redacted ({len(value)} chars)"
    return value


def container_env(container) -> dict[str, str]:
    env = {}
    for item in container.attrs.get("Config", {}).get("Env", []):
        if "=" in item:
            k, v = item.split("=", 1)
            env[k] = v
    return env


def docker_client() -> docker.DockerClient:
    """Raises on failure -- callers decide how to surface it (TUI exits,
    web returns an error response) rather than this module killing the
    process."""
    client = docker.from_env()
    client.ping()
    return client


def get_container(client, name: str):
    try:
        return client.containers.get(name)
    except docker.errors.NotFound:
        return None


def require_container(client, label: str):
    name = CONTAINERS.get(label)
    if not name:
        raise NotFoundError(f"Unknown container label '{label}'.")
    c = get_container(client, name)
    if c is None:
        raise NotFoundError(f"{name} not found.")
    return c


# ─── .env file (managed keys only) ──────────────────────────────────────────

def read_env_file() -> dict[str, str]:
    """Parse the real .env at HOST_PROJECT_DIR/.env. Returns {} if the
    project directory isn't mounted or .env doesn't exist yet."""
    values: dict[str, str] = {}
    if not ENV_FILE or not os.path.isfile(ENV_FILE):
        return values
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip()
    return values


def write_env_updates(updates: dict[str, str]) -> None:
    """Rewrite HOST_PROJECT_DIR/.env, replacing only `updates`' keys in place
    (preserving comments, ordering, and every other var) and appending any
    that don't already exist."""
    raw_lines: list[str] = []
    if ENV_FILE and os.path.isfile(ENV_FILE):
        with open(ENV_FILE) as f:
            raw_lines = f.readlines()

    seen = set()
    out = []
    for line in raw_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
            if k in updates:
                out.append(f"{k}={updates[k]}\n")
                seen.add(k)
                continue
        out.append(line if line.endswith("\n") else line + "\n")
    for k, v in updates.items():
        if k not in seen:
            out.append(f"{k}={v}\n")

    with open(ENV_FILE, "w") as f:
        f.writelines(out)


# ─── Environments (SDL/HEC profiles) ────────────────────────────────────────

def env_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(WATCHTOWER_DB), exist_ok=True)
    conn = sqlite3.connect(WATCHTOWER_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS environments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            hec_url TEXT, hec_token TEXT, hec_index TEXT,
            sdl_base_url TEXT, sdl_read_token TEXT, sdl_write_token TEXT, sdl_account_id TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def env_profile_to_dict(row: sqlite3.Row) -> dict[str, str]:
    return {
        "HEC_URL": row["hec_url"] or "", "HEC_TOKEN": row["hec_token"] or "",
        "HEC_INDEX": row["hec_index"] or "",
        "SDL_BASE_URL": row["sdl_base_url"] or "", "SDL_READ_TOKEN": row["sdl_read_token"] or "",
        "SDL_WRITE_TOKEN": row["sdl_write_token"] or "", "SDL_ACCOUNT_ID": row["sdl_account_id"] or "",
    }


def _profile_matches_live(profile: dict[str, str], live: dict[str, str]) -> bool:
    return all(live.get(k, "") == v for k, v in profile.items() if v)


def list_environments() -> list[dict]:
    conn = env_db()
    rows = conn.execute("SELECT * FROM environments ORDER BY name").fetchall()
    conn.close()
    live = read_env_file()
    out = []
    for row in rows:
        profile = env_profile_to_dict(row)
        out.append({
            "name": row["name"],
            "created_at": row["created_at"],
            "values": {k: (redact(k, v) if k in ENV_SECRET_KEYS and v else v) for k, v in profile.items()},
            "matches_live": _profile_matches_live(profile, live),
        })
    return out


def add_environment(name: str, fields: dict[str, str]) -> None:
    if not name:
        raise ValueError("Name required.")
    conn = env_db()
    try:
        conn.execute(
            "INSERT INTO environments (name, hec_url, hec_token, hec_index, sdl_base_url, "
            "sdl_read_token, sdl_write_token, sdl_account_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (name, fields.get("HEC_URL", ""), fields.get("HEC_TOKEN", ""), fields.get("HEC_INDEX", ""),
             fields.get("SDL_BASE_URL", ""), fields.get("SDL_READ_TOKEN", ""),
             fields.get("SDL_WRITE_TOKEN", ""), fields.get("SDL_ACCOUNT_ID", ""),
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError(f"An environment named '{name}' already exists.")
    finally:
        conn.close()


def get_environment(name: str) -> dict[str, str]:
    """Raw (unredacted) values -- for prefilling an edit form server-side
    (TUI) or anywhere secrets need to actually be compared/reused, not
    displayed. Callers facing a browser should NOT send this back to the
    client; use list_environments()' redacted values instead."""
    conn = env_db()
    row = conn.execute("SELECT * FROM environments WHERE name = ?", (name,)).fetchone()
    conn.close()
    if row is None:
        raise NotFoundError(f"No environment named '{name}'.")
    return env_profile_to_dict(row)


def update_environment(name: str, fields: dict[str, str]) -> None:
    """Update an existing profile. Any field left blank in `fields` keeps
    its current stored value (matches the TUI's add-form "Enter to keep
    current" behavior) -- so an edit form can safely leave secret inputs
    blank instead of round-tripping a redacted display value back as if it
    were real."""
    conn = env_db()
    row = conn.execute("SELECT * FROM environments WHERE name = ?", (name,)).fetchone()
    if row is None:
        conn.close()
        raise NotFoundError(f"No environment named '{name}'.")
    current = env_profile_to_dict(row)
    merged = {k: (fields.get(k) or current.get(k, "")) for k in MANAGED_ENV_KEYS}
    conn.execute(
        "UPDATE environments SET hec_url=?, hec_token=?, hec_index=?, sdl_base_url=?, "
        "sdl_read_token=?, sdl_write_token=?, sdl_account_id=? WHERE name=?",
        (merged["HEC_URL"], merged["HEC_TOKEN"], merged["HEC_INDEX"], merged["SDL_BASE_URL"],
         merged["SDL_READ_TOKEN"], merged["SDL_WRITE_TOKEN"], merged["SDL_ACCOUNT_ID"], name),
    )
    conn.commit()
    conn.close()


def capture_current(name: str | None = None) -> str:
    if not ENV_FILE or not os.path.isfile(ENV_FILE):
        raise FileNotFoundError(f"No .env found at {ENV_FILE or '(HOST_PROJECT_DIR not set)'}.")
    current = read_env_file()
    name = name or f"captured-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    add_environment(name, current)
    return name


def apply_environment(name: str) -> dict:
    if not HOST_PROJECT_DIR or not os.path.isfile(COMPOSE_FILE or ""):
        raise RuntimeError("HOST_PROJECT_DIR isn't mounted correctly -- check docker-compose.yml's "
                            "watchtower volumes.")
    conn = env_db()
    row = conn.execute("SELECT * FROM environments WHERE name = ?", (name,)).fetchone()
    conn.close()
    if row is None:
        raise NotFoundError(f"No environment named '{name}'.")
    profile = env_profile_to_dict(row)

    write_env_updates(profile)
    result = subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "--project-directory", HOST_PROJECT_DIR,
         "-f", COMPOSE_FILE, "up", "-d", "--force-recreate", "verifier", "sgcia", "log-generator"],
        capture_output=True, text=True, timeout=180,
    )
    return {
        "ok": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def delete_environment(name: str) -> None:
    conn = env_db()
    cur = conn.execute("DELETE FROM environments WHERE name = ?", (name,))
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        raise NotFoundError(f"No environment named '{name}'.")


# ─── Diagnostics ────────────────────────────────────────────────────────────

def stack_status(client) -> list[dict]:
    out = []
    for label, name in CONTAINERS.items():
        display, tagline = DISPLAY_NAMES.get(label, (label, ""))
        c = get_container(client, name)
        if c is None:
            out.append({"label": label, "name": name, "display_name": display, "tagline": tagline,
                        "found": False, "status": "not found", "health": "-", "uptime": "-"})
            continue
        status = c.status
        health = c.attrs.get("State", {}).get("Health", {}).get("Status", "none")
        started = c.attrs.get("State", {}).get("StartedAt", "")
        uptime = "-"
        try:
            started_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            delta = datetime.now(timezone.utc) - started_dt
            uptime = str(delta).split(".")[0]
        except Exception:
            pass
        out.append({"label": label, "name": name, "display_name": display, "tagline": tagline,
                    "found": True, "status": status, "health": health, "uptime": uptime})
    return out


def calc_cpu_percent(stats: dict) -> float:
    try:
        cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        sys_delta = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"]["system_cpu_usage"]
        online_cpus = stats["cpu_stats"].get("online_cpus") or len(
            stats["cpu_stats"]["cpu_usage"].get("percpu_usage", [1])
        )
        if sys_delta > 0 and cpu_delta > 0:
            return (cpu_delta / sys_delta) * online_cpus * 100.0
    except (KeyError, ZeroDivisionError, TypeError):
        pass
    return 0.0


def container_resources(client) -> list[dict]:
    out = []
    for label, name in CONTAINERS.items():
        display, _ = DISPLAY_NAMES.get(label, (label, ""))
        c = get_container(client, name)
        if c is None or c.status != "running":
            out.append({"label": label, "display_name": display, "running": False})
            continue
        stats = c.stats(stream=False)
        cpu_pct = calc_cpu_percent(stats)
        mem_usage = stats.get("memory_stats", {}).get("usage", 0)
        mem_limit = stats.get("memory_stats", {}).get("limit", 0)
        nets = stats.get("networks", {}) or {}
        rx = sum(n.get("rx_bytes", 0) for n in nets.values())
        tx = sum(n.get("tx_bytes", 0) for n in nets.values())
        out.append({
            "label": label, "display_name": display, "running": True, "cpu_pct": round(cpu_pct, 1),
            "mem_usage_mib": round(mem_usage / 1024 / 1024, 1),
            "mem_limit_mib": round(mem_limit / 1024 / 1024),
            "rx_kib": round(rx / 1024), "tx_kib": round(tx / 1024),
        })
    return out


def _configured_hosts(client) -> dict[str, str]:
    lg = get_container(client, CONTAINERS["log-generator"])
    sn = get_container(client, CONTAINERS["sgcia"])
    hosts = {}
    if sn is not None:
        hec_url = container_env(sn).get("HEC_URL", "")
        if hec_url:
            hosts["HEC_URL (sgcia)"] = hec_url
    if lg is not None:
        sdl_url = container_env(lg).get("SDL_BASE_URL", "")
        if sdl_url:
            hosts["SDL_BASE_URL (log-generator)"] = sdl_url
    return hosts


def tls_certs(client) -> list[dict]:
    out = []
    for label, url in _configured_hosts(client).items():
        host = url.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
        entry = {"label": label, "host": host}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    entry.update(ok=True, tls_version=ssock.version(),
                                 subject=subject.get("commonName", "?"),
                                 issuer=issuer.get("commonName", "?"),
                                 expires=cert.get("notAfter", "?"))
        except Exception as e:
            entry.update(ok=False, error=str(e))
        out.append(entry)
    return out


def dns_resolution(client) -> list[dict]:
    targets = ["verifier", "sgcia", "log-generator"]
    for url in _configured_hosts(client).values():
        targets.append(url.split("://", 1)[-1].split("/", 1)[0].split(":")[0])
    out = []
    for host in targets:
        try:
            infos = socket.getaddrinfo(host, None)
            ips = sorted({i[4][0] for i in infos})
            out.append({"host": host, "ok": True, "ips": ips})
        except socket.gaierror as e:
            out.append({"host": host, "ok": False, "error": str(e)})
    return out


def volume_disk() -> list[dict]:
    out = []
    for label, path in (("data/ directory", DATA_MOUNT),):
        if not os.path.isdir(path):
            out.append({"label": label, "path": path, "mounted": False})
            continue
        total = 0
        for root, _, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
        usage = shutil.disk_usage(path)
        out.append({
            "label": label, "path": path, "mounted": True,
            "contents_mib": round(total / 1024 / 1024, 2),
            "host_used_gib": round(usage.used / 1024 / 1024 / 1024, 1),
            "host_total_gib": round(usage.total / 1024 / 1024 / 1024, 1),
        })
    return out


def environment_summary() -> dict:
    current = read_env_file()
    values = {k: (redact(k, current.get(k, "")) if k in ENV_SECRET_KEYS and current.get(k) else current.get(k, ""))
              for k in MANAGED_ENV_KEYS}
    envs = list_environments()
    match = next((e["name"] for e in envs if e["matches_live"]), None)
    return {"env_file": ENV_FILE, "values": values, "matched_profile": match, "has_saved_environments": bool(envs)}


# ─── Tools ──────────────────────────────────────────────────────────────────

def logs_tail(client, label: str, n: int = 50) -> str:
    c = require_container(client, label)
    return c.logs(tail=n).decode(errors="replace")


def restart_container(client, label: str) -> None:
    c = require_container(client, label)
    c.restart(timeout=10)


def sources_destinations(client) -> dict:
    out: dict = {}
    sn = get_container(client, CONTAINERS["sgcia"])
    lg = get_container(client, CONTAINERS["log-generator"])
    if sn is not None:
        env = container_env(sn)
        out["sgcia"] = {
            "display_name": display_name("sgcia"),
            "note": "source: log-generator TCP/601, UDP/514",
            "HEC_URL": env.get("HEC_URL", ""),
            "HEC_TOKEN": redact("HEC_TOKEN", env.get("HEC_TOKEN", "")),
            "HEC_INDEX": env.get("HEC_INDEX", ""),
        }
    if lg is not None:
        env = container_env(lg)
        out["log-generator"] = {
            "display_name": display_name("log-generator"),
            "note": "direct-to-SDL EDR path",
            "SDL_BASE_URL": env.get("SDL_BASE_URL", ""),
            "SDL_WRITE_TOKEN": redact("SDL_WRITE_TOKEN", env.get("SDL_WRITE_TOKEN", "")),
            "SCENARIO_CHANCE": env.get("SCENARIO_CHANCE", ""),
            "LOG_INTERVAL_MS": env.get("LOG_INTERVAL_MS", ""),
            "LOG_BURST": env.get("LOG_BURST", ""),
        }
    return out


def proxy_connectivity(client) -> list[dict]:
    checks = [(f"{display_name('verifier')} (verifier)", "verifier", 8000)]
    for label, url in _configured_hosts(client).items():
        host = url.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
        tag = "HEC" if "HEC" in label else "SDL"
        checks.append((f"{tag} ({host})", host, 443))
    out = []
    for label, host, port in checks:
        start = time.time()
        try:
            with socket.create_connection((host, port), timeout=6):
                out.append({"label": label, "host": host, "port": port, "ok": True,
                            "ms": round((time.time() - start) * 1000)})
        except OSError as e:
            out.append({"label": label, "host": host, "port": port, "ok": False, "error": str(e)})
    return out


def source_ports(client) -> list[dict]:
    out = []
    for label, name in CONTAINERS.items():
        display, _ = DISPLAY_NAMES.get(label, (label, ""))
        c = get_container(client, name)
        if c is None:
            out.append({"label": label, "display_name": display, "ports": []})
            continue
        ports = c.attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
        parts = []
        for container_port, bindings in ports.items():
            if not bindings:
                parts.append(f"{container_port} (not published)")
                continue
            for b in bindings:
                parts.append(f"{b.get('HostIp', '0.0.0.0')}:{b.get('HostPort')} -> {container_port}")
        out.append({"label": label, "display_name": display, "ports": parts})
    return out


def sgcia_status() -> dict:
    """GET sgcia's statuscfg /status endpoint (JSON) -- see
    ../syslog-collector/otelcol/extensions/statuscfgextension/snapshot.go
    for the exact shape (receivers/pipelines/exporters, each keyed by their
    config ID). Raises OSError/socket.timeout on failure; callers decide how
    to surface that."""
    conn = http.client.HTTPConnection(SGCIA_STATUS_HOST, SGCIA_STATUS_PORT, timeout=6)
    try:
        conn.request("GET", "/status")
        resp = conn.getresponse()
        data = resp.read()
    finally:
        conn.close()
    return json.loads(data)


def syslog_stats() -> dict[str, str]:
    """Flatten sgcia's /status into simple string-valued metrics for the
    live syslog stream view. These are genuinely different metrics than
    syslog-ng's old `syslog-ng-ctl stats` CSV (sgcia has no disk-buffer
    stage the way syslog-ng did -- see sgcia/config.yaml's header comment),
    not a like-for-like renaming."""
    try:
        status = sgcia_status()
    except OSError:
        return {}
    pipeline = status.get("pipelines", {}).get("logs/syslog", {})
    exporter = status.get("exporters", {}).get("splunk_hec/datapipeline", {})
    return {
        "events_in": str(pipeline.get("events_in", 0)),
        "events_out": str(pipeline.get("events_out", 0)),
        "events_dropped": str(pipeline.get("events_dropped", 0)),
        "parse_errors": str(pipeline.get("parse_errors", 0)),
        "batches_sent": str(exporter.get("batches_sent", 0)),
        "batches_failed": str(exporter.get("batches_failed", 0)),
        "retries": str(exporter.get("retries", 0)),
    }


def syslog_test() -> dict:
    before = syslog_stats()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    msg = f"<134>1 {now} nexus-watchtower watchtower-test - WATCHTOWER - Watchtower connectivity test"
    framed = f"{len(msg.encode())} {msg}"
    with socket.create_connection(("sgcia", 601), timeout=6) as sock:
        sock.sendall(framed.encode())
    time.sleep(1)
    after = syslog_stats()
    b = int(before.get("events_in", 0) or 0)
    a = int(after.get("events_in", 0) or 0)
    return {"before": b, "after": a, "confirmed": a > b}


def list_scenarios(client) -> list[dict]:
    c = require_container(client, "log-generator")
    exit_code, output = c.exec_run(["python3", "fire_scenario.py"])
    text = output.decode(errors="replace")
    scenarios = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Usage:") or stripped.startswith("fire_scenario.py") \
                or stripped.startswith("Available scenarios"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            scenarios.append({"name": parts[0], "title": parts[1]})
    return scenarios


def fire_scenario(client, name: str) -> str:
    c = require_container(client, "log-generator")
    cmd = ["python3", "fire_scenario.py"] + ([name] if name else [])
    exit_code, output = c.exec_run(cmd)
    return output.decode(errors="replace")


def fire_category(client, letter: str) -> str:
    c = require_container(client, "log-generator")
    letter = letter.upper()
    if letter not in CATEGORY_LABELS:
        raise ValueError(f"Invalid category '{letter}'.")
    exit_code, output = c.exec_run(["python3", "fire_scenario.py", "--category", letter])
    return output.decode(errors="replace")


def fire_sources(client) -> str:
    c = require_container(client, "log-generator")
    exit_code, output = c.exec_run(["python3", "fire_sources.py"])
    return output.decode(errors="replace")
