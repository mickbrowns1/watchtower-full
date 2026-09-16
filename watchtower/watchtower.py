#!/usr/bin/env python3
"""
Watchtower — site diagnostics & remediation for the Watchtower Docker
Compose stack (verifier, sgcia, log-generator).

This is a thin rich-rendering layer over core.py, which also backs the web
dashboard (web.py) -- both share the exact same logic, never duplicated.

Run via `docker exec -it nexus-watchtower python3 watchtower.py`
(the container's main process runs the web dashboard instead -- see
Dockerfile/README for the web UI, which is the primary way to use Watchtower
now).
"""
from __future__ import annotations

import subprocess
import sys
import time
from datetime import datetime, timezone

import pyfiglet
from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

import core

console = Console()

RED = "bold cyan"
ACCENT = "bright_cyan"
GOLD = "bold #9fb3c0"
DIM = "grey62"
MIC = "🛡"


def docker_client():
    try:
        return core.docker_client()
    except Exception as e:
        console.print(f"[red]Could not connect to the Docker socket: {e}[/red]")
        console.print("[dim]Is /var/run/docker.sock mounted into this container?[/dim]")
        sys.exit(1)


# ─── Banner / menu chrome ───────────────────────────────────────────────────

def show_banner() -> None:
    console.clear()
    art = pyfiglet.figlet_format("WATCHTOWER", font="ansi_shadow").rstrip("\n")
    body = Text(art, style=RED)
    sound_art = Text(pyfiglet.figlet_format("OPS CONSOLE", font="small").rstrip("\n"), style=GOLD)
    divider = Text("─" * 62, style="grey42")
    sub = Text("Site diagnostics & remediation  ·  Docker Compose  ·  SentinelOne", style=DIM)
    version = Text.from_markup(f"[{ACCENT}]{MIC} v1.0[/{ACCENT}]")
    panel = Panel(
        Group(Align.center(body), Align.center(sound_art), Text(""), divider,
              Align.center(sub), Align.center(version)),
        border_style=RED,
        box=box.ROUNDED,
        padding=(1, 2),
    )
    console.print(panel)
    console.print()
    console.print("[grey62]Press Enter to begin...[/grey62]", end="")
    input()


def status_style(status: str) -> str:
    return {"running": "bold green", "exited": "bold red", "restarting": "bold yellow"}.get(status, "yellow")


def name_cell(row: dict) -> str:
    return f"{row.get('display_name', row['label'])} [{DIM}]({row['label']})[/{DIM}]"


def stack_status_table(client) -> Table:
    table = Table(box=box.SIMPLE, show_header=True, header_style=DIM, padding=(0, 1))
    table.add_column("Container")
    table.add_column("Status")
    table.add_column("Health")
    table.add_column("Uptime")
    for row in core.stack_status(client):
        if not row["found"]:
            table.add_row(name_cell(row), "[red]not found[/red]", "-", "-")
            continue
        health_style = {"healthy": "bold green", "unhealthy": "bold red"}.get(row["health"], DIM)
        table.add_row(
            name_cell(row),
            f"[{status_style(row['status'])}]{row['status']}[/{status_style(row['status'])}]",
            f"[{health_style}]{row['health']}[/{health_style}]",
            row["uptime"],
        )
    return table


MENU_DIAGNOSTICS = [
    ("1", "Full diagnostic scan"),
    ("2", "Service health"),
    ("3", "Container & resources"),
    ("4", "TLS & certificates"),
    ("5", "DNS resolution"),
    ("6", "Volume & disk"),
    ("7", "Environment summary"),
]
MENU_TOOLS = [
    ("8", "Logs (combined/service)"),
    ("9", "Service debugger (interactive shell)"),
    ("10", "Restart service/container"),
    ("11", "Sources & destinations"),
    ("12", "Proxy & connectivity"),
    ("13", "Source ports"),
    ("14", "Signal Check (syslog tester)"),
    ("15", "Syslog stream (continuous)"),
    ("16", "Fire a scenario"),
    ("17", "Fire scenarios by category (A-H)"),
    ("18", "Send one test log per source"),
    ("19", "Field Outposts (SDL/HEC profiles)"),
]


def show_menu(client) -> str:
    console.clear()
    header = Text.assemble(
        (f"WATCHTOWER ", RED), (f"· OPS CONSOLE v1.0    ", GOLD), (MIC, ACCENT),
    )
    console.print(header)
    console.print(Text("Docker Compose site diagnostics  ·  web dashboard also available (see README)", style=DIM))
    console.print()
    console.print(stack_status_table(client))
    console.print()

    menu = Table.grid(padding=(0, 4))
    menu.add_column()
    menu.add_column()
    console.print(Text("Diagnostics", style=RED))
    rows = list(zip(MENU_DIAGNOSTICS[0::2], MENU_DIAGNOSTICS[1::2] + [None]))
    for left, right in rows:
        l = f"  {left[0]}) {left[1]}"
        r = f"{right[0]}) {right[1]}" if right else ""
        menu.add_row(l, r)
    console.print(menu)
    console.print()
    console.print(Text("Tools", style=RED))
    menu2 = Table.grid(padding=(0, 4))
    menu2.add_column()
    menu2.add_column()
    rows2 = list(zip(MENU_TOOLS[0::2], MENU_TOOLS[1::2] + [None]))
    for left, right in rows2:
        l = f"  {left[0]}) {left[1]}"
        r = f"{right[0]}) {right[1]}" if right else ""
        menu2.add_row(l, r)
    console.print(menu2)
    console.print()
    console.print("  0) Exit")
    console.print()
    return console.input(f"[{ACCENT}]Choose [0-19]: [/{ACCENT}]").strip()


def pause() -> None:
    console.print()
    console.input("[grey62]Press Enter to return to menu...[/grey62]")


def pick_container(prompt: str = "Container") -> str | None:
    console.print()
    for i, label in enumerate(core.CONTAINERS, start=1):
        console.print(f"  {i}) {core.display_name(label)} [{DIM}]({label})[/{DIM}]")
    choice = console.input(f"{prompt} [1-{len(core.CONTAINERS)}]: ").strip()
    labels = list(core.CONTAINERS.keys())
    if choice.isdigit() and 1 <= int(choice) <= len(labels):
        return labels[int(choice) - 1]
    console.print("[red]Invalid choice.[/red]")
    return None


# ─── Diagnostics ────────────────────────────────────────────────────────────

def d_service_health(client) -> None:
    console.rule("[red]Service health[/red]")
    console.print(stack_status_table(client))


def d_container_resources(client) -> None:
    console.rule("[red]Container & resources[/red]")
    table = Table(box=box.SIMPLE, header_style=DIM)
    table.add_column("Container")
    table.add_column("CPU %")
    table.add_column("Mem usage")
    table.add_column("Mem limit")
    table.add_column("Net I/O")
    for row in core.container_resources(client):
        if not row["running"]:
            table.add_row(name_cell(row), "-", "-", "-", "-")
            continue
        table.add_row(
            name_cell(row), f"{row['cpu_pct']:.1f}%",
            f"{row['mem_usage_mib']:.1f} MiB", f"{row['mem_limit_mib']} MiB",
            f"↓{row['rx_kib']} KiB / ↑{row['tx_kib']} KiB",
        )
    console.print(table)


def d_tls_certs(client) -> None:
    console.rule("[red]TLS & certificates[/red]")
    results = core.tls_certs(client)
    if not results:
        console.print("[yellow]No HEC_URL/SDL_BASE_URL configured to check.[/yellow]")
        return
    for r in results:
        console.print(f"\n[bold]{r['label']}[/bold]: {r['host']}")
        if r.get("ok"):
            console.print(f"  [green]TLS handshake OK[/green] ({r['tls_version']})")
            console.print(f"  Subject: {r['subject']}")
            console.print(f"  Issuer:  {r['issuer']}")
            console.print(f"  Expires: {r['expires']}")
        else:
            console.print(f"  [red]TLS check failed: {r['error']}[/red]")


def d_dns_resolution(client) -> None:
    console.rule("[red]DNS resolution[/red]")
    for r in core.dns_resolution(client):
        if r["ok"]:
            console.print(f"  [green]OK[/green]  {r['host']:45} -> {', '.join(r['ips'])}")
        else:
            console.print(f"  [red]FAIL[/red] {r['host']:45} -> {r['error']}")


def d_volume_disk() -> None:
    console.rule("[red]Volume & disk[/red]")
    for r in core.volume_disk():
        if not r["mounted"]:
            console.print(f"  [yellow]{r['label']} not mounted at {r['path']}[/yellow]")
            continue
        console.print(
            f"  {r['label']:22} contents: {r['contents_mib']:.2f} MiB   "
            f"host filesystem: {r['host_used_gib']:.1f}/{r['host_total_gib']:.1f} GiB used"
        )


def d_environment_summary() -> None:
    console.rule("[red]Environment summary[/red]")
    if not core.ENV_FILE:
        console.print("[red]HOST_PROJECT_DIR isn't set -- can't read the live .env from here.[/red]")
        return
    summary = core.environment_summary()
    if not any(summary["values"].values()):
        console.print(f"[yellow]No .env found at {summary['env_file']}, or it has none of the managed keys set.[/yellow]")
        return
    table = Table(box=box.SIMPLE, header_style=DIM)
    table.add_column("Key")
    table.add_column("Value")
    for key, value in summary["values"].items():
        table.add_row(key, value or "[dim](not set)[/dim]")
    console.print(table)
    if summary["matched_profile"]:
        console.print(f"\nMatches saved environment: [green]{summary['matched_profile']}[/green]")
    elif summary["has_saved_environments"]:
        console.print("\n[yellow]Live .env doesn't match any saved environment.[/yellow] "
                       "Use Environments -> \"Capture current\" to save it.")
    else:
        console.print("\n[dim]No saved environments yet -- see the Environments tool.[/dim]")


def d_full_scan(client) -> None:
    d_service_health(client)
    console.print()
    d_container_resources(client)
    console.print()
    d_tls_certs(client)
    console.print()
    d_dns_resolution(client)
    console.print()
    d_volume_disk()
    console.print()
    d_environment_summary()


# ─── Tools ──────────────────────────────────────────────────────────────────

def t_logs(client) -> None:
    console.rule("[red]Logs[/red]")
    label = pick_container()
    if label is None:
        return
    n = console.input("How many lines? [50]: ").strip() or "50"
    console.rule(f"{label} — last {n} lines")
    try:
        console.print(core.logs_tail(client, label, int(n)))
    except core.NotFoundError as e:
        console.print(f"[red]{e}[/red]")


def t_service_debugger(client) -> None:
    console.rule("[red]Service debugger[/red]")
    label = pick_container("Open an interactive shell in")
    if label is None:
        return
    name = core.CONTAINERS[label]
    console.print(f"[dim]Launching interactive shell in {name} — type 'exit' to return.[/dim]")
    console.print()
    try:
        subprocess.run(["docker", "exec", "-it", name, "sh"])
    except FileNotFoundError:
        console.print("[red]docker CLI not found in this image.[/red]")


def t_restart(client) -> None:
    console.rule("[red]Restart service/container[/red]")
    label = pick_container("Restart")
    if label is None:
        return
    confirm = console.input(f"Restart [bold]{core.display_name(label)} ({core.CONTAINERS[label]})[/bold]? [y/N]: ").strip().lower()
    if confirm != "y":
        console.print("[dim]Cancelled.[/dim]")
        return
    try:
        with console.status(f"Restarting {core.display_name(label)}..."):
            core.restart_container(client, label)
        console.print("[green]Restarted.[/green]")
    except core.NotFoundError as e:
        console.print(f"[red]{e}[/red]")


def t_sources_destinations(client) -> None:
    console.rule("[red]Sources & destinations[/red]")
    data = core.sources_destinations(client)
    if "sgcia" in data:
        d = data["sgcia"]
        console.print(f"[bold]{d['display_name']}[/bold] [{DIM}](sgcia — {d['note']})[/{DIM}]")
        console.print(f"  HEC_URL:    {d['HEC_URL'] or '(not set)'}")
        console.print(f"  HEC_TOKEN:  {d['HEC_TOKEN'] or '(not set)'}")
        console.print(f"  HEC_INDEX:  {d['HEC_INDEX'] or '(not set)'}")
    if "log-generator" in data:
        d = data["log-generator"]
        console.print(f"\n[bold]{d['display_name']}[/bold] [{DIM}](log-generator — {d['note']})[/{DIM}]")
        console.print(f"  SDL_BASE_URL:    {d['SDL_BASE_URL'] or '(not set)'}")
        console.print(f"  SDL_WRITE_TOKEN: {d['SDL_WRITE_TOKEN'] or '(not set)'}")
        console.print(f"  SCENARIO_CHANCE: {d['SCENARIO_CHANCE'] or '(default)'}")
        console.print(f"  LOG_INTERVAL_MS: {d['LOG_INTERVAL_MS'] or '(default)'}")
        console.print(f"  LOG_BURST:       {d['LOG_BURST'] or '(default)'}")


def t_proxy_connectivity(client) -> None:
    console.rule("[red]Proxy & connectivity[/red]")
    for r in core.proxy_connectivity(client):
        if r["ok"]:
            console.print(f"  [green]OK[/green]  {r['label']:30} {r['host']}:{r['port']}  ({r['ms']} ms)")
        else:
            console.print(f"  [red]FAIL[/red] {r['label']:30} {r['host']}:{r['port']}  {r['error']}")


def t_source_ports(client) -> None:
    console.rule("[red]Source ports[/red]")
    table = Table(box=box.SIMPLE, header_style=DIM)
    table.add_column("Container")
    table.add_column("Published ports")
    for r in core.source_ports(client):
        table.add_row(name_cell(r), "\n".join(r["ports"]) if r["ports"] else "(none)")
    console.print(table)


def t_syslog_tester(client) -> None:
    console.rule("[red]Signal Check (syslog tester)[/red]")
    try:
        result = core.syslog_test()
    except OSError as e:
        console.print(f"[red]Failed to send test message: {e}[/red]")
        return
    console.print("[green]Test message sent to sgcia:601[/green]")
    if result["confirmed"]:
        console.print(f"[green]Confirmed[/green] — logs/syslog pipeline events_in "
                       f"{result['before']} -> {result['after']}")
    else:
        console.print(f"[yellow]No change in events_in "
                       f"({result['before']} -> {result['after']}) — check sgcia logs.[/yellow]")


def t_syslog_stream(client) -> None:
    console.rule("[red]Syslog stream (continuous)[/red]")
    console.print("[dim]Polling sgcia's /status every 2s. Ctrl-C to stop.[/dim]\n")

    def render():
        stats = core.syslog_stats()
        table = Table(box=box.SIMPLE, header_style=DIM)
        table.add_column("Metric")
        table.add_column("Value")
        for k in ("events_in", "events_out", "events_dropped", "parse_errors", "batches_sent", "batches_failed", "retries"):
            table.add_row(k, stats.get(k, "-"))
        return table

    try:
        with Live(render(), refresh_per_second=1, console=console) as live:
            while True:
                time.sleep(2)
                live.update(render())
    except KeyboardInterrupt:
        pass


def t_fire_scenario(client) -> None:
    console.rule("[red]Fire a scenario[/red]")
    name = console.input("Scenario name (partial OK, or 'all', blank to list): ").strip()
    try:
        console.print(core.fire_scenario(client, name))
    except core.NotFoundError as e:
        console.print(f"[red]{e}[/red]")


def t_fire_category(client) -> None:
    console.rule("[red]Fire scenarios by detection category[/red]")
    for letter, label in core.CATEGORY_LABELS.items():
        console.print(f"  {letter}) {label}")
    cat = console.input(f"Category [{'/'.join(core.CATEGORY_LABELS)}]: ").strip().upper()
    try:
        console.print(core.fire_category(client, cat))
    except (core.NotFoundError, ValueError) as e:
        console.print(f"[red]{e}[/red]")


def t_fire_sources(client) -> None:
    console.rule("[red]Send one test log per source[/red]")
    try:
        console.print(core.fire_sources(client))
    except core.NotFoundError as e:
        console.print(f"[red]{e}[/red]")


# ─── Environments submenu ───────────────────────────────────────────────────

def e_list_environments() -> None:
    console.rule("[red]Field outposts (saved environments)[/red]")
    envs = core.list_environments()
    if not envs:
        console.print("[yellow]No outposts registered yet.[/yellow] Use "
                       "\"Snapshot current config\" or \"Register outpost\" to create one.")
        return
    table = Table(box=box.SIMPLE, header_style=DIM)
    table.add_column("Name")
    table.add_column("SDL_BASE_URL")
    table.add_column("HEC_INDEX")
    table.add_column("Matches live .env?")
    for e in envs:
        table.add_row(
            e["name"], e["values"]["SDL_BASE_URL"] or "(not set)", e["values"]["HEC_INDEX"] or "(not set)",
            "[green]yes[/green]" if e["matches_live"] else "",
        )
    console.print(table)


def _prompt_environment_fields(defaults: dict[str, str] | None = None) -> dict[str, str]:
    defaults = defaults or {}
    out = {}
    for key, label in [
        ("HEC_URL", "HEC_URL (DataPipeline HTTP Event Collector URL)"),
        ("HEC_INDEX", "HEC_INDEX"),
        ("SDL_BASE_URL", "SDL_BASE_URL (SDL/XDR host, e.g. https://xdr.us1.sentinelone.net)"),
        ("SDL_ACCOUNT_ID", "SDL_ACCOUNT_ID"),
    ]:
        out[key] = console.input(f"{label} [{defaults.get(key, '') or 'blank'}]: ").strip() or defaults.get(key, "")
    for key, label in [
        ("HEC_TOKEN", "HEC_TOKEN"),
        ("SDL_READ_TOKEN", "SDL_READ_TOKEN"),
        ("SDL_WRITE_TOKEN", "SDL_WRITE_TOKEN"),
    ]:
        has_default = bool(defaults.get(key))
        hint = " [dim](Enter to keep current)[/dim]" if has_default else ""
        val = Prompt.ask(f"{label}{hint}", password=True, default="", show_default=False)
        out[key] = val or defaults.get(key, "")
    return out


def e_add_environment() -> None:
    console.rule("[red]Register outpost (add environment)[/red]")
    name = console.input("Deal name: ").strip()
    if not name:
        console.print("[red]Name required.[/red]")
        return
    fields = _prompt_environment_fields()
    try:
        core.add_environment(name, fields)
        console.print(f"[green]Signed '{name}'.[/green]")
    except ValueError as e:
        console.print(f"[red]{e}[/red]")


def e_capture_current() -> None:
    console.rule("[red]Snapshot current config (capture current .env)[/red]")
    default_name = f"captured-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    name = console.input(f"Save current .env as deal named [{default_name}]: ").strip() or default_name
    try:
        saved = core.capture_current(name)
        console.print(f"[green]Snapshotted live .env as '{saved}'.[/green]")
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]{e}[/red]")


def e_apply_environment() -> None:
    console.rule("[red]Activate outpost (apply — rewrites .env, recreates containers)[/red]")
    envs = core.list_environments()
    if not envs:
        console.print("[yellow]No outposts registered yet. Snapshot or register one first.[/yellow]")
        return
    for i, e in enumerate(envs, start=1):
        console.print(f"  {i}) {e['name']}")
    choice = console.input(f"Activate which outpost [1-{len(envs)}]? ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(envs)):
        console.print("[red]Invalid choice.[/red]")
        return
    env = envs[int(choice) - 1]

    console.print(f"\n[bold]About to ink '{env['name']}':[/bold]")
    for k, v in env["values"].items():
        console.print(f"  {k:16} {v or '(blank)'}")
    console.print("\n[yellow]This rewrites .env and recreates verifier, sgcia, and "
                  "log-generator with these values. Ambient traffic will briefly pause.[/yellow]")
    confirm = console.input("Type 'ink' to continue: ").strip()
    if confirm != "ink":
        console.print("[dim]Cancelled.[/dim]")
        return

    console.print("[dim]Wrote .env. Recreating containers via docker compose...[/dim]")
    try:
        result = core.apply_environment(env["name"])
        console.print(result["stdout"])
        if not result["ok"]:
            console.print(f"[red]docker compose exited {result['returncode']}:[/red]\n{result['stderr']}")
        else:
            console.print(f"[green]Activated '{env['name']}'. Stack recreated with new values.[/green]")
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
    except FileNotFoundError:
        console.print("[red]docker compose plugin not found in this image.[/red]")
    except subprocess.TimeoutExpired:
        console.print("[red]docker compose timed out after 180s.[/red]")


def e_edit_environment() -> None:
    console.rule("[red]Reconfigure an outpost (edit)[/red]")
    envs = core.list_environments()
    if not envs:
        console.print("[yellow]No deals signed yet.[/yellow]")
        return
    for i, e in enumerate(envs, start=1):
        console.print(f"  {i}) {e['name']}")
    choice = console.input(f"Reconfigure which outpost [1-{len(envs)}]? ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(envs)):
        console.print("[red]Invalid choice.[/red]")
        return
    name = envs[int(choice) - 1]["name"]
    raw = core.get_environment(name)
    fields = _prompt_environment_fields(defaults=raw)
    core.update_environment(name, fields)
    console.print(f"[green]Reconfigured '{name}'.[/green] Activate it to actually push these values live.")


def e_delete_environment() -> None:
    console.rule("[red]Decommission an outpost (delete)[/red]")
    envs = core.list_environments()
    if not envs:
        console.print("[yellow]No deals signed yet.[/yellow]")
        return
    for i, e in enumerate(envs, start=1):
        console.print(f"  {i}) {e['name']}")
    choice = console.input(f"Decommission which outpost [1-{len(envs)}]? ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(envs):
        core.delete_environment(envs[int(choice) - 1]["name"])
        console.print(f"[green]Dropped '{envs[int(choice) - 1]['name']}'.[/green]")
    else:
        console.print("[red]Invalid choice.[/red]")


def t_environments(client) -> None:
    while True:
        console.rule("[red]Field Outposts — SDL/HEC profiles[/red]")
        console.print("  1) List registered outposts")
        console.print("  2) Register outpost (add environment)")
        console.print("  3) Snapshot current config (capture current .env)")
        console.print("  4) Activate outpost (apply — rewrites .env, recreates containers)")
        console.print("  5) Decommission an outpost (delete)")
        console.print("  6) Reconfigure an outpost (edit)")
        console.print("  0) Back to main menu")
        choice = console.input(f"[{ACCENT}]Choose [0-6]: [/{ACCENT}]").strip()
        if choice == "0":
            return
        elif choice == "1":
            e_list_environments()
        elif choice == "2":
            e_add_environment()
        elif choice == "3":
            e_capture_current()
        elif choice == "4":
            e_apply_environment()
        elif choice == "5":
            e_delete_environment()
        elif choice == "6":
            e_edit_environment()
        else:
            console.print("[red]Invalid choice.[/red]")
        console.print()
        console.input("[grey62]Press Enter to continue...[/grey62]")


DISPATCH = {
    "1": lambda c: d_full_scan(c),
    "2": lambda c: d_service_health(c),
    "3": lambda c: d_container_resources(c),
    "4": lambda c: d_tls_certs(c),
    "5": lambda c: d_dns_resolution(c),
    "6": lambda c: d_volume_disk(),
    "7": lambda c: d_environment_summary(),
    "8": lambda c: t_logs(c),
    "9": lambda c: t_service_debugger(c),
    "10": lambda c: t_restart(c),
    "11": lambda c: t_sources_destinations(c),
    "12": lambda c: t_proxy_connectivity(c),
    "13": lambda c: t_source_ports(c),
    "14": lambda c: t_syslog_tester(c),
    "15": lambda c: t_syslog_stream(c),
    "16": lambda c: t_fire_scenario(c),
    "17": lambda c: t_fire_category(c),
    "18": lambda c: t_fire_sources(c),
    "19": lambda c: t_environments(c),
}

# Choices that already manage their own "press enter to continue" / return
# flow, so main()'s generic pause() after dispatch would be redundant.
SELF_PACED_CHOICES = {"9", "19"}  # service debugger, environments submenu


def main() -> None:
    show_banner()
    client = docker_client()
    while True:
        choice = show_menu(client)
        if choice == "0":
            console.print("\n[dim]Goodbye.[/dim]")
            return
        handler = DISPATCH.get(choice)
        if handler is None:
            console.print("[red]Invalid choice.[/red]")
            time.sleep(1)
            continue
        console.print()
        try:
            handler(client)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        if choice not in SELF_PACED_CHOICES:
            pause()


if __name__ == "__main__":
    main()
