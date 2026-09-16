#!/usr/bin/env python3
"""
Fire superhero-themed scenarios on demand into sgcia — for testing/demoing
detections without waiting for the rare ambient SCENARIO_CHANCE roll.

Run inside the generator container:
  docker exec nexus-log-generator python3 fire_scenario.py                     # list scenarios
  docker exec nexus-log-generator python3 fire_scenario.py nexus_registry_pull # fire one (partial name ok)
  docker exec nexus-log-generator python3 fire_scenario.py cosmic_cube 5       # fire 5 times
  docker exec nexus-log-generator python3 fire_scenario.py all                 # fire every scenario once
  docker exec nexus-log-generator python3 fire_scenario.py --category A       # fire every scenario that
                                                                                       # triggers an A-category detection

Each scenario shares host/user/IP across sources so the correlation detections
light up. See WATCHTOWER_DETECTIONS.md for which scenario triggers which detection.
"""
import os
import sys
import socket
import generate_logs as g

HOST = os.getenv("SYSLOG_HOST", "sgcia")
PORT = int(os.getenv("SYSLOG_PORT", "601"))

# friendly name (sc_db_mass_extract -> "db_mass_extract") -> function
SCMAP = {(fn.__name__[3:] if fn.__name__.startswith("sc_") else fn.__name__): fn
         for fn in g.SCENARIOS}

# Detection-category letter (WATCHTOWER_DETECTIONS.md section headers) -> the
# scenario names (fire_scenario.py names, i.e. SCMAP keys) that trigger at
# least one detection in that category. Hand-maintained from the "Firing
# detections on demand" table in WATCHTOWER_DETECTIONS.md -- update both
# together if a scenario's detection mapping changes.
CATEGORY_SCENARIOS = {
    "A": {  # A1b, A2, A4, A5, A7, A8, A9 -- technique detections
        "skrull_infiltration_talos", "avengers_xmen_beacon", "gotham_wakanda_rivalry",
        "squad_doom_rivalry", "accords_breach_lateral", "nexus_registry_pull",
        "jleague_financial_audit", "banner_legal_hold", "shield_internal_watchdog",
        "multiverse_travel_anomaly", "xmen_solo_ops_sprawl", "hydra_defection",
        "hawkeye_shield_dispute",  # intentionally below A5's threshold -- see WATCHTOWER_DETECTIONS.md
    },
    "B": {"multiverse_travel_anomaly", "nexus_registry_pull"},  # A7/B1, B4 -- cross-source correlations
    "C": {  # C1-C7 -- named-signature detections
        "cosmic_cube_heist_thanos", "avengers_xmen_beacon", "gotham_wakanda_rivalry",
        "squad_doom_rivalry", "shield_internal_watchdog", "xmen_solo_ops_sprawl",
        "asgard_avengers_trust_pact", "wakanda_infra_standup", "hydra_defection",
        "civil_war_access_revocation", "shield_shutdown",
    },
    "D": {"oscorp_privesc"},               # D3 -- AWS/CloudTrail
    "E": {"accords_breach_lateral"},       # E1 -- SentinelOne EDR
    "F": {"new_recruit_onboarding", "kyle_rayner_onboarding"},  # F1 -- new-account/provisioning
    "G": {"infinity_vault_access"},        # G1 -- informational/baseline
    "H": {"multiverse_nexus_audit"},       # H1 -- cross-faction scope
}


def fire(funcs, count):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    total = 0
    for _ in range(count):
        for fn in funcs:
            title, lines = fn()
            for line in lines:
                if line is not None:  # EDR lines are ingested directly into SDL, nothing to send here
                    s.sendall(line.encode("utf-8"))
            total += len(lines)
            print(f"  fired: {title}  ({len(lines)} events)")
    s.close()
    print(f"\nSent {total} events to {HOST}:{PORT}")


def main():
    args = sys.argv[1:]
    if not args:
        print("Available scenarios:\n")
        for name, fn in SCMAP.items():
            print(f"  {name:20} {fn()[0]}")
        print("\nUsage: fire_scenario.py <name|all> [count]")
        print("       fire_scenario.py --category <A-H>   # fire every scenario mapped to that detection category")
        return

    if args[0] in ("--category", "-c"):
        if len(args) < 2:
            print(f"Usage: fire_scenario.py --category <{'|'.join(sorted(CATEGORY_SCENARIOS))}>")
            sys.exit(1)
        cat = args[1].upper()
        names = CATEGORY_SCENARIOS.get(cat)
        if not names:
            print(f"No scenarios mapped to category '{cat}'. Valid: {', '.join(sorted(CATEGORY_SCENARIOS))}")
            sys.exit(1)
        ordered = sorted(names)
        funcs = [SCMAP[n] for n in ordered if n in SCMAP]
        print(f"Firing {len(funcs)} scenario(s) for category {cat}: {', '.join(ordered)}\n")
        fire(funcs, 1)
        return

    name, count = args[0], (int(args[1]) if len(args) > 1 else 1)
    if name == "all":
        fire(list(SCMAP.values()), count)
        return

    matches = [fn for n, fn in SCMAP.items() if name.lower() in n.lower()]
    if not matches:
        print(f"No scenario matching '{name}'. Run with no args to list them.")
        sys.exit(1)
    fire(matches, count)


if __name__ == "__main__":
    main()
