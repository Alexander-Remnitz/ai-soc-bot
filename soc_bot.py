#!/usr/bin/env python3
"""
AI SOC Bot — triage Wazuh alerts with a local LLM (Ollama).

Pulls recent high-severity alerts from the Wazuh indexer and asks a locally
run model (via Ollama) to triage each one: what happened, how serious, whether
it looks like a false positive, and what to do next. Everything runs locally —
no alert data leaves the machine.

Usage:
    python soc_bot.py                 # triage recent level>=10 alerts
    python soc_bot.py --level 7       # lower the severity threshold
    python soc_bot.py --count 5       # how many alerts to triage
    python soc_bot.py --save          # also write a Markdown report to reports/
"""

import argparse
import datetime as dt
import json
import os
import sys

import requests
import urllib3
from dotenv import load_dotenv

# The indexer uses a self-signed cert; we reach it over a local SSH tunnel,
# so we disable cert verification and silence the resulting warning.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200")
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASS = os.getenv("WAZUH_PASS", "")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

TRIAGE_SYSTEM = (
    "You are a Tier-1 SOC analyst. You are given ONE security alert from a "
    "Wazuh SIEM in a lab environment. Triage it concisely for a busy analyst. "
    "Answer in exactly these four short sections, nothing else:\n"
    "SUMMARY: one sentence — what happened.\n"
    "SEVERITY: one of [Informational, Low, Medium, High, Critical] + a few words why.\n"
    "FALSE POSITIVE?: Likely / Unlikely + a few words why.\n"
    "NEXT STEP: one concrete action the analyst should take.\n"
    "Do not invent details that are not in the alert."
)


def get_alerts(level: int, count: int) -> list[dict]:
    """Query the Wazuh indexer for the most recent alerts at/above `level`."""
    query = {
        "size": count,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"rule.level": {"gte": level}}},
    }
    url = f"{INDEXER_URL}/wazuh-alerts-*/_search"
    try:
        resp = requests.get(
            url,
            auth=(WAZUH_USER, WAZUH_PASS),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        sys.exit(
            "ERROR: could not reach the indexer at "
            f"{INDEXER_URL}.\nIs the SSH tunnel open?  "
            "ssh -N -L 9200:127.0.0.1:9200 labadmin@192.168.122.123"
        )
    except requests.exceptions.HTTPError as e:
        if resp.status_code == 401:
            sys.exit("ERROR: indexer auth failed (401). Check WAZUH_PASS in .env.")
        sys.exit(f"ERROR: indexer returned {resp.status_code}: {e}")

    return [hit["_source"] for hit in resp.json()["hits"]["hits"]]


def extract_fields(alert: dict) -> dict:
    """Pull the fields we care about out of a raw Wazuh alert (safely)."""
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    agent = alert.get("agent", {})
    mitre = rule.get("mitre", {})
    return {
        "time": alert.get("timestamp", "?"),
        "agent": agent.get("name", "?"),
        "rule_id": rule.get("id", "?"),
        "level": rule.get("level", "?"),
        "description": rule.get("description", "?"),
        "srcip": data.get("srcip", "-"),
        "url": data.get("url", "-"),
        "mitre": ", ".join(mitre.get("technique", []) or []) or "-",
        "full_log": (alert.get("full_log", "") or "")[:300],
    }


def group_alerts(alerts: list[dict]) -> list[dict]:
    """Collapse duplicate alerts (same rule + source IP) into one group.

    Returns a list of groups, each the most recent alert of its kind plus a
    `count` of how many times it was seen. Ordered by count (noisiest first).
    """
    groups: dict[tuple, dict] = {}
    for alert in alerts:
        f = extract_fields(alert)
        key = (f["rule_id"], f["srcip"])
        if key not in groups:
            groups[key] = {"fields": f, "count": 1}
        else:
            groups[key]["count"] += 1
            # keep the most recent timestamp as the representative one
            if f["time"] > groups[key]["fields"]["time"]:
                groups[key]["fields"] = f
    return sorted(groups.values(), key=lambda g: g["count"], reverse=True)


def build_prompt(f: dict) -> str:
    """Turn the extracted fields into a compact prompt for the model."""
    return (
        f"ALERT\n"
        f"- Time: {f['time']}\n"
        f"- Agent (host): {f['agent']}\n"
        f"- Rule ID: {f['rule_id']} (level {f['level']})\n"
        f"- Description: {f['description']}\n"
        f"- Source IP: {f['srcip']}\n"
        f"- URL: {f['url']}\n"
        f"- MITRE technique: {f['mitre']}\n"
        f"- Raw log: {f['full_log']}\n"
    )


def triage(prompt: str) -> str:
    """Send one alert to Ollama and return the model's triage text."""
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "system": TRIAGE_SYSTEM,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2},
            },
            timeout=120,
        )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        sys.exit(
            f"ERROR: could not reach Ollama at {OLLAMA_URL}.\n"
            "Is the service running?  systemctl is-active ollama"
        )
    return resp.json().get("response", "").strip()


def main() -> None:
    ap = argparse.ArgumentParser(description="Triage Wazuh alerts with a local LLM.")
    ap.add_argument("--level", type=int, default=10, help="min rule level (default 10)")
    ap.add_argument("--count", type=int, default=50,
                    help="how many recent alerts to fetch before grouping (default 50)")
    ap.add_argument("--save", action="store_true", help="also save a Markdown report")
    args = ap.parse_args()

    if not WAZUH_PASS:
        sys.exit("ERROR: WAZUH_PASS is empty. Copy .env.example to .env and fill it in.")

    print(f"Fetching up to {args.count} alerts with level >= {args.level} ...")
    alerts = get_alerts(args.level, args.count)
    if not alerts:
        print("No matching alerts found.")
        return

    # Collapse duplicates (same rule + source IP) so each threat is triaged once.
    groups = group_alerts(alerts)
    print(f"{len(alerts)} alerts → {len(groups)} distinct threat(s) after grouping.\n")

    lines: list[str] = []
    lines.append(f"# SOC Triage Report — {dt.datetime.now():%Y-%m-%d %H:%M}\n")
    lines.append(
        f"Model: `{OLLAMA_MODEL}` (local) · {len(alerts)} alerts → "
        f"{len(groups)} distinct threat(s)\n"
    )

    for i, g in enumerate(groups, 1):
        f = g["fields"]
        seen = f"(seen {g['count']}×)" if g["count"] > 1 else ""
        print(f"[{i}/{len(groups)}] Rule {f['rule_id']} (lvl {f['level']}) {seen} "
              f"{f['description']}  —  triaging...")
        verdict = triage(build_prompt(f))

        block = (
            f"\n## Threat {i}: {f['description']} {seen}\n"
            f"- **Times seen:** {g['count']}  ·  **Most recent:** {f['time']}\n"
            f"- **Host:** {f['agent']}  ·  **Source IP:** {f['srcip']}\n"
            f"- **Rule:** {f['rule_id']} (level {f['level']})  ·  **MITRE:** {f['mitre']}\n\n"
            f"**AI triage:**\n\n{verdict}\n"
        )
        lines.append(block)
        print(verdict)
        print("-" * 70)

    if args.save:
        os.makedirs("reports", exist_ok=True)
        fname = f"reports/triage-{dt.datetime.now():%Y%m%d-%H%M%S}.md"
        with open(fname, "w") as fh:
            fh.write("\n".join(lines))
        print(f"\nSaved report to {fname}")


if __name__ == "__main__":
    main()
