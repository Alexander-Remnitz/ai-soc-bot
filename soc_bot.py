#!/usr/bin/env python3
"""
AI SOC Bot — triage Wazuh alerts with a local LLM (Ollama).

Pulls recent high-severity alerts from the Wazuh indexer and asks a locally
run model (via Ollama) to triage each one: what happened, how serious, whether
it looks like a false positive, and what to do next. Alert content stays inside
the local lab environment and is not sent to a third-party cloud LLM API.

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

SEVERITIES = {"Informational", "Low", "Medium", "High", "Critical"}
FALSE_POSITIVE_VALUES = {"Likely", "Unlikely"}

TRIAGE_SYSTEM = (
    "You are a Tier-1 SOC analyst. You are given ONE security alert from a "
    "Wazuh SIEM in a lab environment. Triage it concisely for a busy analyst. "
    "Return ONLY a JSON object with exactly these keys: "
    '"summary", "severity", "false_positive", "false_positive_reason", "next_step". '
    '"severity" must be one of: Informational, Low, Medium, High, Critical. '
    '"false_positive" must be Likely or Unlikely. '
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
    except requests.exceptions.RequestException as e:
        sys.exit(f"ERROR: indexer request failed: {e}")

    try:
        hits = resp.json()["hits"]["hits"]
    except (ValueError, KeyError, TypeError):
        sys.exit("ERROR: indexer returned an unexpected response format.")

    return [hit["_source"] for hit in hits if isinstance(hit, dict) and "_source" in hit]


def extract_fields(alert: dict) -> dict:
    """Pull the fields we care about out of a raw Wazuh alert safely."""
    rule = alert.get("rule", {}) or {}
    data = alert.get("data", {}) or {}
    agent = alert.get("agent", {}) or {}
    mitre = rule.get("mitre", {}) or {}
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
    """Collapse duplicate alerts into one group.

    The grouping key includes host, rule, source IP, and URL so events from
    different endpoints are not accidentally merged. Each group keeps the most
    recent representative event and a count of how many times it was seen.
    """
    groups: dict[tuple, dict] = {}
    for alert in alerts:
        f = extract_fields(alert)
        key = (f["agent"], f["rule_id"], f["srcip"], f["url"])
        if key not in groups:
            groups[key] = {"fields": f, "count": 1}
        else:
            groups[key]["count"] += 1
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


def parse_triage(raw: str) -> dict[str, str]:
    """Validate the structured JSON returned by the local LLM."""
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError("response was not valid JSON") from e

    if not isinstance(result, dict):
        raise ValueError("response JSON was not an object")

    required = {
        "summary",
        "severity",
        "false_positive",
        "false_positive_reason",
        "next_step",
    }
    if set(result) != required:
        missing = required - set(result)
        extra = set(result) - required
        details = []
        if missing:
            details.append(f"missing: {', '.join(sorted(missing))}")
        if extra:
            details.append(f"extra: {', '.join(sorted(extra))}")
        raise ValueError("unexpected fields (" + "; ".join(details) + ")")

    for key in required:
        if not isinstance(result[key], str) or not result[key].strip():
            raise ValueError(f"{key} must be a non-empty string")
        result[key] = result[key].strip()

    if result["severity"] not in SEVERITIES:
        raise ValueError("severity is outside the allowed set")
    if result["false_positive"] not in FALSE_POSITIVE_VALUES:
        raise ValueError("false_positive must be Likely or Unlikely")

    return result


def format_triage(result: dict[str, str]) -> str:
    """Render validated triage JSON into the existing human-readable format."""
    return (
        f"SUMMARY: {result['summary']}\n"
        f"SEVERITY: {result['severity']}\n"
        f"FALSE POSITIVE?: {result['false_positive']} — {result['false_positive_reason']}\n"
        f"NEXT STEP: {result['next_step']}"
    )


def triage(prompt: str) -> str:
    """Send one alert to Ollama, validate its JSON, and return formatted triage."""
    last_error = "unknown validation error"
    for _attempt in range(2):
        try:
            resp = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "system": TRIAGE_SYSTEM,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0.2},
                },
                timeout=120,
            )
            resp.raise_for_status()
            payload = resp.json()
            raw = payload.get("response", "")
            return format_triage(parse_triage(raw))
        except requests.exceptions.ConnectionError:
            sys.exit(
                f"ERROR: could not reach Ollama at {OLLAMA_URL}.\n"
                "Is the service running?  systemctl is-active ollama"
            )
        except requests.exceptions.RequestException as e:
            sys.exit(f"ERROR: Ollama request failed: {e}")
        except (ValueError, TypeError) as e:
            last_error = str(e)

    sys.exit(
        "ERROR: Ollama returned invalid structured triage twice. "
        f"Last validation error: {last_error}"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Triage Wazuh alerts with a local LLM.")
    ap.add_argument("--level", type=int, default=10, help="min rule level (default 10)")
    ap.add_argument(
        "--count",
        type=int,
        default=50,
        help="how many recent alerts to fetch before grouping (default 50)",
    )
    ap.add_argument("--save", action="store_true", help="also save a Markdown report")
    args = ap.parse_args()

    if not WAZUH_PASS:
        sys.exit("ERROR: WAZUH_PASS is empty. Copy .env.example to .env and fill it in.")

    print(f"Fetching up to {args.count} alerts with level >= {args.level} ...")
    alerts = get_alerts(args.level, args.count)
    if not alerts:
        print("No matching alerts found.")
        return

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
        print(
            f"[{i}/{len(groups)}] Rule {f['rule_id']} (lvl {f['level']}) {seen} "
            f"{f['description']}  —  triaging..."
        )
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
        with open(fname, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        print(f"\nSaved report to {fname}")


if __name__ == "__main__":
    main()
