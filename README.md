# AI SOC Bot

A local, private AI that triages **Wazuh SIEM alerts** using a language model
running entirely on your own machine via **Ollama** — no cloud, no API keys, no
alert data ever leaving the host.

It pulls recent high-severity alerts from the Wazuh indexer, groups duplicates,
and asks a local model to triage each distinct threat: what happened, how
serious, whether it's likely a false positive, and the recommended next step.

> Companion to the [Wazuh SOC Lab](https://github.com/Alexander-Remnitz/wazuh-soc-lab).
> That project **detects** attacks; this one **triages** the alerts they produce —
> the "automate" step of attack → detect → automate.

## Why local

Alert data is sensitive. Sending it to a hosted LLM API means shipping your
security telemetry to a third party. This bot runs the model **locally with
Ollama**, so triage happens on the same machine that holds the data — private
by design, and free to run.

## How it works

```text
Wazuh indexer (alerts)              This bot                 Ollama (local LLM)
  wazuh-alerts-*    ──SSH tunnel──►  fetch → group  ──HTTP──►  llama3.2:3b (GPU)
                                     duplicates                 │
                                          ◄── triage text ──────┘
                                          │
                                     printed report + Markdown file
```

1. **Fetch** — query the indexer for recent alerts at/above a severity level.
2. **Group** — collapse duplicates (same rule + source IP) so each threat is triaged once, with a "seen N×" count.
3. **Triage** — send each distinct threat to the local model for a structured verdict.
4. **Report** — print to the terminal and optionally save a timestamped Markdown report.

The indexer is reached over an **SSH tunnel**, so it stays bound to localhost on
the Wazuh host and is never exposed on the network — a deliberate security choice.

## Setup

Requires: a running Wazuh indexer, [Ollama](https://ollama.com) with a pulled model, Python 3.10+.

```bash
# 1. Install Ollama + a small model (example: Arch/Omarchy)
sudo pacman -S ollama-cuda          # or the official install script
sudo systemctl enable --now ollama
ollama pull llama3.2:3b

# 2. Project setup
git clone https://github.com/Alexander-Remnitz/ai-soc-bot.git
cd ai-soc-bot
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 3. Configure — copy the template and add your Wazuh admin password
cp .env.example .env
$EDITOR .env                         # set WAZUH_PASS

# 4. Open the SSH tunnel to the indexer (separate terminal, keep it open)
ssh -N -L 9200:127.0.0.1:9200 labadmin@<wazuh-host>
```

## Usage

```bash
python soc_bot.py                 # triage recent level>=10 alerts (grouped)
python soc_bot.py --level 7       # lower the severity threshold
python soc_bot.py --count 100     # fetch more alerts before grouping
python soc_bot.py --save          # also write a Markdown report to reports/
```

See [`docs/sample-report.md`](docs/sample-report.md) for example output.

## Sample output

```text
50 alerts → 3 distinct threat(s) after grouping.

[1/3] Rule 31151 (lvl 10) (seen 45×) Multiple web server 400 error codes ...
SUMMARY: Multiple web server 400 errors from the same source IP (web scan).
SEVERITY: Low — automated scanning (gobuster seen in the log), not a breach.
FALSE POSITIVE?: Likely — signature of a directory brute-force tool.
NEXT STEP: Confirm the source IP and block it if unauthorized.
```

## Configuration (`.env`)

| Variable | Purpose | Default |
|---|---|---|
| `WAZUH_INDEXER_URL` | Indexer URL (via the tunnel) | `https://127.0.0.1:9200` |
| `WAZUH_USER` | Indexer user | `admin` |
| `WAZUH_PASS` | Indexer password | *(required, in .env)* |
| `OLLAMA_URL` | Local Ollama endpoint | `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | Model to use | `llama3.2:3b` |

## Limitations (honest notes)

- A small 3B model is fast and private but **not authoritative** — it occasionally
  disagrees with itself on "false positive". It's a triage **assist**, not a
  replacement for an analyst. A human stays in the loop.
- Triage quality scales with model size; a larger model (if VRAM allows) gives
  steadier verdicts. The model is a one-line change in `.env`.

## Security

- No alert data leaves the machine — the model runs locally.
- The indexer is reached over an SSH tunnel, not exposed on the network.
- `.env` (holding the password) and `reports/` are gitignored and never committed.
