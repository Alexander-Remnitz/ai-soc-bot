# AI SOC Bot

A local AI assistant that triages **Wazuh SIEM alerts** with an on-device language model via **Ollama**. Alert content stays inside the local lab environment and is not sent to a third-party cloud LLM API.

It pulls recent high-severity alerts from the Wazuh indexer, groups duplicates, and asks a local model to triage each distinct threat: what happened, how serious it is, whether it is likely a false positive, and the recommended next step.

> Companion to the [Wazuh SOC Lab](https://github.com/Alexander-Remnitz/wazuh-soc-lab).
> That project **detects** attacks; this one **triages** the alerts they produce — the "automate" step of attack → detect → automate.

## Why local

Security telemetry can be sensitive. The bot uses a locally hosted Ollama model instead of a hosted LLM API, so alert content remains within the lab environment. The Wazuh indexer is reached through an SSH tunnel rather than exposing the indexer service to the network.

## How it works

```text
Wazuh indexer (alerts)              This bot                 Ollama (local LLM)
  wazuh-alerts-*    ──SSH tunnel──►  fetch → group  ──HTTP──►  llama3.2:3b (GPU)
                                     duplicates                 │
                                          ◄── JSON triage ──────┘
                                          │
                                     validate + format
                                          │
                                     terminal + Markdown report
```

1. **Fetch** — query the indexer for recent alerts at/above a severity level.
2. **Group** — collapse duplicates using host + rule + source IP + URL, so similar events from different endpoints are not accidentally merged.
3. **Triage** — send each distinct threat to the local model and request structured JSON.
4. **Validate** — require the expected fields and allowed severity/false-positive values; retry once if the model returns malformed output.
5. **Report** — print the validated result to the terminal and optionally save a timestamped Markdown report.

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

Run the unit tests with:

```bash
python -m unittest discover -s tests -v
```

See [`docs/sample-report.md`](docs/sample-report.md) for example output.

## Sample output

```text
50 alerts → 3 distinct threat(s) after grouping.

[1/3] Rule 31151 (lvl 10) (seen 45×) Multiple web server 400 error codes ...
SUMMARY: Multiple web server 400 errors from the same source IP (web scan).
SEVERITY: Low
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

## Limitations

- A small 3B model is fast and private but **not authoritative**. It is a triage assist, not a replacement for an analyst; a human stays in the loop.
- Triage quality varies by model. A larger model can provide steadier output if hardware permits.
- The Wazuh indexer currently uses a self-signed certificate and the client disables TLS certificate verification because the connection is carried through a local SSH tunnel. A production deployment should trust the Wazuh CA and enable certificate verification.
- The bot groups alerts heuristically. Host + rule + source IP + URL is safer than the original rule + source-IP key, but production correlation would normally use richer event context.

## Security

- Alert content is processed by a local Ollama model and is not sent to a hosted LLM API.
- The indexer is reached over an SSH tunnel instead of exposing port 9200 to the network.
- `.env` (holding the password) and `reports/` are gitignored and never intentionally committed.

## Live end-to-end verification

**Verified 2026-10-02.** The complete integration path was tested successfully against the live Wazuh lab:

`Wazuh indexer → SSH tunnel → alert fetch → grouping → Ollama llama3.2:3b → structured JSON validation → terminal output → Markdown report`

- Wazuh indexer returned HTTP 200 through the local SSH tunnel.
- The bot fetched 5 live level-10 alerts and grouped them into 3 distinct threats.
- Local Ollama generated triage for all 3 groups.
- Structured responses passed the bot validation path.
- A Markdown report was written successfully to `reports/`.
- Generated reports remain excluded from Git by `.gitignore`.
- The small 3B model can still produce semantically inconsistent judgments, so human review remains required.
