# SOC Triage Report — sample output

Model: `llama3.2:3b` (local) · 50 alerts → 3 distinct threat(s)

This is a representative run against the [Wazuh SOC Lab](https://github.com/Alexander-Remnitz/wazuh-soc-lab).
All IPs are private-range lab addresses.

---

## Threat 1: Multiple web server 400 error codes from same source ip. (seen 45×)
- **Times seen:** 45  ·  **Rule:** 31151 (level 10)
- **Host:** mr-axe  ·  **Source IP:** 10.66.66.10

**AI triage:**

SUMMARY: Multiple web server 400 error codes from the same source IP were detected.
SEVERITY: Low — automated scanning (the "gobuster" tool appears in the raw log), not a breach.
FALSE POSITIVE?: Likely — the pattern matches a directory brute-force tool rather than a real exploit.
NEXT STEP: Confirm the source IP and block it if the scanning is unauthorized.

## Threat 2: Access attempt to known-vulnerable endpoint (diag.php) on mr-axe (seen 4×)
- **Times seen:** 4  ·  **Rule:** 100100 (level 10, custom)
- **Host:** mr-axe  ·  **Source IP:** 10.66.66.10  ·  **MITRE:** Exploit Public-Facing Application

**AI triage:**

SUMMARY: A known-vulnerable endpoint (diag.php) on mr-axe was accessed from 10.66.66.10.
SEVERITY: Medium — potential exploitation attempt; the 403 response indicates it was blocked.
FALSE POSITIVE?: Unlikely — targets a known-vulnerable endpoint with a matching MITRE technique.
NEXT STEP: Investigate the source IP to determine whether it is a legitimate user or an attacker.

## Threat 3: syslog: User missed the password more than one time
- **Times seen:** 1  ·  **Rule:** 2502 (level 10)  ·  **MITRE:** Brute Force
- **Host:** wazuh  ·  **Source IP:** 192.168.122.1

**AI triage:**

SUMMARY: Multiple failed SSH authentication attempts were logged for a user.
SEVERITY: Medium — a brute-force indicator, though no successful compromise is shown.
FALSE POSITIVE?: Likely — consistent with routine failed logins during setup/testing.
NEXT STEP: Review the source's SSH login history and confirm whether the attempts were expected.
