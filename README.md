# Sigma Detection Lab

A detection-engineering portfolio: custom Sigma rules mapped to MITRE ATT&CK, each validated against real Windows attack telemetry from the [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) dataset, plus a Python harness that tests every rule against every sample.

## Workflow
For each detection I:
1. Pick an ATT&CK technique and study how it appears in Windows / Sysmon logs.
2. Write a vendor-neutral Sigma rule (`rules/`).
3. Validate it with `sigma check` and convert it to a Splunk query with `sigma convert`.
4. Test the detection logic against a real attack capture (`samples/`) to confirm it fires and stays quiet on benign events.
5. Document the rule, validation result, and false-positive profile (`docs/`).

## Detections

| # | Technique | Tactic | Severity | Rule |
|---|-----------|--------|----------|------|
| 01 | [T1033](https://attack.mitre.org/techniques/T1033/) System Owner/User Discovery | Discovery | Low | `rules/whoami_discovery.yml` |
| 02 | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) LSASS Memory | Credential Access | High | `rules/lsass_credential_dump.yml` |
| 03 | [T1059](https://attack.mitre.org/techniques/T1059/) Command and Scripting Interpreter | Execution | High | `rules/svchost_spawning_cmd.yml` |
| 04 | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Clear Windows Event Logs | Defense Evasion | High | `rules/security_log_cleared.yml` |

Full writeups for each are in `docs/`.

## Batch testing harness
`harness.py` loads every detection, scans each `.evtx` sample in `samples/`, and reports which detections fired in a single results table. This turns a set of one-off test scripts into one repeatable detection-testing tool.

Run it with:
## Tooling
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli) / pySigma for rule validation and conversion
- python-evtx for parsing the EVTX samples

## Structure
