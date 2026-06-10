# Sigma Detection Lab

A small detection-engineering portfolio: custom Sigma rules mapped to MITRE ATT&CK, each validated against real Windows attack telemetry from the [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) dataset.

## Workflow
For each detection I:
1. Pick an ATT&CK technique and study how it appears in Windows/Sysmon logs.
2. Write a vendor-neutral Sigma rule (`rules/`).
3. Validate it with `sigma check` and convert it to a Splunk query with `sigma convert`.
4. Test the detection logic against a real attack capture (`samples/`) to confirm it fires.
5. Document the rule, validation result, and false-positive profile (`docs/`).

## Detections

| # | Technique | Tactic | Severity | Rule |
|---|-----------|--------|----------|------|
| 01 | [T1033](https://attack.mitre.org/techniques/T1033/) System Owner/User Discovery | Discovery | Low | `rules/whoami_discovery.yml` |
| 02 | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) LSASS Memory | Credential Access | High | `rules/lsass_credential_dump.yml` |

Full writeups for each are in `docs/`.

## Tooling
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli) / pySigma for rule validation and conversion
- python-evtx for parsing the EVTX samples

## Structure
