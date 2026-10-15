# Detection: Windows Security Event Log Cleared

**MITRE ATT&CK:** [T1070.001 - Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
**Tactic:** Defense Evasion
**Severity:** High
**Rule:** rules/security_log_cleared.yml

## What it detects
Clearing of the Windows Security event log, recorded as Event ID 1102. Attackers clear logs to destroy evidence of their activity. The act of clearing is itself logged as 1102, so the attacker cannot wipe the log without leaving this single trace behind.

## Detection logic
Matches native Windows Security log events where EventID is 1102 in the Security channel. Unlike the Sysmon-based rules in this repo, this uses a Windows builtin log source (service: security), showing detection coverage beyond Sysmon.

## Validation
Tested against a real attack sample: DE_1102_security_log_cleared.evtx (from sbousseaden/EVTX-ATTACK-SAMPLES).

Result: 112 events scanned, 1 detection fired. The single log-clearing event was caught.

    [ALERT] Windows Security event log cleared (T1070)
            Channel:     Security
            TimeCreated: 2019-03-19 23:35:07

## Engineering note
ATT&CK is versioned. The installed pySigma dataset had renamed the relevant tactic and dropped the .001 sub-technique, so the tags were reconciled to what the validator actually accepts (attack.stealth, attack.t1070) by querying the tool directly rather than trusting the website.

## False positives
[Clearing the security log is almost never part of normal operation. The only legitimate case is an administrator deliberately clearing logs during maintenance, which is rare and should be verifiable against a change record. Because benign occurrences are so uncommon, this rule has a low false-positive risk, which is what justifies its high severity: when it fires, it is very likely a real attempt to destroy evidence.]
