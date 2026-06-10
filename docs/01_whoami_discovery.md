@'
# Detection: Whoami Execution for Account Discovery

**MITRE ATT&CK:** [T1033 - System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
**Tactic:** Discovery
**Severity:** Low
**Rule:** rules/whoami_discovery.yml

## What it detects
Execution of whoami.exe. After gaining access to a host, attackers commonly run whoami (often with /all) to enumerate the current user's privileges and group memberships before deciding their next move.

## Detection logic
Matches any process-creation event where the process image ends with \whoami.exe.
Sigma selection: Image|endswith: "\whoami.exe"
Compiled to Splunk: Image="*\\whoami.exe"

## Validation
Tested against a real attack sample: LM_wmiexec_impacket_sysmon_whoami.evtx (Impacket wmiexec lateral movement, from sbousseaden/EVTX-ATTACK-SAMPLES).

Result: 4 process-creation events scanned, 1 detection fired.

    [ALERT] whoami execution detected (T1033)
            Image:       C:\Windows\System32\whoami.exe
            CommandLine: whoami  /all
            User:        IEWIN7\IEUser

## False positives
Administrators and login scripts legitimately check user context, so on its own this is low-severity. Higher fidelity comes from correlating it with a suspicious parent process (e.g. spawned by wmiprvse.exe, indicating remote execution) or a burst of discovery commands in sequence.
'@ | Out-File -FilePath docs/01_whoami_discovery.md -Encoding utf8