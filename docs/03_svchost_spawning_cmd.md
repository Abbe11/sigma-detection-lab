# Detection: cmd.exe Spawned by svchost.exe

**MITRE ATT&CK:** [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
**Tactic:** Execution
**Severity:** High
**Rule:** rules/svchost_spawning_cmd.yml

## What it detects
cmd.exe launched with svchost.exe as its parent process. svchost.exe runs background Windows services and has no legitimate reason to open a command shell. Attackers establishing a reverse shell or running post-exploitation commands often produce this exact parent-child pairing.

## Detection logic
Matches Sysmon Event ID 1 (ProcessCreation) where BOTH conditions are true together: ParentImage ends with \svchost.exe AND Image ends with \cmd.exe. Requiring both is essential. Matching svchost as a parent alone is meaningless (it parents many things legitimately), and matching cmd.exe alone would flag every command prompt. Only the combination isolates the attack.

## Validation
Tested against a real attack sample: revshell_cmd_svchost_sysmon_1.evtx (reverse shell, from sbousseaden/EVTX-ATTACK-SAMPLES).

Result: 4 process-creation events scanned, 1 detection fired. The single malicious event (svchost spawning cmd) was caught; three legitimate svchost launches (parented by services.exe) were correctly ignored.

    [ALERT] Suspicious cmd.exe spawned by svchost.exe (T1059)
            ParentImage: C:\Windows\System32\svchost.exe
            Image:       C:\Windows\System32\cmd.exe

## False positives
[YOU WILL FILL THIS IN]
