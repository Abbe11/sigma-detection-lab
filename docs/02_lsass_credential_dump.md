# Detection: LSASS Memory Access for Credential Dumping

**MITRE ATT&CK:** [T1003.001 - LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
**Tactic:** Credential Access
**Severity:** High
**Rule:** rules/lsass_credential_dump.yml

## What it detects
A process opening a handle to lsass.exe with access rights that allow reading process memory. lsass.exe holds credentials, hashes, and Kerberos tickets in memory; tools like Mimikatz open it with these rights to harvest them. This is one of the most common steps in real intrusions and ransomware.

## Detection logic
Matches Sysmon Event ID 10 (ProcessAccess) where TargetImage ends with \lsass.exe AND GrantedAccess is one of the memory-read masks commonly requested by credential dumpers (0x1010, 0x1410, 0x1438, 0x143a, 0x1fffff).

## Validation
Tested against a real attack sample: sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx (Mimikatz sekurlsa::logonpasswords, from sbousseaden/EVTX-ATTACK-SAMPLES).

Result: 1 ProcessAccess event scanned, 1 detection fired.

    [ALERT] LSASS credential dump detected (T1003.001)
            SourceImage:   C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe
            TargetImage:   C:\Windows\system32\lsass.exe
            GrantedAccess: 0x00001010

## Engineering note
The raw event recorded GrantedAccess as 0x00001010 (leading zeros), while the rule lists 0x1010. The detection script normalizes both sides (strip 0x, strip leading zeros) before comparing. Matching access masks as exact strings is brittle; normalizing the value makes the detection robust across log-source formatting differences.

## False positives
Some legitimate security software (AV/EDR, monitoring agents) accesses lsass with these rights. Tune by allow-listing known-good SourceImage paths rather than weakening the access-mask match. The SourceImage here (mimikatz.exe on a user Desktop) is obviously malicious; in production, the SourceImage is the key triage field.
