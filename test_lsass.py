import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

SAMPLE = "samples/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"
PROCESS_ACCESS_ID = "10"
SUSPICIOUS_MASKS = {"1010", "1410", "1438", "143a", "1fffff"}

def norm(mask):
    if not mask:
        return ""
    return mask.lower().replace("0x", "").lstrip("0")

def get_field(root, ns, name):
    for data in root.findall(f".//{ns}Data"):
        if data.get("Name") == name:
            return data.text
    return None

def main():
    matches = 0
    scanned = 0
    with Evtx(SAMPLE) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
            eid = None
            for e in root.findall(f".//{ns}EventID"):
                eid = e.text
            if eid != PROCESS_ACCESS_ID:
                continue
            scanned += 1
            target = get_field(root, ns, "TargetImage")
            access = get_field(root, ns, "GrantedAccess")
            if target and target.lower().endswith("\\lsass.exe") and norm(access) in SUSPICIOUS_MASKS:
                matches += 1
                source = get_field(root, ns, "SourceImage")
                print("[ALERT] LSASS credential dump detected (T1003.001)")
                print(f"        SourceImage:   {source}")
                print(f"        TargetImage:   {target}")
                print(f"        GrantedAccess: {access}")
                print()
    print("=" * 50)
    print(f"ProcessAccess events scanned: {scanned}")
    print(f"Detections fired:             {matches}")

if __name__ == "__main__":
    main()
