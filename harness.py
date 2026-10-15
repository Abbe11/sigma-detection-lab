import os
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

def get_field(root, ns, name):
    for data in root.findall(f".//{ns}Data"):
        if data.get("Name") == name:
            return data.text
    return None

# --- detections: each takes (eid, fields, channel) -> True/False ---
def detect_whoami(eid, f, ch):
    return eid == "1" and (f.get("Image") or "").lower().endswith("\\whoami.exe")

def detect_lsass(eid, f, ch):
    masks = {"1010", "1410", "1438", "143a", "1fffff"}
    access = (f.get("GrantedAccess") or "").lower().replace("0x", "").lstrip("0")
    return eid == "10" and (f.get("TargetImage") or "").lower().endswith("\\lsass.exe") and access in masks

def detect_svchost_cmd(eid, f, ch):
    return (eid == "1"
            and (f.get("ParentImage") or "").lower().endswith("\\svchost.exe")
            and (f.get("Image") or "").lower().endswith("\\cmd.exe"))

def detect_logclear(eid, f, ch):
    return eid == "1102" and ch == "Security"

DETECTIONS = {
    "whoami_discovery": detect_whoami,
    "lsass_dump": detect_lsass,
    "svchost_spawns_cmd": detect_svchost_cmd,
    "security_log_cleared": detect_logclear,
}

FIELDS_WE_NEED = ["Image", "ParentImage", "TargetImage", "GrantedAccess"]

def scan_file(path):
    """Return {detection_name: fire_count} and total events scanned for one sample."""
    counts = {name: 0 for name in DETECTIONS}
    scanned = 0
    with Evtx(path) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
            eid = None
            for e in root.findall(f".//{ns}EventID"):
                eid = e.text
            channel = None
            for c in root.findall(f".//{ns}Channel"):
                channel = c.text
            fields = {name: get_field(root, ns, name) for name in FIELDS_WE_NEED}
            scanned += 1
            for name, check in DETECTIONS.items():
                if check(eid, fields, channel):
                    counts[name] += 1
    return counts, scanned

def main():
    sample_dir = "samples"
    samples = [f for f in os.listdir(sample_dir) if f.lower().endswith(".evtx")]
    print(f"{'SAMPLE':<45} {'DETECTION':<22} {'SCANNED':>8} {'FIRED':>6}")
    print("-" * 85)
    for s in samples:
        counts, scanned = scan_file(os.path.join(sample_dir, s))
        short = (s[:42] + "...") if len(s) > 45 else s
        for name, fired in counts.items():
            if fired > 0:
                print(f"{short:<45} {name:<22} {scanned:>8} {fired:>6}")
    print("-" * 85)
    print("Scan complete. Only firing detections shown above.")

if __name__ == "__main__":
    main()
