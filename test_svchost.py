import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

SAMPLE = "samples/revshell_cmd_svchost_sysmon_1.evtx"
PROCESS_CREATION_ID = "1"

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
            if eid != PROCESS_CREATION_ID:
                continue
            scanned += 1
            parent = get_field(root, ns, "ParentImage")
            image = get_field(root, ns, "Image")
            # BOTH conditions must match together
            if parent and parent.lower().endswith("\\svchost.exe") and image and image.lower().endswith("\\cmd.exe"):
                matches += 1
                print("[ALERT] Suspicious cmd.exe spawned by svchost.exe (T1059)")
                print(f"        ParentImage: {parent}")
                print(f"        Image:       {image}")
                print()
    print("=" * 50)
    print(f"ProcessCreation events scanned: {scanned}")
    print(f"Detections fired:               {matches}")

if __name__ == "__main__":
    main()
