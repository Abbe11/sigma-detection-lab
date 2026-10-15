#!/usr/bin/env python3
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

SAMPLE = "samples/LM_wmiexec_impacket_sysmon_whoami.evtx"
PROCESS_CREATION_ID = "1"

def get_field(root, ns, name):
    for data in root.findall(f".//{ns}Data"):
        if data.get("Name") == name:
            return data.text
    return None

def main():
    matches = 0
    total_proc_events = 0
    with Evtx(SAMPLE) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"
            event_id = None
            for eid in root.findall(f".//{ns}EventID"):
                event_id = eid.text
            if event_id != PROCESS_CREATION_ID:
                continue
            total_proc_events += 1
            image = get_field(root, ns, "Image")
            if image and image.lower().endswith("\\whoami.exe"):
                matches += 1
                cmdline = get_field(root, ns, "CommandLine")
                user = get_field(root, ns, "User")
                print("[ALERT] whoami execution detected (T1033)")
                print(f"        Image:       {image}")
                print(f"        CommandLine: {cmdline}")
                print(f"        User:        {user}")
                print()
    print("=" * 50)
    print(f"Process-creation events scanned: {total_proc_events}")
    print(f"Detections fired:                {matches}")

if __name__ == "__main__":
    main()
