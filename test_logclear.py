import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

SAMPLE = "samples/DE_1102_security_log_cleared.evtx"

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
            channel = None
            for c in root.findall(f".//{ns}Channel"):
                channel = c.text
            scanned += 1
            # detection logic: EventID 1102 in the Security channel
            if eid == "1102" and channel == "Security":
                matches += 1
                ts = None
                for t in root.findall(f".//{ns}TimeCreated"):
                    ts = t.get("SystemTime")
                print("[ALERT] Windows Security event log cleared (T1070)")
                print(f"        Channel:     {channel}")
                print(f"        TimeCreated: {ts}")
                print()
    print("=" * 50)
    print(f"Events scanned:   {scanned}")
    print(f"Detections fired: {matches}")

if __name__ == "__main__":
    main()
