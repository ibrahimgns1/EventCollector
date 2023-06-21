import os
import sys
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from evtx import PyEvtxParser
import time
from collections import Counter

log_types = {
    "System": "System.evtx",
    "Security": "Security.evtx",
    "Application": "Application.evtx",
    "Windows PowerShell": "Windows PowerShell.evtx",
    "OneApp_IGCC": "OneApp_IGCC.evtx",
    "Setup": "Setup.evtx",
    "TaskScheduler": "Microsoft-Windows-TaskScheduler%4Maintenance.evtx",
    "Windows Defender": "Microsoft-Windows-Windows Defender%4Operational.evtx"
}

xml_paths = {
    "event_id": "./ns:System/ns:EventID",
    "source_name": "./ns:System/ns:Provider",
    "computer_name": "./ns:System/ns:Computer",
    "channel": "./ns:System/ns:Channel",
    "level": "./ns:System/ns:Level",
    "event_data_1": "./ns:EventData/ns:Data",
    "event_data_2": "./ns:UserData/*"
}

def sanitize_key(key):
    return key.replace('.', '-').replace('$', '').replace('#', '').replace('[', '').replace(']', '').replace('/', '').replace('{', '').replace('}', '').replace(':', '')

def get_element_text(root, path):
    element = root.find(path)
    return element.text if element is not None else None

def get_element_attribute(root, path, attribute_name):
    element = root.find(path)
    return element.get(attribute_name) if element is not None else None

def get_event_data(root):
    event_data = {}

    for data in root.findall(xml_paths["event_data_1"]):
        name = data.get('Name')
        value = data.text
        if name:
            event_data[name] = value.strip() if value else value
        else:
            event_data["Message"] = value.strip() if value else value

    if not event_data:
        for data in root.findall(xml_paths["event_data_2"]):
            event_data[data.tag] = data.text.strip() if data.text else data.text

    return event_data if event_data else None

def get_element_level(root):
    element = root.find(xml_paths["level"])
    if element is not None:
        level = element.text
        if level in ["0", "4"]:
            return "Information"
        elif level == "1":
            return "Critical"
        elif level == "2":
            return "Error"
        elif level == "3":
            return "Warning"
        else:
            return level
    return None

def main():
    log_types_to_query = sys.argv[1].split(',')
    output_directory = sys.argv[2]
    mode = sys.argv[3]
    time_after = sys.argv[4]
    max_records = 100 if mode == 'fast' else None
    time_after = datetime.strptime(time_after, "%d.%m.%Y %H:%M:%S")
    namespaces = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    for key, path in xml_paths.items():
        xml_paths[key] = path.replace("ns:", "{http://schemas.microsoft.com/win/2004/08/events/event}")

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    start_time = time.time()
    total_logs = 0

    for log_type in log_types_to_query:
        if log_type in log_types:
            log_file_path = os.path.join("C:\\Windows\\System32\\winevt\\Logs", log_types[log_type])
            if not os.path.exists(log_file_path):
                continue

            parser = PyEvtxParser(log_file_path)
            event_logs = []
            record_count = 0

            for record in parser.records():
                timestamp = record.get("timestamp")
                record_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f %Z")
                if record_time < time_after:
                    continue

                xml_data = record.get("data")
                if xml_data:
                    root = ET.fromstring(xml_data)

                    event_id = get_element_text(root, xml_paths["event_id"])
                    source_name = get_element_attribute(root, xml_paths["source_name"], 'Name')
                    computer_name = get_element_text(root, xml_paths["computer_name"])
                    channel = get_element_text(root, xml_paths["channel"])
                    event_data = get_event_data(root)
                    Level = get_element_level(root)

                    if event_data:
                        event_data = {sanitize_key(key): value for key, value in event_data.items()}

                    event = {
                        "LogName": channel,
                        "RecordNumber": record["event_record_id"],
                        "EventID": event_id,
                        "SourceName": source_name,
                        "ComputerName": computer_name,
                        "TimeGenerated": record_time.strftime("%d.%m.%Y %H:%M:%S"),
                        "TimeWritten": record_time.strftime("%d.%m.%Y %H:%M:%S"),
                        "Message": event_data,
                        "Level": Level
                    }

                    event_logs.append(event)

                record_count += 1
                total_logs += 1
                if max_records and record_count >= max_records:
                    break

            print(f"Collected {record_count} logs for {log_type}")

            output_file = os.path.join(output_directory, f"{log_type}.json")
            with open(output_file, 'w') as file:
                json.dump(event_logs, file, indent=4)

            print(f"Event logs exported to {output_file}")

        else:
            print(f"Unknown log type: {log_type}")

    end_time = time.time()
    duration = end_time - start_time
    print(f"\nTotal logs collected: {total_logs}")
    print(f"Total duration: {duration:.2f} seconds")

if __name__ == "__main__":
    main()
