import os
import sys
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from evtx import PyEvtxParser
import time
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
def sanitize_key(key):
    # Replace characters that are not allowed in Firebase keys
    return key.replace('.', '-').replace('$', '').replace('#', '').replace('[', '').replace(']', '').replace('/', '').replace('{', '').replace('}', '').replace(':', '')


def get_element_text(root, path, namespaces):
    element = root.find(path, namespaces=namespaces)
    return element.text if element is not None else None
def get_element_attribute(root, path, attribute_name, namespaces):
    element = root.find(path, namespaces=namespaces)
    return element.get(attribute_name) if element is not None else None

def get_event_data(root, namespaces):
    event_data = {}

    # Try the first XML structure
    for data in root.findall("./ns:EventData/ns:Data", namespaces):
        name = data.get('Name')
        value = data.text
        if name:
            event_data[name] = value.strip() if value else value
        else:
            # If there is no name, treat it as the message
            event_data["Message"] = value.strip() if value else value

    # Check if the event data is empty
    if not event_data:
        # Try the second XML structure
        for data in root.findall("./ns:UserData/*", namespaces):
            event_data[data.tag] = data.text.strip() if data.text else data.text

    return event_data if event_data else None




def get_element_level(root, path, namespaces):
    element = root.find(path, namespaces=namespaces)
    if element is not None:
        if element.tag == "{http://schemas.microsoft.com/win/2004/08/events/event}Level":
            level = element.text
            if level == "1":
                return "Critical"
            elif level == "2":
                return "Error"
            elif level == "3":
                return "Warning"
            elif level == "4":
                return "Information"
            else:
                return level
        return element.text
    return None






def main():
    log_types_to_query = sys.argv[1].split(',')
    
    output_directory = sys.argv[2]
    mode = sys.argv[3]
    time_after = sys.argv[4]

    max_records = 100 if mode == 'fast' else None

    time_after = datetime.strptime(time_after, "%d.%m.%Y %H:%M:%S")

    

    # XML namespace
    namespaces = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    # Ensure the output directory exists
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    start_time = time.time()
    total_logs = 0
    # Iterate over log types
    for log_type in log_types_to_query:
        if log_type in log_types:
            log_file_path = os.path.join("C:\\Windows\\System32\\winevt\\Logs", log_types[log_type])
            if not os.path.exists(log_file_path):
                continue
            parser = PyEvtxParser(log_file_path)
            event_logs = []
            record_count = 0

            # Iterate over each event record
            for record in parser.records():
                xml_data = record.get("data")
                if xml_data:
                    # Parse the XML data
                    root = ET.fromstring(xml_data)
                    timestamp = record.get("timestamp")

                    # Skip if before the specified time
                    
                    record_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f %Z")
                    formatted_time = record_time.strftime("%d.%m.%Y %H:%M:%S")
                    if record_time < time_after:
                        continue

                    # Extract information from the XML data using namespaces
                    event_id = get_element_text(root, "./ns:System/ns:EventID", namespaces)
                    source_name = get_element_attribute(root, "./ns:System/ns:Provider", 'Name', namespaces)
                    computer_name = get_element_text(root, "./ns:System/ns:Computer", namespaces)
                    channel = get_element_text(root, "./ns:System/ns:Channel", namespaces)
                    event_data = get_event_data(root, namespaces)
                    Level = get_element_level(root, "./ns:System/ns:Level",namespaces)
                    if event_data:
                        event_data = {sanitize_key(key): value for key, value in event_data.items()}
                    # Construct the event dictionary
                    event = {
                        "LogName": channel,
                        "RecordNumber": record["event_record_id"],
                        "EventID": event_id,
                        "SourceName": source_name,
                        "ComputerName": computer_name,
                        "TimeGenerated": formatted_time,
                        "TimeWritten":formatted_time,
                        "Message": event_data,
                        "Level": Level
                    }
                    event_logs.append(event)

                record_count += 1
                total_logs += 1
                if max_records and record_count >= max_records:
                    break
            print(f"Collected {record_count} logs for {log_type}")

            # Save the event logs as JSON
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