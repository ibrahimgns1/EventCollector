import os
import sys
import traceback
import win32con
import win32evtlog
import win32evtlogutil
import win32security
import codecs
import json

def sid_to_string(sid):
    if sid is None:
        return None
    try:
        return win32security.ConvertSidToStringSid(sid)
    except Exception as e:
        print(f"Failed to convert SID: {e}")
        return None

def getEventLogs(server, logtype, logPath, max_logs=None):
    print(f"Logging {logtype} events")
    events = []

    try:
        hand = win32evtlog.OpenEventLog(server, logtype)
        total = win32evtlog.GetNumberOfEventLogRecords(hand)

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        log_count = 0
        while True:
            events_read = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events_read:
                break
            
            for event in events_read:
                event_dict = {
                    'LogName': logtype,
                    'RecordNumber': event.RecordNumber,
                    'EventID': event.EventID & 0x1FFFFFFF,
                    'EventType': evt_dict.get(event.EventType, 'Unknown'),
                    'SourceName': str(event.SourceName),
                    'ComputerName': str(event.ComputerName),
                    'Category': event.EventCategory,
                    'TimeGenerated': event.TimeGenerated.Format(),
                    'TimeWritten': event.TimeWritten.Format(),
                    'Message': win32evtlogutil.SafeFormatMessage(event, logtype)
                }
                events.append(event_dict)

                # Check max_logs for fast mode
                log_count += 1
                if max_logs and log_count >= max_logs:
                    break
            
            # Break the outer loop if max_logs is reached
            if max_logs and log_count >= max_logs:
                break
        
        # Print the total number of events saved
        if max_logs:
            print(f"Total events saved from {logtype} (filtered) = {log_count}")
        else:
            print(f"Total events in {logtype} = {total}")

    except:
        traceback.print_exc()

    # Save events to a JSON file
    with codecs.open(logPath, encoding='utf-8', mode='w') as log_file:
        json.dump(events, log_file, indent=4, ensure_ascii=False)

    print(f"Log creation finished. Location of log is {logPath}")


if __name__ == "__main__":
    # Example usage: python script.py "System,Application" "output_path" "fast"

    # Parse arguments
    selectedLogTypes = sys.argv[1].split(',')
    outputPath = sys.argv[2]
    mode = sys.argv[3]  # 'fast' or 'slow'

    server = None  # None = local machine
    max_logs = 100 if mode == 'fast' else None

    evt_dict = {
        win32con.EVENTLOG_AUDIT_FAILURE: 'EVENTLOG_AUDIT_FAILURE',
        win32con.EVENTLOG_AUDIT_SUCCESS: 'EVENTLOG_AUDIT_SUCCESS',
        win32con.EVENTLOG_INFORMATION_TYPE: 'EVENTLOG_INFORMATION_TYPE',
        win32con.EVENTLOG_WARNING_TYPE: 'EVENTLOG_WARNING_TYPE',
        win32con.EVENTLOG_ERROR_TYPE: 'EVENTLOG_ERROR_TYPE'
    }

    for logtype in selectedLogTypes:
        logPath = os.path.join(outputPath, f"{logtype}_log.json")
        getEventLogs(server, logtype, logPath, max_logs)
