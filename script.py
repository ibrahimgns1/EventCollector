import os
import sys
import time
import traceback
import win32con
import win32evtlog
import win32evtlogutil
import win32security
import winerror
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

def getAllEvents(server, logtypes, basePath):
    if not server:
        serverName = "localhost"
    else:   
        serverName = server
    for logtype in logtypes:
        path = os.path.join(basePath, f"{serverName}_{logtype}_log.json")
        getEventLogs(server, logtype, path)

def getEventLogs(server, logtype, logPath):
    print("Logging %s events" % logtype)
    events = []

    try:
        hand = win32evtlog.OpenEventLog(server, logtype)
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        print("Total events in %s = %s" % (logtype, total))

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events_read = win32evtlog.ReadEventLog(hand, flags, 0)

        while events_read:
            for event in events_read:
                # Extract information from the event
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

            events_read = win32evtlog.ReadEventLog(hand, flags, 0)

    except:
        traceback.print_exc()

    # Save events to a JSON file
    with codecs.open(logPath, encoding='utf-8', mode='w') as log_file:
        json.dump(events, log_file, indent=4, ensure_ascii=False)

    print("Log creation finished. Location of log is %s" % logPath)

if __name__ == "__main__":
    server = None  # None = local machine
    logTypes = ["System", "Application", "Security", "OneApp_IGCC","Setup","TaskScheduler","Windows Defender","Power Shell"]
    evt_dict = {
        win32con.EVENTLOG_AUDIT_FAILURE: 'EVENTLOG_AUDIT_FAILURE',
        win32con.EVENTLOG_AUDIT_SUCCESS: 'EVENTLOG_AUDIT_SUCCESS',
        win32con.EVENTLOG_INFORMATION_TYPE: 'EVENTLOG_INFORMATION_TYPE',
        win32con.EVENTLOG_WARNING_TYPE: 'EVENTLOG_WARNING_TYPE',
        win32con.EVENTLOG_ERROR_TYPE: 'EVENTLOG_ERROR_TYPE'
    }

    getAllEvents(server, logTypes, "C:\\Users\\90539\\Desktop\\events")
