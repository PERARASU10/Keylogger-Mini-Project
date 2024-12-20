# file_monitor.py
import os
import json
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threat_signatures import KNOWN_KEYLOGGERS, KNOWN_MALWARE, SUSPICIOUS_PATHS

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, monitored_dirs, excluded_dirs, event_log):
        self.monitored_dirs = monitored_dirs
        self.excluded_dirs = excluded_dirs
        self.event_log = event_log
        self.threat_activity = {} 

    def on_modified(self, event):
        if not event.is_directory:
            self.log_event("Modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.log_event("Created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event("Deleted", event.src_path)

    def log_event(self, event_type, path):
        if any(path.startswith(excluded) for excluded in self.excluded_dirs):
            return
        try:
            alert = self.check_threat(path)
            if alert:
                # Count repeated activity for the same threat file
                if path in self.threat_activity:
                    self.threat_activity[path]["count"] += 1
                else:
                    self.threat_activity[path] = {"count": 1, "details": alert}

                # Only log if activity repeats
                event_info = {
                    "type": event_type,
                    "path": path,
                    "size": os.path.getsize(path) if os.path.exists(path) else 0,
                    "timestamp": time.ctime(),
                    "alert": alert + (f" - Repeated {self.threat_activity[path]['count']} times" if self.threat_activity[path]["count"] > 1 else "")
                }
                self.event_log.append(event_info)
                self.log_alert(event_info)
        except FileNotFoundError:
            pass

    def check_threat(self, path):
        file_name = os.path.basename(path).lower()
        if file_name in KNOWN_KEYLOGGERS or file_name in KNOWN_MALWARE:
            return "Potential Threat Detected"
        if any(path.startswith(suspicious_path) for suspicious_path in SUSPICIOUS_PATHS):
            return "Suspicious Path Detected"
        return None

    def log_alert(self, alert_info):
        with open("alerts.json", "a") as f:
            f.write(json.dumps(alert_info) + "\n")


class FileMonitor:
    def __init__(self, monitored_dirs, excluded_dirs):
        self.monitored_dirs = monitored_dirs
        self.excluded_dirs = excluded_dirs
        self.event_log = []
        self.observer = Observer()

    def start(self):
        event_handler = FileMonitorHandler(self.monitored_dirs, self.excluded_dirs, self.event_log)
        for directory in self.monitored_dirs:
            self.observer.schedule(event_handler, directory, recursive=True)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()

    def get_alerts(self):
        return self.event_log
