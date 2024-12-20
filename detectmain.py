import os
import psutil
import hashlib
import time
import logging
import threading
from flask import Flask, render_template, jsonify, request
from file_monitor import FileMonitor
import atexit
from scapy.layers.inet import IP

from scapy.all import sniff, DNSQR
from scapy.all import sniff, IP, TCP, Raw
from flask_socketio import SocketIO, emit
import requests
app = Flask(__name__)
socketio = SocketIO(app)

# Global variable to store detection alerts and all processes
detection_alerts = []
process_list = []
detected_activity = {
    "dns_queries": {},
    "smtp_connections": {},
    "processes": {}
}
access_denied_processes=[]
monitored_dirs = ["C:/"]  # Monitor entire C drive
excluded_dirs = ["C:/Windows", "C:/Program Files", "C:/Program Files (x86)", "C:/Users/Public"]
file_monitor = FileMonitor(monitored_dirs, excluded_dirs)
file_monitor.start()
network_data = []  # Stores network packet data
bandwidth_data = {"bytes_sent": 0, "bytes_received": 0}  # Bandwidth usage
api_key = "cd503dfa8ddf9f2576960d62a3609bcba237db94f3325e9ae374d877372b5be0"  # Replace with your VirusTotal API key
virustotal_cache = {}  # Cache for VirusTotal results
data_lock = threading.Lock() 
is_suspicious_process=False



logging.basicConfig(filename="keylogger_detection.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Define known keylogger signatures with optional threat scores
known_keylogger_hashes = {
"42e0eda5412a988852e1cf9bb963422603d48777e94c5a19f77804213e1f50e6": {"filename": "NEW PO (YST2310-1010).zip", "threat_score": 10},


}

known_keylogger_processes = [
   
    'keylogger.exe',
'malicious.exe',
'Purchase71249018.exe',
'REVISE FDA.exe',
'Required Copies.img',
'stealthrecorder.exe',
'keyboardspy.exe',
'capturedata.exe',
'spykeylogger.exe',
'keysniffer.exe',
'recordit.exe',
'inputlogger.exe',
'keystroke.exe',
'tracklog.exe',
'passwordlogger.exe',
'sniffit.exe',
'logmykeystrokes.exe',
'keywatcher.exe',
'hiddenlogger.exe',
'recordkey.exe',
'keytrack.exe',
'spytool.exe',
'keycapture.exe',
'datacapture.exe',
'loggerr.exe',
'stealthlogger.exe',
'keyloggerpro.exe',
'keystrokegrabber.exe',
'trackpad.exe',
'keyspy.exe',
'inputrecorder.exe',
'spycapture.exe',
'logmein.exe',
'keylog.exe',
'stealthrecord.exe',
'inputspy.exe',
'keyboardmonitor.exe',
'keystrokeanalyzer.exe',
'recordmykeys.exe',
'keymonitor.exe',
'tracker.exe',
'keyloggerx.exe',
'mysniffer.exe',
'passwordstealer.exe',
'inputloggerpro.exe',
'logmyinput.exe',
'keyrecorder.exe',
'securelogger.exe',
'spydll.dll',
'keychain.exe',
'kl.exe'

]
process_list_lock = threading.Lock()
def calculate_file_hash(file_path):
    
    
    if not file_path or not isinstance(file_path, (str, bytes, os.PathLike)):
        logging.warning(f"Skipping hashing for invalid file path: {file_path}")
        return None
    
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Error hashing file {file_path}: {e}")
        return None

# Function to check if the process is known to be malicious
def is_malicious_process(process_name):
    return process_name.lower() in [proc.lower() for proc in known_keylogger_processes]

# Function to scan for running processes and check for keyloggers
def detect_keylogger():
    logging.info("Starting keylogger detection...")
    global process_list,access_denied_processes
    process_list = []
    
    
    high_cpu_proc, high_mem_proc = None, None
      # Counter for suspicious processes
    suspicious_process = 0  # Counter for suspicious processes
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'exe']):
        try:
            process_name = proc.info['name']
            process_exe = proc.info['exe']
            cpu_percent = proc.info['cpu_percent']
            memory_percent = proc.info['memory_percent']
            
            # Track the highest CPU and memory-consuming processes
           

            # Skip processes that don't have a valid executable path
            if not process_exe or not os.path.isfile(process_exe):
                logging.warning(f"Skipping process {process_name} (PID: {proc.pid}) with invalid executable path.")
                continue

            # Check if process name matches known keyloggers
            is_suspicious_process = False
            
            alert_message = ""
            if is_malicious_process(process_name):
                is_suspicious_process = True
                alert_message = f"Potential keylogger detected: {process_name}"
                logging.warning(alert_message)
                detection_alerts.append(alert_message)

            # Calculate hash of the executable file
            file_hash = calculate_file_hash(process_exe)
            if file_hash in known_keylogger_hashes:
                is_suspicious_process = True
                alert_message = f"Keylogger detected: {known_keylogger_hashes[file_hash]['filename']} (Process: {process_name}, PID: {proc.pid})"
                logging.warning(alert_message)
                detection_alerts.append(alert_message)
          
            
            

            with process_list_lock:
                process_list.append({
                'pid': proc.pid,
                'name': process_name,
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'exe': process_exe,
                'is_suspicious': is_suspicious_process
                
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            access_denied_processes.append({'pid': proc.pid, 'name': proc.info['name']})
            logging.warning(f"Access denied for process (PID: {proc.pid}), unable to retrieve information.")
            continue
        
def update_activity(activity_type, key, data):
    if key in detected_activity[activity_type]:
        detected_activity[activity_type][key]["count"] += 1
        detected_activity[activity_type][key]["last_seen"] = time.time()
    else:
        detected_activity[activity_type][key] = {**data, "count": 1, "last_seen": time.time()}

    # Emit updated data to clients
    socketio.emit("update_activity", {activity_type: detected_activity[activity_type]})

# Detect suspicious DNS queries
def detect_suspicious_dns(packet):
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode("utf-8")
        if "gmail.com" in query or "smtp" in query:  # Adjust for targeted domains
            key = query
            data = {
                "query": query,
                "source_ip": packet[IP].src if packet.haslayer(IP) else "Unknown",
            }
            update_activity("dns_queries", key, data)

# Detect suspicious SMTP connections
def check_smtp_connections():
    while True:
        for conn in psutil.net_connections(kind="inet"):
            if conn.raddr and conn.raddr.port == 465:  # Port 465 is SMTP over SSL
                process = psutil.Process(conn.pid)
                key = f"{process.name()}-{conn.laddr}-{conn.raddr}"
                data = {
                    "process_name": process.name(),
                    "local_address": conn.laddr,
                    "remote_address": conn.raddr,
                }
                update_activity("smtp_connections", key, data)
        

# Monitor suspicious processes
def monitor_processes():
    while True:
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                cmdline = proc.info["cmdline"]
                if cmdline:  # Ensure cmdline is not None
                    cmdline_str = " ".join(cmdline)
                    if "pynput" in cmdline_str or "keyboard.Listener" in cmdline_str:
                        key = f"{proc.info['pid']}-{proc.info['name']}"
                        data = {
                            "pid": proc.info["pid"],
                            "name": proc.info["name"],
                            "cmdline": cmdline_str,
                        }
                        update_activity("processes", key, data)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
def capture_packets():
    def process_packet(packet):
        global bandwidth_data

        if IP in packet:
            with data_lock:
                # Basic packet info
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                pkt_len = len(packet)
                timestamp = time.time()

                # Update bandwidth
                if packet.haslayer(TCP):
                    if src_ip.startswith("192."):  # Example: Adjust for your network
                        bandwidth_data["bytes_sent"] += pkt_len
                    if dst_ip.startswith("192."):  # Example: Adjust for your network
                        bandwidth_data["bytes_received"] += pkt_len

                # VirusTotal integration
                if src_ip not in virustotal_cache:
                    virustotal_cache[src_ip] = check_virustotal(src_ip)
                      


                pkt_info = {
                    "src": src_ip,
                    "dst": dst_ip,
                    "proto": proto,
                    "len": pkt_len,
                    "time": timestamp,
                    "keylogger": "keylogger" in packet[Raw].load.decode(errors="ignore").lower() if packet.haslayer(Raw) else False,
                    "vt_flagged": virustotal_cache.get(src_ip, {}).get("flagged", False),
                }

                # Append packet data
                network_data.append(pkt_info)
                if len(network_data) > 10:  # Keep the last 100 packets
                    network_data.pop(0)


    sniff(prn=process_packet, store=False, count=0)
    

# VirusTotal API call
def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {"flagged": len(data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})) > 0}
    except Exception as e:
        print(f"Error fetching VirusTotal data for {ip}: {e}")
    time.sleep(15)
    return {"flagged": False}

def start_threads():
    # Thread for DNS monitoring
    threading.Thread(target=lambda: sniff(filter="port 53", prn=detect_suspicious_dns, store=False), daemon=True).start()

    # Thread for SMTP monitoring
    threading.Thread(target=check_smtp_connections, daemon=True).start()

    # Thread for process monitoring
    threading.Thread(target=monitor_processes, daemon=True).start()
    
    threading.Thread(target=detect_keylogger, daemon=True).start()
    threading.Thread(target=capture_packets, daemon=True).start()
    


# Flask route for the homepage
@app.route("/")
def index():
    try:
        return render_template("index.html",detection_alerts=detection_alerts)
    except Exception as e:
        logging.error(f"Error rendering index.html: {e}")
        return jsonify({"error": "Unable to load index page."})


@app.route('/frontend')
def frontend():
    # Render frontend.html for the /frontend route
    return render_template('frontend.html', detection_alerts=detection_alerts)
@app.route('/process')
def process():
    # Render frontend.html for the /frontend route
    return render_template('process.html', detection_alerts=detection_alerts)

@app.route('/cpumonitor')
def cpumonitor():
    # Render frontend.html for the /frontend route
    return render_template('cpumonitor.html')

@app.route('/memorymonitor')
def memorymonitor():
    # Render frontend.html for the /frontend route
    return render_template('memorymonitor.html' )


@app.route("/filemonitor")
def filemonitor():
    return render_template("filemonitor.html",detection_alerts=detection_alerts)
@app.route("/alert")
def get_alert():
    return jsonify(file_monitor.get_alerts())

@atexit.register
def cleanup():
    file_monitor.stop()

@app.route('/alerts')
def get_alerts():
    return jsonify(alerts=detection_alerts)

@app.route('/processes')
def get_processes():
    with process_list_lock:  # Ensure thread-safe access
        sorted_process_list = sorted(process_list, key=lambda x: x.get('is_suspicious', False), reverse=True)
    return jsonify(processes=sorted_process_list)





@app.route('/process/<int:pid>')
def get_process_detail(pid):
    process_detail = next((proc for proc in process_list if proc['pid'] == pid), None)
    if process_detail:
        return jsonify(process_detail)
    else:
        return jsonify({"error": "Process not found"}), 404

# Flask route to get process metrics for graph/chart
@app.route('/process_metrics')
def get_process_metrics():
    metric_type = request.args.get('metric', 'cpu')  # User's choice of metric (cpu or memory)
    
    known_processes = [proc for proc in process_list if proc.get('is_known_signature', False)]
    other_processes = [proc for proc in process_list if not proc.get('is_known_signature', False)]

    # Prepare data for the frontend
    sorted_process_list = known_processes + other_processes  # Known processes first
    if metric_type == 'cpu':
        data = {proc['name']: proc['cpu_percent'] for proc in sorted_process_list}
    else:  # Default to memory
        data = {proc['name']: proc['memory_percent'] for proc in sorted_process_list}

    return jsonify(metrics=data)



@app.route('/network_data')
def get_network_data():
    with data_lock:
        return jsonify(network_data)

@app.route('/bandwidth')
def get_bandwidth():
    return jsonify(bandwidth_data)





@app.route("/network")
def networkmonitor11():
    return render_template("network.html",activity=detected_activity,detection_alerts=detection_alerts)

@app.route("/api/activity")
def activity_data():
    return jsonify(detected_activity)


if __name__ == "__main__":
    start_threads()
    
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)


