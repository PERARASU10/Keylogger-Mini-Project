import os
import psutil
import hashlib
import time
import logging
import threading
from flask import Flask, render_template, jsonify, request
from file_monitor import FileMonitor
import atexit
import yara
from scapy.all import sniff, IP, TCP, UDP, DNS
import platform
from datetime import datetime
import subprocess
import math
import base64
import requests
import socket
import whois
from collections import defaultdict
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

monitor_thread = None
monitor_running = False

monitor_keylogger= None
monitor_run = False

# Global variable to store detection alerts and all processes
detection_alerts = []
network_alerts = []
process_list = []
traffic_stats = {}  # For anomaly detection
baseline_traffic = {} # Example baseline for normal traffic
ABUSEIPDB_API_KEY = '35609dedf43947b57c4f613eed59aa4cd4432a24d089fcd48064d54229338a1c19949d06dcf9ea53'
ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2/check'
access_denied_processes = []
monitored_dirs = ["C:/"]  # Monitor entire C drive
excluded_dirs = ["C:/Windows", "C:/Program Files", "C:/Program Files (x86)", "C:/Users/Public"]
file_monitor = FileMonitor(monitored_dirs, excluded_dirs)
file_monitor.start()
yara_matched_processes = []
api_key = "cd503dfa8ddf9f2576960d62a3609bcba237db94f3325e9ae374d877372b5be0"

# Configure logging
logging.basicConfig(filename="keylogger_detection.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Define known keylogger signatures with optional threat scores
known_keylogger_hashes = {
"42e0eda5412a988852e1cf9bb963422603d48777e94c5a19f77804213e1f50e6": {"filename": "NEW PO (YST2310-1010).zip", "threat_score": 10},
"ac42bb7461430ed2dd0d2a31f3ff70907b50e154005bde115783bf722b0bb217": {"filename": "ac42bb7461430ed2dd0d2a31f3ff70907b50e154005bde115783bf722b0bb217", "threat_score": 10},
"b32404c30f409946db010ddd023b2efecb55b7f93c469d1af66bde2e346325e5": {"filename": "ΦΟΡΜΑ ΑΙΤΗΣΗΣ ΜΕΤΑΒΙΒΑΣΗΣ.doc", "threat_score": 10},
"d496e51ec37ceea2ba0053b6fc163c7235ea2f479825fed46c90d7e990ceac2d": {"filename": "23112023_2214_BARCLAYS.ISO", "threat_score": 10},
"418c5807f39fdc38d2bcb69acc0e4457bb74072fc3255fe94b071c912a206365": {"filename": "1464-36-0x0000000007D70000-0x0000000007DB2000-memory.dmp", "threat_score": 10},
"702743e89f646a52d2d877135038a5f56eea6f81e9b320ad1e850ab5b36cfa69": {"filename": "plugmanzx.exe", "threat_score": 10},
"c83c8ec888f8404ab18d2a3706bafc74a36fb3e05dd64b9c58efd610d67f82cf": {"filename": "3.exe", "threat_score": 10},
"a259b90ecf696db15cbbbad7cbe14c5a2a8889052d570e6845a0bd8c697cedc1": {"filename": "a259b90ecf696db15cbbbad7cbe14c5a2a8889052d570e6845a0bd8c697cedc1", "threat_score": 10},
"a287c286d818d3b4ffcbc11c61502858997182dac7c10276198b75773f5e3dea": {"filename": "a287c286d818d3b4ffcbc11c61502858997182dac7c10276198b75773f5e3dea", "threat_score": 10},
"4731517b198414342891553881913565819509086b8154214462788c740b34c9": {"filename": "4731517b198414342891553881913565819509086b8154214462788c740b34c9.exe", "threat_score": 10},
"3696b50af7b213dbb488178e4202096f3efc1e0c9f6f3b8d48e47799d49537f6": {"filename": "Purchase Order No. 4500017624.js", "threat_score": 10},
"3cbf36d411a17825571754792d24ef1c527bf7a3dc1576542a9e3f7af17b25d8": {"filename": "Tracking#1Z379W410424496200.vbs", "threat_score": 10},
"0c0b8cfcdae8cc7d8a0b193e9e14d060138396c1c3635ba1f346b2836a51de0b": {"filename": "z1n0t6KQiluA8LgQ7.exe", "threat_score": 10},
"ad7cecbbae93e5f9899d2600ce0a0516b185c7b31f778916be4c534beba1cc8b": {"filename": "z57f30i4QHbDOhsnME.exe", "threat_score": 10},
"610b31befe1d38d5026b63036026eeb2a796a0ebae7bf0be301028b1c78df016": {"filename": "tmp", "threat_score": 10},
"b2d0b4b87b6fc95ba22b007f29bde3c96aa877cd0095e3f7d8fa32fe215aaeb1": {"filename": "image_2023-11-23_211031656.png", "threat_score": 10},
"d81e8511ca6925abf689f2f0e7c7ec5b1f14338a66b3329fa38e5a6d7b594392": {"filename": "Shipment document.exe", "threat_score": 10},
"91434e57f158bb81625776231e38663bbf467f0bec3048d4c49ed36461ed4724": {"filename": "a8c4cdad67ebf05fa888878920cf061d.exe", "threat_score": 10},
"42ba69214710a76d900781f560a65f5b2a8c4358407f844fc22fee83ae20577d": {"filename": "42ba69214710a76d900781f560a65f5b2a8c4358407f844fc22fee83ae20577d", "threat_score": 10},
"4ffb1b49ab7d78d24c97791d704ba56303455fbe0469d0f7203489eb68fce05e": {"filename": "4ffb1b49ab7d78d24c97791d704ba56303455fbe0469d0f7203489eb68fce05e", "threat_score": 10},
"b4b21540586e47c730fdef86c904b723afe9fe640e37b6ea3d898557c9b3dac1": {"filename": "b4b21540586e47c730fdef86c904b723afe9fe640e37b6ea3d898557c9b3dac1", "threat_score": 10},
"53e37eafee1ac440492fc29df6bdfcce69c927c8fe4c7ecba9ddf89fb83be29e": {"filename": "53e37eafee1ac440492fc29df6bdfcce69c927c8fe4c7ecba9ddf89fb83be29e", "threat_score": 10},
"ca829a3b395a1fd1fca7c3a721e04facf94da82b20910b24014434e683e6e2d1": {"filename": "ca829a3b395a1fd1fca7c3a721e04facf94da82b20910b24014434e683e6e2d1", "threat_score": 10},
"3a23416f70098116646a055816e46e718c473fe6b4bf26512405cafc2daad7ab": {"filename": "3a23416f70098116646a055816e46e718c473fe6b4bf26512405cafc2daad7ab.docx", "threat_score": 10},
"d2335ed2926627c5fb98681cffb67b8d9eaa3bcf3ab64b417b4e461e3c713c4b": {"filename": "d2335ed2926627c5fb98681cffb67b8d9eaa3bcf3ab64b417b4e461e3c713c4b", "threat_score": 10},
"1945785c36c91cb9b8f33d468bde5aeeaca274ee1e4ee1a6c591aadc9de4ec36": {"filename": "Swift Copy $45667.23 Gem Textile.zip", "threat_score": 10},
"25a4772b405adb2585dc19e528156f6907ce3f539d0bc85827419f93c320f5cc": {"filename": "25a4772b405adb2585dc19e528156f6907ce3f539d0bc85827419f93c320f5cc", "threat_score": 10},
"1121afc53e444ca276a5c5292e11bf91a13847f4c62754cdc5aef8e9f787600a": {"filename": "1121afc53e444ca276a5c5292e11bf91a13847f4c62754cdc5aef8e9f787600a", "threat_score": 10},
"d58e82b995a9c7a1ae33e67e42c7cc62e525244012abe7c39c0cc9e52cf5c206": {
        "filename": "d58e82b995a9c7a1ae33e67e42c7cc62e525244012abe7c39c0cc9e52cf5c206",
        "threat_score": 10
    },
    "e6362b723c59c42f7b1b60fa8bb229c9eb189db22e80319e2ec1f8f1b1d14333": {
        "filename": "e6362b723c59c42f7b1b60fa8bb229c9eb189db22e80319e2ec1f8f1b1d14333",
        "threat_score": 10
    },
    "bd881fe57802e3d2c133b6ff9c0a3fb6776b950113cb7e528337dff2957865be": {
        "filename": "bd881fe57802e3d2c133b6ff9c0a3fb6776b950113cb7e528337dff2957865be",
        "threat_score": 10
    },
    "b36f06a4435c5cefcd95288f3893ec0a729c01a0555479706ef682cebe72dc80": {
        "filename": "b36f06a4435c5cefcd95288f3893ec0a729c01a0555479706ef682cebe72dc80",
        "threat_score": 10
    },
    "423533a254ed111fca5ddece696b0f5aa3351cbe4762441f6e897eb8f8a46abd": {
        "filename": "423533a254ed111fca5ddece696b0f5aa3351cbe4762441f6e897eb8f8a46abd",
        "threat_score": 10
    },
    "443acdcb91218eb4732a8beaea7a9007e6b09dce91977d25d035c6180bc40456": {
        "filename": "443acdcb91218eb4732a8beaea7a9007e6b09dce91977d25d035c6180bc40456",
        "threat_score": 10
    },
    "7002c7c342d8e74fb96328b923bf05164080dcb1c4f4876a7bf5d920056a3967": {
        "filename": "7002c7c342d8e74fb96328b923bf05164080dcb1c4f4876a7bf5d920056a3967",
        "threat_score": 10
    },
    "6492da2662143ab3b7fa97df5dc0a2f7492d56fa56655be0380694eebc018743": {
        "filename": "6492da2662143ab3b7fa97df5dc0a2f7492d56fa56655be0380694eebc018743",
        "threat_score": 10
    },
    "ccd6b02d0a92eb856e09f96e6307876ad984bec6c04ea7114a3fe3aea927ad4a": {
        "filename": "ccd6b02d0a92eb856e09f96e6307876ad984bec6c04ea7114a3fe3aea927ad4a",
        "threat_score": 10
    },
    "bcc30b9c1a7bb03d86666d4a594c934d965969b9d2fd1abfb6a6d8479959bae3": {
        "filename": "bcc30b9c1a7bb03d86666d4a594c934d965969b9d2fd1abfb6a6d8479959bae3",
        "threat_score": 10
    },
    "c0d0bc43c743c9ae396e8d47e15c08dd083795d2594ea3e7589dbd25c43bb370": {
        "filename": "c0d0bc43c743c9ae396e8d47e15c08dd083795d2594ea3e7589dbd25c43bb370",
        "threat_score": 10
    },
    "6e932314f7a10cde100b19c5c68549240b4680cbc1dd54ba70de929a8867e090": {
        "filename": "6e932314f7a10cde100b19c5c68549240b4680cbc1dd54ba70de929a8867e090_ESTADO_DE_CUENTA_15.11.2023.bz",
        "threat_score": 10
    },
    "f84e5e9ee5aab87880518da8f0ad9046656468b0f39c36ddcea561b9facd16c4": {
        "filename": "2.Invoice-4500000956-1018.exe",
        "threat_score": 10
    },
    "917bdf6c2b504b5b05eac1a68d618a9442e5f9ebd7f4abf6f9f0d1d16168ebc9": {
        "filename": "1188-18-0x00000000047E0000-0x0000000004822000-memory.dmp",
        "threat_score": 10
    },
    "7045c1465bc70e0f8a8eaac0515b457496c9641e7ce11fdbc1dab8e8ee08426e": {
        "filename": "confirmation.exe",
        "threat_score": 10
    },
    "70c5897be4d10a28f6cfd2daad75860f52aca523fd9299aa29073ab14408109a": {
        "filename": "Invoice_1-19580161·pdf.exe",
        "threat_score": 10
    },
    "0fe3a1191b5f6d5cb9509f93081e04a063e5668c3fe10ab677887c1c3f7f72b6": {
        "filename": "ATTACHED INVOICES.zip",
        "threat_score": 10
    },
    "585d9696b6875fb0d009ba282596d75ea409b88ba27d125996d791899d008d68": {
        "filename": "wpo28029 Changzhou Tairun.zip",
        "threat_score": 10
    },
    "e38f859f13e982d332dada2cc71f6ebfeb87793959bd37642dc8f9a1d9b655da": {
        "filename": "overdue payment pdf.rar",
        "threat_score": 10
    },
    "d339ed6ed6e5df059a61e220a5b695f4773d1b849ad36c9a1e0e42dd38068c2c": {
        "filename": "17112023_0009_16112023_ZAMÓWIENIE_N.2311780.IMG",
        "threat_score": 10
    },
    "a245bbcd8bd89a1b4d24f79630212fed50905ac410132678fcea552048b66792": {
        "filename": "FILE Invoice 43155 from America's Custom Brokers.exe",
        "threat_score": 10
    },
    "3c5e1993db8f454b72132cc7dd4b9180dccaa415b2fa9d0c8d55f768ebeffab4": {
        "filename": "INV and PAK.exe",
        "threat_score": 10
    },
    "dbe5ea4fdeec96fa6dbd4e378dd10f4c6b89a921adaff45fe358f3dbb55da1fb": {
        "filename": "NEAS.dbe5ea4fdeec96fa6dbd4e378dd10f4c6b89a921adaff45fe358f3dbb55da1fb.exe",
        "threat_score": 10
    },
    "4dc4ade4ae2d4abc759ac2fd298eeca6a88f1669fb1f3e761c46d134b5620a0f": {
        "filename": "NEAS.4dc4ade4ae2d4abc759ac2fd298eeca6a88f1669fb1f3e761c46d134b5620a0f.exe",
        "threat_score": 10
    },
    "6927a9e73bf55a3401c967648cfc9f0d1d6cbf7cf452dd483620992d7d8b34e2": {
        "filename": "NEAS.6927a9e73bf55a3401c967648cfc9f0d1d6cbf7cf452dd483620992d7d8b34e2.exe",
        "threat_score": 10
    },
    "f213a569cf0a8b823f8116f03f2e49ec48a0ffc2bd7bb202b638517fa8eb975b": {
        "filename": "INV and PAK.zip",
        "threat_score": 10
    },
    "f6b96b0e4ca1b30e8f8973036205314b80f9ac4ebff7f0e46c1c74d51c72202a": {
        "filename": "NEAS.f6b96b0e4ca1b30e8f8973036205314b80f9ac4ebff7f0e46c1c74d51c72202a.exe",
        "threat_score": 10
    },
    "93da5b68246f2c37789b4fe137f570a7eaf939810bedac23fc6ce070a19672e5": {
        "filename": "NEAS.93da5b68246f2c37789b4fe137f570a7eaf939810bedac23fc6ce070a19672e5.exe",
        "threat_score": 10
    },
    "cbebcef944dc8b96250fa57c98bef408a1f3f053f303871f89f8f3035b4b3e7a": {
        "filename": "NEAS.cbebcef944dc8b96250fa57c98bef408a1f3f053f303871f89f8f3035b4b3e7a.exe",
        "threat_score": 10
    },
    "777c4e75052752ee1f5ccad536e28dc1bc5d8436892bbbcc86a7cf69d581ab8f": {
        "filename": "NEAS.777c4e75052752ee1f5ccad536e28dc1bc5d8436892bbbcc86a7cf69d581ab8f.exe",
        "threat_score": 10
    },
    "8632a6cdacd3c2ca44c427d1ef6bea4a9c16a7089a31f12fe79ba6e108860902": {
        "filename": "NEAS.8632a6cdacd3c2ca44c427d1ef6bea4a9c16a7089a31f12fe79ba6e108860902.exe",
        "threat_score": 10
    },
    "d387bc9dc482dc2c34301df9a24716472d122ff2e1212b2f66681b55b8d67bd1": {
        "filename": "d387bc9dc482dc2c34301df9a24716472d122ff2e1212b2f66681b55b8d67bd1",
        "threat_score": 10
    }


}

known_keylogger_processes = [
   'NEW PO (YST2310-1010).zip',
    'ac42bb7461430ed2dd0d2a31f3ff70907b50e154005bde115783bf722b0bb217',
    'ΦΟΡΜΑ ΑΙΤΗΣΗΣ ΜΕΤΑΒΙΒΑΣΗΣ.doc',
    '23112023_2214_BARCLAYS.ISO',
    '1464-36-0x0000000007D70000-0x0000000007DB2000-memory.dmp',
    'plugmanzx.exe',
    '3.exe',
    'a259b90ecf696db15cbbbad7cbe14c5a2a8889052d570e6845a0bd8c697cedc1',
    'a287c286d818d3b4ffcbc11c61502858997182dac7c10276198b75773f5e3dea',
    '4731517b198414342891553881913565819509086b8154214462788c740b34c9.exe',
    'Purchase Order No. 4500017624.js',
    'Tracking#1Z379W410424496200.vbs',
    'z1n0t6KQiluA8LgQ7.exe',
    'z57f30i4QHbDOhsnME.exe',
    'tmp',
    'image_2023-11-23_211031656.png',
    'Shipment document.exe',
    'a8c4cdad67ebf05fa888878920cf061d.exe',
    '42ba69214710a76d900781f560a65f5b2a8c4358407f844fc22fee83ae20577d',
    '4ffb1b49ab7d78d24c97791d704ba56303455fbe0469d0f7203489eb68fce05e',
    'b4b21540586e47c730fdef86c904b723afe9fe640e37b6ea3d898557c9b3dac1',
    '53e37eafee1ac440492fc29df6bdfcce69c927c8fe4c7ecba9ddf89fb83be29e',
    'ca829a3b395a1fd1fca7c3a721e04facf94da82b20910b24014434e683e6e2d1',
    '3a23416f70098116646a055816e46e718c473fe6b4bf26512405cafc2daad7ab',
    'd2335ed2926627c5fb98681cffb67b8d9eaa3bcf3ab64b417b4e461e3c713c4b',
    'Swift Copy $45667.23 Gem Textile.zip',
    '25a4772b405adb2585dc19e528156f6907ce3f539d0bc85827419f93c320f5cc',
    '1121afc53e444ca276a5c5292e11bf91a13847f4c62754cdc5aef8e9f787600a',
    'd58e82b995a9c7a1ae33e67e42c7cc62e525244012abe7c39c0cc9e52cf5c206',
    'e6362b723c59c42f7b1b60fa8bb229c9eb189db22e80319e2ec1f8f1b1d14333',
    'bd881fe57802e3d2c133b6ff9c0a3fb6776b950113cb7e528337dff2957865be',
    'b36f06a4435c5cefcd95288f3893ec0a729c01a0555479706ef682cebe72dc80',
    '423533a254ed111fca5ddece696b0f5aa3351cbe4762441f6e897eb8f8a46abd',
    '443acdcb91218eb4732a8beaea7a9007e6b09dce91977d25d035c6180bc40456',
    '7002c7c342d8e74fb96328b923bf05164080dcb1c4f4876a7bf5d920056a3967',
    '6492da2662143ab3b7fa97df5dc0a2f7492d56fa56655be0380694eebc018743',
    'ccd6b02d0a92eb856e09f96e6307876ad984bec6c04ea7114a3fe3aea927ad4a',
    'bcc30b9c1a7bb03d86666d4a594c934d965969b9d2fd1abfb6a6d8479959bae3',
    'c0d0bc43c743c9ae396e8d47e15c08dd083795d2594ea3e7589dbd25c43bb370',
    '6e932314f7a10cde100b19c5c68549240b4680cbc1dd54ba70de929a8867e090',
    '2.Invoice-4500000956-1018.exe',
    '1188-18-0x00000000047E0000-0x0000000004822000-memory.dmp',
    'confirmation.exe',
    'Invoice_1-19580161·pdf.exe',
    'ATTACHED INVOICES.zip',
    'wpo28029 Changzhou Tairun.zip',
    'overdue payment pdf.rar',
    '17112023_0009_16112023_ZAMÓWIENIE_N.2311780.IMG',
    'FILE Invoice 43155 from America\'s Custom Brokers.exe',
    'INV and PAK.exe',
    'NEAS.dbe5ea4fdeec96fa6dbd4e378dd10f4c6b89a921adaff45fe358f3dbb55da1fb',
    'NEAS.4dc4ade4ae2d4abc759ac2fd298eeca6a88f1669fb1f3e761c46d134b5620a0f',
    'NEAS.6927a9e73bf55a3401c967648cfc9f0d1d6cbf7cf452dd483620992d7d8b34e2',
    'INV and PAK.zip',
    'NEAS.f6b96b0e4ca1b30e8f8973036205314b80f9ac4ebff7f0e46c1c74d51c72202a',
    'NEAS.93da5b68246f2c37789b4fe137f570a7eaf939810bedac23fc6ce070a19672e5',
    'NEAS.cbebcef944dc8b96250fa57c98bef408a1f3f053f303871f89f8f3035b4b3e7a',
    'NEAS.777c4e75052752ee1f5ccad536e28dc1bc5d8436892bbbcc86a7cf69d581ab8f',
    'NEAS.8632a6cdacd3c2ca44c427d1ef6bea4a9c16a7089a31f12fe79ba6e108860902',
    'd387bc9dc482dc2c34301df9a24716472d122ff2e1212b2f66681b55b8d67bd1',
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


# Function to calculate the SHA-256 hash of a file
rules = yara.compile(source=r"""
rule Enhanced_Keylogger_Detection
{
    meta:
        description = "Enhanced detection for potential keylogger patterns, functions, and behaviors"
        author = "AI-enhanced rules"
        date = "2024-11-08"

    strings:
        // Generic keywords often found in keylogger code
        $keyword_keystroke = "keystroke"
        $keyword_keylog = "keylog"
        $keyword_password_capture = "password capture"
        $keyword_record_keys = "record keys"
        $keyword_get_asciikey = "GetAsyncKeyState"
        $keyword_get_foreground = "GetForegroundWindow"
        $keyword_get_window = "GetWindowText"
        $keyword_hook_proc = "SetWindowsHookEx"
        $keyword_logfile = "logfile"
        $keyword_keyevent = "keybd_event"
        $keyword_vk_code = "VK_SHIFT"

        // API calls and functions often used by keyloggers
        $api_open_process = "OpenProcess"
        $api_read_memory = "ReadProcessMemory"
        $api_write_memory = "WriteProcessMemory"
        $api_create_file = "CreateFile"
        $api_close_handle = "CloseHandle"
        $api_send_input = "SendInput"

        // Strings related to stealth and hidden file creation
        $stealth_hide_console = "ShowWindow(SW_HIDE)"
        $stealth_persistence = "Registry\\Run"
        $stealth_autorun = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        
    condition:
        // Detect common keylogging keywords and API functions
        2 of ($keyword_*) or
        2 of ($api_*) or
        (any of ($stealth_*) and 1 of ($keyword_*))
}
rule Keylogger_Network_Activity
{
    meta:
        description = "Detects network activity patterns consistent with keylogger data transmission"
        author = "AI-enhanced rules"
        date = "2024-11-08"
    
    strings:
        // Network keywords often associated with data exfiltration by keyloggers
        $network_http = "HTTP"
        $network_https = "HTTPS"
        $network_send = "send"
        $network_socket = "socket"
        $network_wsastartup = "WSAStartup"
        $network_wsa_send = "WSASend"
        $network_internet_open = "InternetOpen"
        $network_internet_connect = "InternetConnect"
        $network_wininet_send = "HttpSendRequest"
        
        // Keywords suggesting outbound data exfiltration
        $exfiltrate_password = "password"
        $exfiltrate_keystrokes = "keystrokes"
        $exfiltrate_logs = "logs"
        $exfiltrate_url = "URL"
        
    condition:
        // Trigger if both network and exfiltration keywords are found
        any of ($network_*) and any of ($exfiltrate_*)
}
rule Keylogger_Persistence_Techniques
{
    meta:
        description = "Detects potential persistence mechanisms used by keyloggers"
        author = "AI-enhanced rules"
        date = "2024-11-08"
        
    strings:
        // Registry keys commonly used for persistence
        $persistence_registry_run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $persistence_registry_runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        
        // File and shortcut creation strings for autorun
        $persistence_startup_shortcut = "shell:startup"
        $persistence_schedule_task = "schtasks"
        
        // Additional stealthy persistence mechanisms
        $persistence_hidden_file = "attrib +h"
        $persistence_hide_file = "hidden file"
        $persistence_hide_folder = "hidden folder"
        
    condition:
        // Look for registry-based or file-based persistence techniques
        any of ($persistence_*)
}
""")
def calculate_entropy(data):
    if not data:
        return 0
    length = len(data)
    return -sum((p := data.count(x) / length) * math.log2(p) for x in set(data))


# Function for WHOIS lookup
def get_whois_info(ip):
    try:
        info = whois.whois(ip)
        return str(info)
    except Exception:
        return "WHOIS lookup failed"
    
# Function for GeoIP lookup

# Function to query AbuseIPDB
def check_abuse_ip(ip):
    try:
        response = requests.get(
            ABUSEIPDB_API_URL,
            headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
        )
        if response.status_code == 200:
            return response.json().get("data", {}).get("abuseConfidenceScore", 0)
    except Exception as e:
        logging.error(f"AbuseIPDB API Error: {e}")
    return 0


# Function for anomaly detection

def is_anomalous(ip):
    current_traffic = traffic_stats[ip]
    baseline = baseline_traffic[ip]
    return current_traffic > baseline * 1.5  
# Example: traffic exceeds 1.5x baseline
def get_geoip_details(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        return response.json() if response.status_code == 200 else {"status": "fail"}
    except Exception as e:
        return {"error": str(e)}


# Function for reverse DNS lookup
def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Reverse DNS lookup failed"

# Function to query threat intelligence API
def threat_intelligence_check(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"malicious": data.get("malicious", 0), "suspicious": data.get("suspicious", 0)}
    except Exception as e:
        logging.error(f"VirusTotal API Error: {e}")
    return {"malicious": 0, "suspicious": 0}

# WHOIS and reverse DNS lookup
def domain_details(ip):
    try:
        reverse_name = socket.gethostbyaddr(ip)[0]
        whois = subprocess.check_output(["whois", ip]).decode("utf-8", errors="ignore")
        return reverse_name, whois
    except Exception:
        return "N/A", "WHOIS lookup failed"
# Function for port scanning
def scan_ports(ip):
    try:
        open_ports = []
        for port in range(20, 1025):  # Scanning common ports
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        return open_ports
    except Exception as e:
        return {"error": str(e)}

# Function to perform ping and traceroute
def perform_network_tests(ip):
    try:
        ping = subprocess.run(["ping", "-c", "3", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        traceroute = subprocess.run(["traceroute", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        return {
            "ping_result": ping.stdout if ping.returncode == 0 else ping.stderr,
            "traceroute_result": traceroute.stdout if traceroute.returncode == 0 else traceroute.stderr
        }
    except Exception as e:
        return {"error": str(e)}

# Function to analyze device details
def get_device_details():
    try:
        return {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_version": platform.version(),
            "processor": platform.processor(),
            "architecture": platform.architecture()
        }
    except Exception as e:
        return {"error": str(e)}

# Function for comprehensive analysis
def analyze_suspicious_activity(ip, dns_query=None):
    geo_info = get_geoip_details(ip)
    reverse_dns_name = reverse_dns(ip)
    threat_intelligence = threat_intelligence_check(ip)
    open_ports = scan_ports(ip)
    tests = perform_network_tests(ip)
    device_info = get_device_details()

    # Define reasoning for suspicious activity
    if geo_info.get("status") == "fail":
        reason = "GeoIP lookup failed. Suspicious destination."
    elif geo_info.get("country") not in ["United States", "Canada", "United Kingdom"]:
        reason = f"Unusual country detected: {geo_info.get('country', 'Unknown')}."
    elif threat_intelligence.get("malicious", 0) > 0 or threat_intelligence.get("suspicious", 0) > 0:
        reason = "Threat intelligence flagged the IP as malicious."
    elif len(open_ports) > 10:
        reason = "Unusually high number of open ports detected."
    else:
        reason = "Flagged for unknown reasons. Requires further investigation."

    return {
        "geo_info": geo_info,
        "reverse_dns": reverse_dns_name,
        "threat_intelligence": threat_intelligence,
        "open_ports": open_ports,
        "network_tests": tests,
        "device_info": device_info,
        "reason": reason
    }

# Packet processing function
def process_packet(packet):
    global network_alerts
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dns_query = None

        # Check for DNS queries
        if packet.haslayer(DNS) and packet[DNS].qd:
            dns_query = packet[DNS].qd.qname.decode("utf-8")

        # Analyze suspicious activity
        analysis = analyze_suspicious_activity(dst_ip, dns_query)

        # Common alert structure
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dns_query": dns_query or "N/A",
            "geo_info": analysis["geo_info"],
            "reverse_dns": analysis["reverse_dns"],
            "threat_intelligence": analysis["threat_intelligence"],
            "open_ports": analysis["open_ports"],
            "network_tests": analysis["network_tests"],
            "device_info": analysis["device_info"],
            "reason": analysis["reason"],
            "measures": "Block the IP or conduct a deeper investigation.",
            "whois": get_whois_info(src_ip),
            "abuse_score": check_abuse_ip(src_ip)
        }

        # Check for anomalies
        if is_anomalous(src_ip) or is_anomalous(dst_ip):
            alert.update({
                "alert": "Anomalous Traffic Detected",
                "measures": "Investigate and block if necessary."
            })
            network_alerts.append(alert)
            return

        # Check for SYN Flood
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            if traffic_stats.get(src_ip, 0) > 100:  # Example threshold for SYN packets
                alert.update({
                    "alert": "Possible SYN Flood Attack",
                    "measures": "Investigate and block if necessary."
                })
                network_alerts.append(alert)
                return

        # Check for high entropy payloads
        if packet.haslayer("Raw"):
            payload = bytes(packet["Raw"].load)
            entropy = -sum(p / len(payload) * (p / len(payload)).bit_length() for p in payload)
            if entropy > 7.5:  # High entropy threshold
                alert.update({
                    "alert": "High Entropy Payload (Potential Obfuscation)",
                    "measures": "Inspect payload and block if necessary."
                })
                network_alerts.append(alert)
                return

        # If no specific anomalies are detected, add a general alert
        network_alerts.append(alert)

# Function to detect attacks based on traffic patterns
def detect_attack(packet):
    global network_alerts
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        alert = None
        print("Packet detected:", packet.summary())
        # DNS Analysis
        dns_query = packet[DNS].qd.qname.decode("utf-8") if packet.haslayer(DNS) and packet[DNS].qd else None

        # Detect common attack patterns
        if TCP in packet and packet[TCP].flags == "S":
            alert = "Possible SYN Flood Attack"
        elif UDP in packet and len(packet) > 1024:
            alert = "Possible UDP Flood Attack"
        elif dns_query and "xn--" in dns_query:  # Look for Punycode (potential phishing domains)
            alert = "Suspicious DNS Query (Punycode Domain)"
        elif dst_ip.startswith("180.163"):  # Example for specific IP range filtering
            alert = "Traffic to high-risk IP range"

        # Inspect payload for obfuscation (entropy > 7.5 is suspicious)
        payload = bytes(packet[IP].payload)
        if calculate_entropy(payload) > 7.5:
            alert = "High Entropy Payload (Potential Obfuscation)"

        if alert:
            # Enrich data with external intelligence
            malicious, suspicious = process_packet(dst_ip)
            reverse_dns, whois_info = domain_details(dst_ip)

            network_alerts.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dns_query": dns_query or "N/A",
                "alert": alert,
                "malicious_reports": malicious,
                "suspicious_reports": suspicious,
                "reverse_dns": reverse_dns,
                "whois": whois_info,
                "measures": "Investigate source IP and block if necessary."
            })

# Function to calculate the SHA-256 hash of a file
def calculate_file_hash(file_path):
    try:
        sha256_hash = hashlib.sha256()
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
    global process_list, yara_matched_processes
    process_list = []
    yara_matched_processes = [] 
    
    
      # Counter for suspicious processes
    
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
            is_suspicious_yara=False
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

            try:
                yara_match = rules.match(process_exe)
                if yara_match:
        # Check if yara_match is a list and contains at least one match
                    if isinstance(yara_match, list) and len(yara_match) > 0:
                        rule_name = yara_match[0].rule  # Get the rule name from the first match
                        is_suspicious_yara = True
                        alert_message = f"YARA match: {rule_name} on {process_name} (PID: {proc.pid})"
                        logging.warning(alert_message)
                        detection_alerts.append(alert_message)
                        logging.info(f"YARA matches found for {process_name} (PID: {proc.pid})")
            # Add YARA-matched process details to the global list
                        yara_matched_processes.append({
                'pid': proc.pid,
                'name': process_name,
                'exe': process_exe,
                'rule': rule_name
            })
                    
            except Exception as e:
                 logging.error(f"Unexpected error during YARA match for file {process_exe}: {e}")

            # Increment suspicious process count if marked as suspicious
            if is_suspicious_yara:
                suspicious_process_yara += 1
            if is_suspicious_process:
                suspicious_process +=1

            # Append process details to process list
            process_list.append({
                'pid': proc.pid,
                'name': process_name,
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'exe': process_exe,
                'is_suspicious_process': is_suspicious_process,
                'is_suspicious_yara': is_suspicious_yara
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            access_denied_processes.append({'pid': proc.pid, 'name': proc.info['name']})
            logging.warning(f"Access denied for process (PID: {proc.pid}), unable to retrieve information.")
            continue

   
    


@app.route("/")
def index():
    try:
        return render_template("index.html",detection_alerts=detection_alerts)
    except Exception as e:
        logging.error(f"Error rendering index.html: {e}")
        return jsonify({"error": "Unable to load index page."})

 # Render frontend.html for the /frontend route

@app.route('/frontend')
def frontend():
    return render_template('frontend.html', detection_alerts=detection_alerts)

 # Render frontend.html for the /frontend route
@app.route('/process')
def process():
    return render_template('process.html', detection_alerts=detection_alerts)





@app.route("/filemonitor")
def filemonitor():
    return render_template("filemonitor.html",detection_alerts=detection_alerts)


@atexit.register
def cleanup():
    file_monitor.stop()

# Flask route to get the detection alerts dynamically
@app.route('/alerts')
def get_alerts():
    return jsonify(alerts=detection_alerts)

@app.route('/processes')
def get_processes():
    sorted_process_list = sorted(process_list, key=lambda x: x['is_suspicious_process'], reverse=True)
    return jsonify(processes=sorted_process_list)

# Flask route to get details of a suspicious process

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
    
    if metric_type == 'cpu':
        data = {proc['name']: proc['cpu_percent'] for proc in process_list}
    else:  # default to memory
        data = {proc['name']: proc['memory_percent'] for proc in process_list}
    
    return jsonify(metrics=data)

@app.route('/yara_matches')
def get_yara_matches():
    return jsonify(yara_matches=yara_matched_processes)

@app.route("/alert")
def get_alert():
    return jsonify(file_monitor.get_alert())

@app.route('/total_suspicious')
def get_total_suspicious():
    total_suspicious = sum(1 for proc in process_list if proc.get('is_suspicious_process', False))
    return jsonify(total_suspicious=total_suspicious)

@app.route('/Network_alerts')
def Network_alerts():
    return jsonify(network_alerts)

@app.route('/network')
def network():
    return render_template('network.html')

@app.route('/yara_suspicious')
def yara_suspicious():
    yara_suspicious = sum(1 for proc in process_list if proc.get('is_suspicious_yara', False))
    return jsonify(yara_suspicious=yara_suspicious)

@atexit.register
def cleanup():
    file_monitor.stop()

def continuous_monitoring():
    try:
        while True:
            
            sniff(filter="ip", prn=lambda packet: (process_packet(packet), detect_attack(packet)), store=False)
            detect_keylogger()
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user.")
is_monitoring = False

@app.route('/start', methods=['POST'])
def start_monitoring():
    global is_monitoring
    if not is_monitoring:
        is_monitoring = True
        logging.info("Monitoring started.")
        
        detect_keylogger()  # Call your detection function
    return jsonify({"status": "Monitoring started"})

@app.route('/stop', methods=['POST'])
def stop_monitoring():
    global is_monitoring
    if is_monitoring:
        is_monitoring = False
        logging.info("Monitoring stopped.")
        # Add any cleanup logic if needed
    return jsonify({"status": "Monitoring stopped"})

def start_flask():
    app.run(debug=False, use_reloader=False)
if __name__ == "__main__":
    try:
        flask_thread = threading.Thread(target=start_flask)
        flask_thread.start()
        continuous_monitoring()
        app.run(host="0.0.0.0", port=5000)
    except KeyboardInterrupt:
        print("Monitoring stopped by user.")
    
    
