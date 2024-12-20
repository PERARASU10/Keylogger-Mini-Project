# Implementing keylogging malware and detecting keylogging technology

## Keylogger 

## Overview

This project is a simple keylogger designed for educational purposes. It captures keystrokes from the user’s keyboard and send the keystrokes via email and logs them into a file for later analysis. The keylogger can be used to understand how keystroke logging works and to demonstrate potential security risks associated with keyloggers.
Features

*  Logs all keystrokes made by the user
*  Its capture input key and send to email.
*  Saves the logs to a local file
*  Runs in the background with minimal system impact
*  Works on [Operating Systems: Windows/Linux (specify based on your project)]
*  [Additional features like email reporting, screenshot capture, etc.]

## Installation

  Clone the Repository

```
[git clone https://github.com/yourusername/keylogger.git](https://github.com/PERARASU10/Keylogger-Project.git)
```
Navigate to the Project Directory
```
cd keylogger-Project
```
Install Dependencies

  Python 3.x is required.
  Install the necessary libraries:
  ```
    pip install smtplib
    pip install pynput
    pip install keyboards
    pip install time
  ```
Run the Keylogger
```
    python keylogger.py
```

## Screenshots

![Screenshot from 2024-09-03 23-19-50](https://github.com/user-attachments/assets/16704083-66c4-44ab-b009-15f8112a72fc)

![Screenshot from 2024-09-03 23-20-23](https://github.com/user-attachments/assets/173d8bb6-49d7-419e-a070-2048888e5a0d)

## Usage

Once the keylogger is running, it will start capturing keystrokes and save them to a file (log.txt by default).
You can stop the keylogger by [specify how to stop it, e.g., closing the terminal, pressing a specific key combination, etc.].
Review the log.txt file to see the captured keystrokes.

## Legal Disclaimer

This keylogger is intended for educational purposes only. Unauthorized use of this software to capture keystrokes without the consent of the user is illegal and unethical. Please ensure you have the appropriate permissions before using this tool.

## Contributing

If you would like to contribute to this project, feel free to fork the repository and submit a pull request. Contributions that enhance the functionality or security of the keylogger are welcome.

## Keylogger Detection:
## About :

  The Keylogger Detection system is designed to identify potential keylogging activity on a system by monitoring processes, network packets, file activities, and suspicious patterns using advanced techniques like machine learning, YARA rules, and signature-based detection. It integrates real-time packet sniffing, process inspection, and DNS/SNMP analysis to ensure robust protection against keylogger threats.

## Features :
  1.Real-Time Process Monitoring:
      Identifies malicious processes based on known signatures and hash matching.
      Tracks high CPU and memory usage by suspicious processes.
      Access denied processes are logged for further analysis.
      
  2.Network Activity Monitoring:
      Captures DNS queries and SMTP connections to detect suspicious communications.
      Monitors packet-level information for potential malicious activity.
      
  3.File Activity Detection:
      Watches for unauthorized file access in monitored directories.
      Integrates with YARA rules to scan files for suspicious patterns.
      
 4.Machine Learning Integration:
      Uses a pre-trained Random Forest model for real-time keylogger prediction based on packet flow features.
      Data is scaled for accurate predictions.
      
 5.VirusTotal Integration:
      Queries VirusTotal for reputation checks of IPs associated with captured packets.
      
 6.Web-Based Interface:
      Flask and SocketIO provide a real-time dashboard for process monitoring, alerts, and network analysis.
## Requirements:
  1.Python Libraries:
       Flask, SocketIO, psutil, scapy, yara, joblib, numpy, and requests.
     
   2.Pre-trained Files:
       Random Forest model (random_forest_model.pkl).
       Scaler for feature transformation (scaler.pkl).
     
   3.System Permissions:
       Administrator/root access for packet sniffing and system-level process monitoring.
     
   4.External Services:
       VirusTotal API key for reputation checks.
## System Architecture :
![DALL·E 2024-12-09 12 30 31 - A simple system architecture diagram for a keylogger detection system  The diagram includes_ (1) 'Data Collection Layer' at the bottom, with component](https://github.com/user-attachments/assets/30af32bd-7862-4f8d-8ecc-a2e36669bf85)
## Output :

![photo-collage png (1)](https://github.com/user-attachments/assets/3246d1f7-cbd1-4779-b3f1-3543d301ec45)
![photo-collage png](https://github.com/user-attachments/assets/a7ab862a-291f-4e17-9a08-fcef455f0933)

## Results and Impact :

  1.Enhanced Security:
       Real-time detection and prevention of keylogger activities.
       Reduces the risk of sensitive data theft.
     
   2.Scalability:
       Extensible to include additional rules, machine learning models, or external APIs.
     
   3.Transparency:
       Web-based alerts and logs provide actionable insights to the user.
     
  4.Proactive Defense:
       Combines traditional signature-based detection with machine learning for adaptive threat identification.
     
   5.Usability:
       Intuitive UI and detailed logs make the tool accessible for both technical and non-technical users.
