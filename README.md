# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/GaddisM/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “gaddis” downloaded a tor installer, did something that resulted in many tor-related file being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. And I discovered the computer named “gdsvm” recorded that the user account “gaddis” silently launched the Tor Browser installer from their Downloads folder, creating a new process for the file tor-browser-windows-x86_64-portable-15.0.4.exe.

These events began at : '2026-01-29T20:50:09.3692583Z'


**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "gdsvm"  
| where InitiatingProcessAccountName == "gaddis"  
| where FileName contains "tor"  
| where Timestamp >= datetime('2026-01-29T20:50:09.3692583Z')
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"   
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1273" height="433" alt="Screenshot 2026-01-30 at 15 53 23" src="https://github.com/user-attachments/assets/10747ae4-76b9-4f92-95e0-a1692e4b197e" />

---

### 2. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “gaddis” actually opened the tor browser. There was evidence that they open it at 2026-01-29T20:24:52.0129405Z
There were several other instances of firefox.exe (tor) as well as tor.exe spawned afterwards.


**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "gdsvm"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1284" height="482" alt="Screenshot 2026-01-30 at 16 18 58" src="https://github.com/user-attachments/assets/365d997f-893e-4d3e-bde2-09c6528b19ac" />


---

### 3. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At 2026-01-29T20:25:21.0842054Z, the workstation “gdsvm” showed the user “Gaddis” successfully establishing a network connection when the Tor executable tor.exe, launched from the Tor Browser folder on the desktop, reached out across the internet to the remote IP address 127.0.0.1 on port 9150. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\gaddis\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql

DeviceNetworkEvents
| where DeviceName == "gdsvm"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ('9001', '9030', '9040', '9050', '9051', '9150', '80', '443')
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1382" height="451" alt="Screenshot 2026-01-30 at 16 42 43" src="https://github.com/user-attachments/assets/a5d6dfe9-c155-4942-aa82-83a7b77b1c17" />


---

## Chronological Event Timeline 

2026-01-29 20:50 UTC

 Tor-related file activity was first observed on the workstation “gdsvm” under the user “gaddis,” indicating the Tor Browser installer had been downloaded.

 
~20:24–20:25 UTC

 The user executed the Tor Browser portable installer from the Downloads folder, resulting in multiple Tor-related files being extracted to the desktop.

 
20:24:52 UTC

 The user launched Tor Browser. Process logs confirmed firefox.exe (Tor) and tor.exe were spawned.

 
20:25:21 UTC

 Tor successfully established a network connection via tor.exe using port 9150, consistent with Tor proxy behavior. Additional encrypted connections over port 443 followed.

 
~20:25–20:32 UTC

 User interaction continued, including the creation of a file named tor-shopping-list.txt on the desktop, confirming active use of Tor Browser.


---

## Summary

On January 29, 2026, the user “gaddis” on the workstation “gdsvm” downloaded and executed the Tor Browser portable installer. Following installation, Tor Browser files were extracted to the desktop, and the browser was actively launched. Process creation logs confirmed the execution of both firefox.exe (Tor Browser) and tor.exe.
Network telemetry showed successful Tor network connectivity using known Tor ports, including port 9150, as well as encrypted outbound HTTPS connections consistent with Tor usage. The creation of a user-authored file named `tor-shopping-list.txt` indicates intentional and interactive use of Tor Browser rather than accidental execution.
Overall, the evidence clearly demonstrates successful installation, launch, and active use of Tor Browser on the endpoint during the observed timeframe.

---

## Response Taken

TOR usage was confirmed on the endpoint gdsvm by the user gaddis. 

The device was isolated and the user's direct manager was notified.


---
