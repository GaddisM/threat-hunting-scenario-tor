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

<img width="1202" height="472" alt="Screenshot 2026-01-30 at 16 34 14" src="https://github.com/user-attachments/assets/8e0de700-65aa-46ca-8185-b714aff5752a" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

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
