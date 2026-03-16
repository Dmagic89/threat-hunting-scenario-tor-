<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Dmagic89/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md) 

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

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “dmagic89” downloaded a tor installer, did something that resulted in many tor-related file being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2026-03-03T11:28:36.5253281Z. These events began at: 2026-03-03T10:27:55.1039831Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "davis-vm-final"
| where InitiatingProcessAccountName == "dmagic89"
| where  FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account =InitiatingProcessAccountName

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-15.0.7.exe". Based on the logs returned, At 2026-03-03T11:10:06.4322538Z, the user dmagic89 on the virtual machine davis-vm-final executed the file tor-browser-windows-x86_64-portable-15.0.7.exe from their Downloads folder using the /S switch, which silently launched the Tor Browser installer in the background without any visible prompts to the user.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "davis-vm-final"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"
|project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “dmagic89” actually opened the tor browser. There was evidence that they did open it at 2026-03-03T11:11:11.5533093Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "davis-vm-final"
| where FileName has_any ("tor-browser-setup.exe","firefox.exe","tor.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2026-03-03T11:11:47.471268Z, the user dmagic89 on the virtual machine davis-vm-final successfully established an outbound network connection using tor.exe (located in the Tor Browser folder on the user’s Desktop) to the remote IP address 136.244.82.118 over port 9001, connecting to the URL. https://www.x6jlacydzw7j6.com.There were a couple other connections to sites over port 443.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "davis-vm-final"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("firefox.exe","tor.exe")
| where RemotePort  in ("9050","9150","9001","9030","9051","80","443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. Initial Tor-Related File Activity

- **Timestamp:** `2026-03-03T10:27:55.1039831Z`
- **Device:** `davis-vm-final`
- **User:** `dmagic89`
- **Event:** Tor-related files discovered on the system.
- **Details:**  
  File event logs revealed the presence of multiple files containing the string **"tor"**, indicating that Tor-related content had been downloaded or extracted on the device. These file events mark the earliest observed Tor-related activity during the investigation timeframe.
- **File Location:**  
  Multiple locations, including user Desktop directories.

---

### 2. Process Execution – Tor Browser Installer

- **Timestamp:** `2026-03-03T11:10:06.4322538Z`
- **Device:** `davis-vm-final`
- **User:** `dmagic89`
- **Event:** Tor Browser installer executed.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.7.exe /S`
- **File Path:** `C:\Users\Dmagic89\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`
- **Details:**  
  The Tor Browser installer was executed from the user's **Downloads** directory. The `/S` switch indicates that the installer ran in **silent mode**, meaning the installation occurred without visible prompts or user interaction.

---

### 3. Process Execution – Tor Browser Launch

- **Timestamp:** `2026-03-03T11:11:11.5533093Z`
- **Device:** `davis-vm-final`
- **User:** `dmagic89`
- **Event:** Tor Browser session initiated.
- **Action:** Process creation detected.
- **Details:**  
  Process creation logs confirm that the Tor Browser was launched. Multiple associated processes were generated, including **firefox.exe**, which serves as the Tor Browser interface, and **tor.exe**, which manages Tor network communications.
- **File Paths:**
  - `C:\Users\Dmagic89\Desktop\Tor Browser\Browser\firefox.exe`
  - `C:\Users\Dmagic89\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

### 4. Network Connection – Tor Relay Communication

- **Timestamp:** `2026-03-03T11:11:47.471268Z`
- **Device:** `davis-vm-final`
- **User:** `dmagic89`
- **Event:** Outbound connection to Tor relay node.
- **Action:** Network connection detected.
- **Process:** `tor.exe`
- **Remote IP:** `136.244.82.118`
- **Remote Port:** `9001`
- **Remote URL:** `https://www.x6jlacydzw7j6.com`
- **Process Path:** `C:\Users\Dmagic89\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- **Details:**  
  The **tor.exe** process established an outbound connection to a Tor relay server over port **9001**, which is commonly used for Tor relay traffic. This confirms the device successfully connected to the **Tor anonymity network** and began routing traffic through Tor nodes.

---

### 5. Additional Tor Network Activity

- **Timestamps:**
  - `2026-03-03T11:12:05Z` – Connection established over port `443`
  - `2026-03-03T11:12:12Z` – Local connection to `127.0.0.1`
- **Event:** Additional Tor network communications detected.
- **Action:** Multiple successful encrypted connections observed.
- **Details:**  
  Additional encrypted connections over port **443** were detected, which is consistent with **Tor browser traffic routing through multiple relay nodes**.

---

### 6. File Creation – Tor Shopping List

- **Timestamp:** `2026-03-03T11:28:36.5253281Z`
- **Device:** `davis-vm-final`
- **User:** `dmagic89`
- **Event:** File creation detected.
- **Action:** File written to disk.
- **File Path:** `C:\Users\Dmagic89\Desktop\tor-shopping-list.txt`
- **Details:**  
  A file named **tor-shopping-list.txt** was created on the user's Desktop during the investigation timeframe. The filename suggests potential user interaction with the system during or after Tor browsing activity.
---

## Summary

The investigation shows that the user dmagic89 on the virtual machine davis-vm-final downloaded and
executed the Tor Browser portable installer. The installer was run using a silent installation switch (/S),
which launched the setup without user prompts. Shortly after installation, the user opened the Tor Browser,
which started the tor.exe and firefox.exe processes associated with Tor.
Within seconds of launching the browser, the system successfully established outbound network
connections to the Tor network, including a connection to the external IP 136.244.82.118 over port 9001, a
port commonly used for Tor relay communication. Additional encrypted connections over port 443 were also
observed. During the activity, multiple Tor-related files were created or copied to the user's Desktop, including a
file named tor-shopping-list.txt.
Overall, the logs confirm that the user downloaded, installed, launched, and used the Tor Browser to
connect to the Tor network from the device.

---

## Response Taken

TOR usage was confirmed on endpoint Davis-VM-final by the user dmagic89. The device was isolated and the user's direct manager was notified.

---
