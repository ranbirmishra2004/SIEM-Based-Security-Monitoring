# 🛡️ SIEM-Based SOC Monitoring, Threat Detection & Incident Investigation

## Hands-On SOC Analyst Project Using Splunk Enterprise

A hands-on **Security Operations Center (SOC) laboratory project** focused on centralized security monitoring, Windows event-log collection, SPL-based threat detection, alert analysis, and incident investigation using **Splunk Enterprise**.

The project demonstrates an end-to-end SOC workflow:

> **Collect → Index → Search → Detect → Investigate → Validate → Document → Improve**

The primary detection scenario focuses on **Windows Event ID 4625 (Failed Logon)** and demonstrates how repeated authentication failures can be identified, investigated, and classified using security telemetry.

---

## 🎯 Project Objective

The objective of this project was to build a practical SIEM-based SOC environment rather than simply installing Splunk.

The laboratory demonstrates how a SOC analyst can:

- Collect Windows security telemetry
- Forward endpoint logs to a centralized SIEM
- Store events in a dedicated Splunk index
- Search and analyze security events using SPL
- Detect repeated failed authentication attempts
- Investigate suspicious authentication activity
- Correlate event fields and timestamps
- Create an incident investigation workflow
- Map relevant activity to MITRE ATT&CK
- Document findings and limitations
- Identify future detection-engineering improvements

---

## 🏗️ Project Architecture

```text
                         SOC ANALYST WORKFLOW
                                 │
                                 ▼
┌──────────────────────┐
│   Windows 10 VM      │
│                      │
│ Security Logs        │
│ System Logs          │
│ Application Logs     │
│ PowerShell Logs      │
└──────────┬───────────┘
           │
           │ Universal Forwarder
           │
           │ TCP 9997
           ▼
┌──────────────────────────────┐
│       Ubuntu VM              │
│                              │
│    Splunk Enterprise         │
│                              │
│    Index: soc-project1       │
│    Receiving: TCP 9997       │
└──────────────┬───────────────┘
               │
               │ SPL Searches
               ▼
┌──────────────────────────────┐
│     Detection Engineering   │
│                              │
│ Event ID 4625                │
│ Failed Authentication        │
│ Threshold ≥ 5                │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│       SOC Analyst            │
│                              │
│ Detect → Triage → Correlate  │
│ → Decide → Close             │
└──────────────┬───────────────┘
               │
               ▼
        ┌──────────────┐
        │  SOC-001     │
        │  Investigation│
        └──────────────┘
```

---

## 🧪 Laboratory Environment

| Component | Configuration |
|---|---|
| Endpoint | Windows 10 x64 |
| Windows Build | 19045 |
| Endpoint Agent | Splunk Universal Forwarder 10.4.3 |
| Splunk Server | Ubuntu 26.04.1 LTS |
| SIEM | Splunk Enterprise 10.4.3 |
| Splunk Index | `soc-project1` |
| Forwarding Port | TCP `9997` |
| Splunk Web Port | `8000` |
| Test Account | `splunktest` |
| Virtualization | VMware |

The project used two virtual machines connected through a laboratory network.

> **Note:** The network subnet changed during the project from `192.168.7.0/24` to `192.168.1.0/24`. This required updating the Universal Forwarder destination configuration and troubleshooting forwarding errors.

---

# 📥 Log Collection

The Windows Universal Forwarder was configured to collect multiple Windows event channels.

### Configured log sources

```text
Windows Security
Windows System
Windows Application
Microsoft-Windows-PowerShell/Operational
```

The collected events were forwarded to the Splunk server over:

```text
TCP 9997
```

and stored in:

```text
index=soc-project1
```

---

# ⚙️ Splunk Forwarder Configuration

The forwarding architecture uses two primary configuration files.

### `inputs.conf`

Defines **what telemetry should be collected**.

Example structure:

```ini
[WinEventLog://Security]
disabled = 0
index = soc-project1

[WinEventLog://System]
disabled = 0
index = soc-project1

[WinEventLog://Application]
disabled = 0
index = soc-project1

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = soc-project1
```

### `outputs.conf`

Defines **where the collected telemetry should be sent**.

```ini
[tcpout]
defaultGroup = soc-indexer

[tcpout:soc-indexer]
server = <SPLUNK_SERVER_IP>:9997
```

The destination IP must match the current Splunk server address.

---

# 🔎 Windows Security Event Monitoring

The project focused primarily on Windows authentication telemetry.

Important Windows Event IDs examined include:

| Event ID | Activity |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Explicit credential use |
| 4672 | Special privileges assigned |
| 4720 | User account created |
| 4726 | User account deleted |
| 4740 | Account locked out |
| 4688 | Process creation |
| 4104 | PowerShell Script Block Logging |

---

# 🚨 Primary Detection: Event ID 4625

The primary detection scenario is based on:

```text
EventCode = 4625
```

which represents a **failed Windows logon attempt**.

A single failed authentication attempt is not necessarily malicious.

However, repeated failures involving the same source and account within a short period may represent a useful investigation candidate.

For the laboratory, the detection threshold was:

```text
5 or more failed logons
```

---

# 🧩 Event 4625 Analysis

The investigation examined important event fields including:

```text
EventCode
Account_Name
Source_Network_Address
Logon_Type
Status
Sub_Status
_time
```

Example laboratory activity:

```text
Account:        splunktest
Source:         127.0.0.1
Logon Type:     2
Event Code:     4625
Sub-Status:     0xC000006A
```

The sub-status:

```text
0xC000006A
```

was associated with a valid user and incorrect password in the investigated event.

---

# 🔍 SPL Detection Logic

The detection uses Splunk Search Processing Language (SPL) to identify repeated failed logons.

Core logic:

```spl
index=soc-project1
LogName=Security
EventCode=4625
| eval target_user=mvindex(Account_Name,1)
| stats count by Source_Network_Address,target_user
| where count >= 5
| sort -count
```

### Detection workflow

```text
1. Filter
      ↓
2. Extract
      ↓
3. Count
      ↓
4. Apply Threshold
      ↓
5. Rank Results
```

The resulting candidate in the laboratory was:

```text
Source: 127.0.0.1
User:   splunktest
Count:  5
```

---

# 📊 Detection Engineering Library

The project also defined a broader detection-engineering library.

### DET-01 — Failed Logon Baseline

Identifies sudden increases or clusters of failed authentication activity.

### DET-02 — Authentication Burst

Identifies repeated failed logons reaching the defined threshold within a time window.

### DET-03 — Source IP Concentration

Identifies one source attempting authentication against multiple accounts.

### DET-04 — Username Concentration

Identifies one account receiving authentication attempts from multiple sources.

### DET-05 — 4624 / 4625 Correlation

Looks for successful authentication occurring after repeated failures.

### DET-06 — PowerShell Script Block Monitoring

Uses PowerShell Event ID 4104 telemetry to identify potentially suspicious script activity.

---

# 📈 Dashboard & Alerting

The project defined an analyst-oriented Splunk dashboard containing areas such as:

- Total failed logins
- Failed logins by username
- Failed logins by source IP
- Authentication activity over time
- PowerShell activity
- Brute-force candidates

The alert logic is designed around the failed-logon threshold:

```text
EventCode = 4625
        ↓
Group by source + account
        ↓
Count failures
        ↓
Count >= 5
        ↓
Generate investigation candidate
```

### Project Status

The dashboard and alert architecture were specified as part of the project.

The current project documentation does **not** claim that the complete six-panel dashboard capture and alert firing were fully evidenced.

This distinction is intentional because a SOC analyst should clearly separate:

> **Implemented evidence vs. planned functionality vs. untested functionality.**

---

# 🔥 Incident Investigation — SOC-001

## Incident Overview

The primary investigation was documented as:

```text
Incident ID: SOC-001
```

The incident was generated around five failed authentication events.

### Timeline

```text
13:17:34 → Failed Logon
13:17:38 → Failed Logon
13:17:41 → Failed Logon
13:17:45 → Failed Logon
13:17:49 → Failed Logon
```

The five events crossed the laboratory detection threshold.

---

## 🕵️ SOC Investigation Workflow

The investigation followed:

```text
Detect
   ↓
Triage
   ↓
Correlate
   ↓
Decide
   ↓
Close
```

### Detection

Five failed authentication attempts reached the configured threshold.

### Triage

The analyst examined:

- Account
- Source address
- Logon type
- Status
- Sub-status
- Timestamp

### Correlation

The activity involved:

```text
Account: splunktest
Source:  127.0.0.1
```

The authentication failure was associated with an incorrect-password status.

### Decision

The available telemetry was consistent with controlled laboratory testing.

### Final Verdict

```text
Known controlled test activity
```

```text
Compromise: NOT OBSERVED
```

The incident was closed without claiming compromise.

---

# 🧠 Important SOC Principle

One of the most important lessons from this project was:

> **A detection is not automatically an attack.**

A threshold-based alert identifies activity that deserves investigation.

The analyst must validate:

```text
Who?
What?
When?
Where?
How?
Why?
```

before deciding whether the activity represents malicious behavior.

This project therefore avoids claiming that the five failed logons represented a confirmed attack.

---

# 🎯 MITRE ATT&CK Mapping

Relevant detection concepts were mapped to MITRE ATT&CK techniques.

| Technique | Description | Project Status |
|---|---|---|
| T1110.001 | Password Guessing | Pattern / detection relevance |
| T1110.003 | Password Spraying | Not tested |
| T1110.004 | Credential Stuffing | Not tested |
| T1078 | Valid Accounts | Not tested |
| T1059.001 | PowerShell | 4104 telemetry present |
| T1021.001 | RDP | Not tested |

### Important distinction

The ATT&CK mapping represents **relevance to the telemetry and detection scenarios**.

It does **not** mean that an adversary was confirmed to have performed every mapped technique.

---

# 🔐 Security Monitoring Workflow

The overall SOC workflow developed in this project can be summarized as:

```text
                 ┌───────────────┐
                 │ Windows Logs  │
                 └───────┬───────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Universal       │
                │ Forwarder       │
                └────────┬────────┘
                         │
                      TCP 9997
                         │
                         ▼
                ┌─────────────────┐
                │ Splunk          │
                │ Enterprise      │
                └────────┬────────┘
                         │
                         ▼
                   ┌──────────┐
                   │   SPL    │
                   └────┬─────┘
                        │
                        ▼
                  ┌───────────┐
                  │ Detection │
                  └─────┬─────┘
                        │
                        ▼
                  ┌───────────┐
                  │   Triage  │
                  └─────┬─────┘
                        │
                        ▼
                 ┌─────────────┐
                 │ Investigation│
                 └──────┬──────┘
                        │
                        ▼
                 ┌─────────────┐
                 │ SOC-001     │
                 │ Case Close  │
                 └─────────────┘
```

---

# 🧰 Technologies Used

### SIEM

- Splunk Enterprise
- Splunk Search Processing Language (SPL)

### Endpoint

- Windows 10
- Windows Event Logs
- PowerShell Operational Logs
- Splunk Universal Forwarder

### Server

- Ubuntu 26.04.1 LTS

### Networking

- TCP/IP
- TCP 9997
- Port validation
- ICMP connectivity testing

### Security Operations

- SIEM monitoring
- Authentication monitoring
- Threat detection
- Event analysis
- Incident triage
- Incident investigation
- MITRE ATT&CK mapping

### Virtualization

- VMware

---

# 📂 Repository Structure

```text
splunk-soc-analyst-project/
│
├── README.md
│
├── presentation/
│   └── Splunk_SOC_Project_Presentation_v2.pptx
│
├── documentation/
│   └── SOC_Project_Report.pdf
│
├── screenshots/
│   ├── architecture.png
│   ├── network-validation.png
│   ├── splunk-index.png
│   ├── event-4625.png
│   ├── spl-query.png
│   ├── detection-result.png
│   ├── dashboard.png
│   └── incident-soc-001.png
│
├── splunk-config/
│   ├── inputs.conf
│   └── outputs.conf
│
└── queries/
    └── failed-logon-detection.spl
```

---

# 📸 Project Evidence

Screenshots and supporting evidence should be organized according to the investigation workflow.

Recommended evidence:

1. Windows endpoint configuration
2. Ubuntu server configuration
3. IP configuration
4. Network connectivity
5. TCP 9997 validation
6. Splunk receiving configuration
7. Splunk index
8. Universal Forwarder configuration
9. Windows Event Viewer
10. Event ID 4625
11. SPL detection query
12. Detection results
13. Authentication timeline
14. Dashboard
15. SOC-001 investigation

---

# ⚠️ Project Limitations

The laboratory environment has several limitations:

- One Windows endpoint
- Low-volume laboratory telemetry
- Fixed detection thresholds
- No implemented SOAR response
- No automated email response
- Sysmon telemetry not included
- Linux SSH telemetry not included
- Limited enterprise-scale log volume
- Several ATT&CK scenarios were not tested

These limitations mean the project should be viewed as a **SOC laboratory and detection-engineering demonstration**, rather than a production SOC deployment.

---

# 🚀 Future Improvements

The next iteration of the project can include:

### Endpoint Visibility

- Deploy Sysmon
- Monitor process creation
- Monitor PowerShell activity
- Monitor persistence-related events

### Linux Monitoring

- Collect Linux authentication logs
- Monitor SSH authentication
- Detect SSH brute-force patterns

### Multi-Endpoint SOC

- Add multiple Windows endpoints
- Centralize telemetry from multiple systems
- Compare authentication activity across hosts

### Detection Engineering

- Improve time-window logic
- Create dynamic thresholds
- Reduce false positives
- Add 4624/4625 correlation
- Develop additional correlation searches

### Threat Intelligence

- GeoIP enrichment
- Threat-intelligence feeds
- Malicious IP reputation
- IOC enrichment

### Automation

- SOAR integration
- Automated ticket creation
- Automated notification
- Automated containment workflows

---

# 📚 Key Skills Demonstrated

This project demonstrates practical exposure to:

```text
SIEM Deployment
        ↓
Log Collection
        ↓
Log Forwarding
        ↓
Windows Security Monitoring
        ↓
SPL Query Development
        ↓
Detection Engineering
        ↓
Alert Analysis
        ↓
Incident Triage
        ↓
Incident Investigation
        ↓
MITRE ATT&CK Mapping
        ↓
Security Documentation
```

---

# 💼 SOC Analyst Perspective

This project was designed around the responsibilities of an entry-level SOC Analyst.

Rather than focusing only on the technical installation of Splunk, the project emphasizes the analyst workflow:

> **Collect → Monitor → Detect → Investigate → Validate → Document → Improve**

The most important takeaway is that effective SOC operations require both **technical detection skills** and **analytical judgment**.

A security alert should be investigated using available evidence before assigning a final verdict.

---

# 📊 Project Outcome

The project successfully demonstrates a controlled SIEM monitoring workflow in which:

- Windows security telemetry is collected
- Logs are forwarded through Splunk Universal Forwarder
- Events are centralized in Splunk
- Event ID 4625 is analyzed
- SPL is used to aggregate failed authentication attempts
- A threshold-based detection identifies an investigation candidate
- SOC-001 is investigated
- The activity is classified as controlled laboratory testing
- No compromise is claimed based on the available evidence
- Detection limitations and future improvements are documented

---

# 👨‍💻 Author

**Ranbir Mishra**

**MCA — Cybersecurity & Security Operations**

Focus Areas:

- SOC Operations
- SIEM
- Splunk
- Threat Detection
- Incident Investigation
- Security Monitoring
- Linux
- Network Security
- Log Analysis

---

# ⭐ Project Highlights

```text
✔ Splunk Enterprise SIEM
✔ Windows Security Event Monitoring
✔ Universal Forwarder
✔ TCP 9997 Log Forwarding
✔ SPL Detection Engineering
✔ Event ID 4625 Analysis
✔ Threshold-Based Detection
✔ SOC-001 Incident Investigation
✔ MITRE ATT&CK Mapping
✔ Security Documentation
✔ SOC Workflow Demonstration
```

---

## 📌 Disclaimer

This project was developed in an isolated laboratory environment for **educational, cybersecurity training, SOC analysis, and detection-engineering purposes**.

The authentication events and investigation scenario described in this repository represent controlled laboratory activity. No unauthorized systems were targeted.

---

## 📎 Project Presentation

The complete project presentation is available in:

```text
presentation/Splunk_SOC_Project_Presentation_v2.pptx
```

The presentation covers the laboratory architecture, log collection, Windows events, SPL detection, dashboard/alert design, SOC-001 investigation, MITRE ATT&CK mapping, limitations, and future work.

---

# ⭐ If You Find This Project Useful

If this project demonstrates useful SOC/SIEM concepts, feel free to **star the repository** and explore the documentation and detection queries.
