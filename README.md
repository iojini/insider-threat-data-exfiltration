# Threat Hunt Report: Insider Threat and Data Exfiltration Investigation

<img width="2052" height="1533" alt="ITDEv2_bordered" src="https://github.com/user-attachments/assets/235e4bd8-6402-44a4-9954-6560f4f47371" />

##  Scenario

An employee named John Doe is currently working in a sensitive department and has recently been placed on a performance improvement plan (PIP). After this decision, John has reportedly reacted with concerning behavior and management now believes that John may be considering the theft of proprietary information before quitting and leaving the company. Since John is an administrator on his device, there are no limits to the applications he can use. Therefore, he may try to archive or compress sensitive information and send it to a private drive. This investigation aims to analyze activities on John's corporate device to ensure that no suspicious actions are taking place.

- [Scenario Creation](https://github.com/iojini/insider-threat-data-exfiltration/blob/main/insider-threat-data-exfiltration-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- Log Repository: Azure Log Analytics
- Kusto Query Language (KQL)

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` table for archiving activity

Searched the DeviceFileEvents table and discovered archiving activity on the target device (i.e., employee-data-20251002004431.zip was created at 12:44:40.196 AM).

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "irene-test-vm-m"
| where FileName endswith ".zip"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, ActionType, FileName
```
<img width="1938" height="739" alt="TH3_1" src="https://github.com/user-attachments/assets/75c0f7a9-3173-4ff0-b997-2722decc008a" />

---

### 2. Searched the `DeviceProcessEvents` table for suspicious activity before and after archive creation

Searched the DeviceProcessEvents table for activities occuring one minute before and one minute after the archive was created and discovered that a powershell script silently installed 7-zip on the device at 12:44:32.908 AM. Furthermore, 7-zip was used to compress employee data at 12:44:40.145 AM.

**Query used to locate events:**

```kql
// 2025-10-02T00:44:40.1965293Z
let VMName = "irene-test-vm-m";
let specificTime = datetime(2025-10-02T00:44:40.1965293Z);
DeviceProcessEvents
| where TimeGenerated between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by TimeGenerated desc
| project TimeGenerated, FileName, ProcessCommandLine
```
<img width="1980" height="640" alt="TH3_2v3" src="https://github.com/user-attachments/assets/f5f8e619-eb3f-480c-b34c-d91f955f8cbe" />

---

### 3. Searched the `DeviceNetworkEvents` table for network activity indicative of exfiltration

Searched for any indication of successful exfiltration from the network and discovered outbound connections to Azure Blob Storage. PowerShell connected to sacyberrangedanger.blob.core.windows.net at 12:44:40.285 AM.

**Query used to locate events:**

```kql
let VMName = "irene-test-vm-m";
let specificTime = datetime(2025-10-02T00:44:40.1965293Z);
DeviceNetworkEvents
| where TimeGenerated between ((specificTime - 4m) .. (specificTime + 4m))
| where DeviceName == VMName
| order by TimeGenerated desc
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
```
<img width="1916" height="931" alt="TH3_3" src="https://github.com/user-attachments/assets/c6f7f817-4a4d-404f-98c8-e8136e31c31d" />

---

## Summary

The analysis revealed that the target device was internet-facing for several days, with the most recent occurrence on October 16, 2025. During this exposure period, multiple threat actors attempted to gain unauthorized access to the device. Analysis of failed logon attempts identified numerous external IP addresses conducting brute-force attacks, with some IPs attempting to log in over 90 times (e.g., 185.39.19.56 with 100 failed attempts, 45.227.254.130 with 93 failed attempts).

Critically, none of the identified threat actor IP addresses successfully gained access to the system. Further investigation revealed that the only successful network logons during the last 30 days were associated with the 'labuser' account (53 total). Notably, there were zero failed logon attempts for this account, and the successful logons originated from an IP address consistent with expected and legitimate sources. In summary, no indicators of compromise (IOC) were found.

---

## Relevant MITRE ATT&CK TTPs

| TTP ID | TTP Name | Description | Detection Relevance |
|--------|----------|-------------|---------------------|
| T1133 | External Remote Services | Internet-facing VM inadvertently exposed to the public internet, allowing external access attempts. | Identifies misconfigured devices exposed to the internet through DeviceInfo table queries. |
| T1046 | Network Service Discovery | External threat actors discovered and identified the exposed service before attempting access. | Indicates potential reconnaissance and scanning by external actors prior to brute-force attempts. |
| T1110 | Brute Force | Multiple failed login attempts from external IP addresses attempting to gain unauthorized access (e.g., 185.39.19.56 with 100 attempts). | Identifies brute-force login attempts and suspicious login behavior from multiple remote IPs. |
| T1075 | Pass the Hash | Failed login attempts could suggest credential-based attacks including pass-the-hash techniques. | Identifies failed login attempts from external sources, indicative of credential attacks. |
| T1021 | Remote Services | Remote network logons via legitimate services showing external interaction attempts with the exposed device. | Identifies legitimate and malicious remote service logons to the exposed device. |
| T1070 | Indicator Removal on Host | No indicators of successful brute-force attacks, demonstrating that defensive measures prevented unauthorized access. | Confirms the lack of successful attacks due to effective monitoring and legitimate account usage. |
| T1078 | Valid Accounts | Successful logons from the legitimate account 'labuser' were normal and monitored, representing valid credential usage. | Monitors legitimate access and excludes unauthorized access attempts by confirming expected IP sources. |

---

This table organizes the MITRE ATT&CK techniques (TTPs) observed during the investigation. The detection methods identified both the attack attempts (brute force from external IPs) and confirmed that no unauthorized access occurred, with all successful logons representing legitimate user activity.

---

## Response Taken

| MITRE Mitigation ID | Name | Action Taken | Description | Relevance |
|---------------------|------|--------------|-------------|-----------|
| M1030 | Network Segmentation | Network Security Group Hardening | Reconfigured the NSG attached to 'irene-test-vm-m' to restrict RDP access to authorized IP addresses only, eliminating public internet exposure. | Prevents unauthorized external access by limiting remote access to trusted sources only. |
| M1036 | Account Use Policies | Account Lockout Policy Implementation | Implemented account lockout thresholds to automatically lock accounts after a specified number of failed login attempts. | Mitigates brute-force attack risks by preventing unlimited password guessing attempts. |
| M1032 | Multi-factor Authentication | Multi-Factor Authentication Deployment | Deployed MFA for all network logon types, requiring additional authentication factors beyond passwords. | Adds an additional security layer to prevent unauthorized access even if credentials are compromised. |
| M1047 | Audit | Continuous Monitoring Configuration | Established ongoing monitoring of DeviceInfo and DeviceLogonEvents tables for configuration changes and suspicious login activity. | Enables early detection of future misconfigurations or unauthorized access attempts. |

---

The following response actions were taken: reconfigured the NSG attached to the target machine to restrict RDP access to authorized endpoints only, removing public internet exposure; implemented account lockout thresholds to prevent brute-force attacks by automatically locking accounts after excessive failed login attempts; deployed MFA for network authentication to provide additional security beyond password-based access; established ongoing monitoring for configuration changes and suspicious login activity.

---
