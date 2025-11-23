# Threat Event (Data Exfiltration from Disgruntled Employee)
**Archival Activity via Silent 7-Zip Execution**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Provision a Windows VM and confirm the VM is reachable externally (e.g., ping)
2. Onboard the VM to Microsoft Defender for Endpoint (MDE)
3. Run the following PowerShell script on the onboarded VM to simulate a data exfiltration attempt by an insider threat:<br>
    [Data Exfiltration Simulation Script](https://github.com/iojini/insider-threat-data-exfiltration/blob/main/scripts/exfiltratedata.ps1)

---

## Tables Used for IoC Identification:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table|
| **Purpose**| Used to detect TOR download and list creation.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table|
| **Purpose**| Used to detect the silent installation and launching of TOR.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect connections to known TOR ports (e.g, 9001, 9030, 9040, 9050, 9051, 9150) and sites over ports 80 and 443.|

---
