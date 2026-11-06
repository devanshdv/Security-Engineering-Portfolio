<img width="2560" height="600" alt="card-stig" src="https://github.com/user-attachments/assets/db8b2684-f3be-4e64-89d9-602097f77cb7" />

# Windows 11 STIG Remediation

Ten security settings on a Windows 11 computer, fixed and proven: each one failed the official US government checklist before, and passed after.

The checklist is the DISA STIG for Windows 11, the security standard the US Department of Defense uses for its computers[cite: 8]. Each setting was fixed with a PowerShell script and confirmed by a Tenable scan that logs in and checks the computer against the checklist[cite: 8].

* **Checklist:** DISA Microsoft Windows 11 STIG v2r9, run as a Tenable compliance scan.
* **Target:** One Windows 11 virtual machine in Azure, part of the LOG(N) Pacific Cyber Range.
* **Before:** Numerous failed checks across the compliance audit.
* **After:** All ten targeted settings successfully passed.

---
<img width="2600" height="2368" alt="flow" src="https://github.com/user-attachments/assets/9c0817b4-a4be-4c69-8b28-c6369da631a4" />


## The Ten Settings Fixed

Each of the following ten settings failed the initial checklist[cite: 10]. Each one was fixed with a dedicated PowerShell script, and a subsequent Tenable scan logged in and checked it again. All ten moved from Failed to Passed. 

| STIG ID | Vulnerability Remediation | Script File |
| :--- | :--- | :--- |
| **WN11-SO-000120** | **SMB Server Packet Signing:** Configured the SMB server to always require packet signing to prevent man-in-the-middle attacks. | `WN11-SO-000120.ps1`|
| **WN11-SO-000100** | **SMB Client Packet Signing:** Configured the SMB client to always perform packet signing. | `WN11-SO-000100.ps1` |
| **WN11-SO-000150** | **Restrict Anonymous Enumeration:** Restricted anonymous enumeration of shares to prevent unauthorized reconnaissance. | `WN11-SO-000150.ps1` |
| **WN11-CC-000005** | **No Camera on the Lock Screen:** Disabled camera access from the lock screen before signing in. | `WN11-CC-000005.ps1`|
| **WN11-CC-000010** | **No Lock Screen Slide Shows:** Disabled the display of slide shows on the lock screen. | `WN11-CC-000010.ps1` |
| **WN11-CC-000155** | **Disable Solicited Remote Assistance:** Configured the system to explicitly deny Solicited Remote Assistance connections. | `WN11-CC-000155.ps1` |
| **WN11-CC-000180** | **Disable Autoplay:** Disabled the default Autoplay behavior for all non-volume devices to prevent unauthorized execution. | `WN11-CC-000180.ps1` |
| **WN11-CC-000305** | **Disable Encrypted File Indexing:** Configured Windows Search to stop indexing encrypted files. | `WN11-CC-000305.ps1' |
| **WN11-CC-000326** | **Record Every PowerShell Script:** Enabled script block logging so the full text of each script that runs is logged. | `WN11-CC-000326.ps1` |
| **WN11-00-000175** | **No 'Run As Someone Else':** The Secondary Logon service is switched off. | `WN11-00-000175.ps1` |
<img width="2752" height="1536" alt="Gemini_Generated_Image_tlgusitlgusitlgu" src="https://github.com/user-attachments/assets/e8cdc67e-9f7b-4f70-a4f6-775a58eeaa56" />

---

## Method

1. Run the DISA Windows 11 STIG audit as a credentialed scan and record every failed check.
2. For each finding, write one PowerShell script that sets exactly the setting the STIG checks, then prints the value back as evidence.
3. Run the script as Administrator on the VM.
4. Rescan with the same scan and confirm the finding moved from Failed to Passed.

---

## Lessons Learned

* **Registry Precision:** A scanner's check can be stricter than general documentation. Ensuring exact DWORD configurations in the correct hive paths is critical for passing automated compliance audits.
* **Scan Authentication:** Credentialed scanning of a standalone Windows 11 VM needs the scanner allowed through the firewall, Remote Registry available, and remote UAC filtering relaxed for the local admin account during the scan. All of it was put back afterwards. 
* **Evidence Trails:** Audit settings are the evidence trail[cite: 10]. Enabling script block logging (Event 4104) records exactly the evidence a threat hunt depends on.
