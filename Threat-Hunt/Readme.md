# Threat Hunt Report: AI-Orchestrated Intrusion Investigation

**Participant:** Devansh Sharma
**Date:** November 2026

## Platforms and Languages Leveraged

**Platforms:**

* Microsoft Sentinel / Azure Log Analytics
* SemiCrest Technologies infrastructure (`sc-portal01`, `sc-admin01`, `sc-db01`)

**Languages/Tools:**

* Kusto Query Language (KQL) for querying workspace telemetry, custom agent logs, and system events
* MITRE ATT&CK Framework

---

## Scenario

At SemiCrest Technologies, an unknown threat actor orchestrated a multi-stage intrusion using a novel execution engine: an autonomous AI agent. Security teams needed to determine the exact level of autonomy the attacker employed, map the human decision gates guiding the AI, and deconflict the attacker's footprint from legitimate environmental noise (including scheduled backups and morning traffic spikes) to accurately scope the incident.

---

## Key Observations

* **Execution Engine:** The intrusion was executed using an AI agent prompted by a human operator, mapping to MITRE ATT&CK technique **T1588.007** (Obtain Capabilities: Artificial Intelligence).
* **Autonomy Level:** The attack was semi-autonomous, classified as a "person who set a machine going."
* **Human Operator Gates:** The operator did not execute commands directly; instead, they paused the autonomous agent at **4 distinct decision gates** to verify intelligence before authorizing the next phase.
* **Credential Pivot:** The `portal_svc` credential was compromised and used for lateral movement, distinguishable from legitimate app traffic via the **source IP address**.
* **False Positives:** A 03:00 `pg_dump` job and a 07:30 PostgreSQL connection spike were successfully triaged as **noise** (normal scheduled activity and users logging in for the workday, respectively).

---

## Timeline & Queries Used

### Locating the Agent Logs:
Initial investigation into the operator's directives resulted in query timeouts. A global schema search was executed to find the exact table housing the `user_input` field, pinpointing the custom `LLMAgentLogs_CL` table.
```kql
find withsource=TableName where * contains "user_input"
```
**<img width="1781" height="797" alt="image" src="https://github.com/user-attachments/assets/f0b6d84e-328c-40ff-888d-8c7f3304a5a9" />
**

📌 *Target Table:* `LLMAgentLogs_CL`

### Extracting Operator Decision Gates:
We filtered the custom AI agent table to the local time of the attack (accounting for UTC offset) and excluded benign administrative tasks (e.g., CI pipeline checks). This isolated the exact moments the human operator intervened.
```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-24T06:00:00Z) .. datetime(2026-10-25T06:00:00Z))
| where isnotempty(user_input)
| project TimeGenerated, user_input
| sort by TimeGenerated asc
```
<img width="1742" height="833" alt="image" src="https://github.com/user-attachments/assets/37a5a860-780f-4a76-9361-8fa1323e9b74" />


📌 *Gate Count:* `4 decision gates`

### Verifying Machine-Speed Execution:
To confirm the hybrid nature of the attack, we cross-referenced the human inputs with Syslog events showing non-human, machine-speed execution bursts during the autonomous phases.
```kql
Syslog
| where TimeGenerated between (datetime(2026-10-24T00:00:00Z) .. datetime(2026-10-24T05:00:00Z))
| summarize count() by bin(TimeGenerated, 3s)
| top 5 by count_ desc
```
<img width="1732" height="692" alt="image" src="https://github.com/user-attachments/assets/b565cbd0-cb85-4fed-af8e-f897321e456b" />


📌 *Classification:* `a person who set a machine going`

---

## Summary of Findings

| Flag | Description | Answer/Value |
| ---- | ----------------------------- | ------------------------------------------------ |
| 1 | Operator decision gates | `4 gates between exploit-lateral, lateral-collection, collection-staging, staging-exfil` |
| 2 | Autonomy placement | `a person who set a machine going with LLMAgentLogs_CL.user_input and Syslog.SyslogMessage` |
| 3 | Novel ATT&CK technique | `T1588.007 Obtain Capabilities: Artificial Intelligence` |
| 4 | Credential reuse separation | `source IP address` |
| 5 | pg_dump disconfirmation | `normal scheduled activity because it runs on a regular schedule before the attack window` |
| 6 | Connection spike dead end | `noise caused by users logging in at the start of the workday` |

---

## Response Actions

* **Credential Rotation:** `portal_svc` credentials reset and sessions originating from anomalous source IPs terminated.
* **Telemetry Expansion:** Detections created to monitor `LLMAgentLogs_CL` for unauthorized operator directives mapping to reconnaissance or data collection.
* **Incident Triage Integration:** 48-hour historical baseline reviews mandated for all future scheduled task investigations to rapidly dismiss benign jobs like the 03:00 `pg_dump`.
* **Awareness:** Threat intelligence updated to include MITRE T1588.007 for hybrid AI-orchestrated attack models.

---

## Diamond Model of Intrusion Analysis

| Feature | Description |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Adversary** | Unknown threat actor orchestrating an autonomous AI agent to execute the kill chain. |
| **Capability** | AI-driven enumeration, exploitation, and data collection, categorized under MITRE T1588.007 (Artificial Intelligence). |
| **Infrastructure** | Azure Log Analytics custom telemetry (`LLMAgentLogs_CL`), standard network protocols generating high-volume Syslog bursts. |
| **Victim** | SemiCrest Technologies (specifically targeting `sc-portal01`, `sc-admin01`, and `sc-db01`). |

```text
                   +-----------------------+
                   |     Infrastructure    |
                   | (sc-db01, sc-admin01) |
                   +-----------+-----------+
                               |
                               v
+----------------+     +------+-------+     +------------------+
|   Adversary    |<--->|   Capability  |<--->|      Victim      |
| Unknown Actor  |     | AI Agent (LLM)|     | SemiCrest Tech.  |
|                |     | Pivot/Exfil   |     |                  |
+----------------+     +---------------+     +------------------+
```

---

## Lessons Learned

* AI agents can execute kill chains at machine speed but still require human validation at strategic boundary gates.
* High-volume database connections (07:30 spike) and scheduled backups (03:00 `pg_dump`) must be baselined against historical 48-hour data to prevent alert fatigue and false positives.
* Source IP analysis is critical for distinguishing attacker lateral movement from legitimate application traffic when a service account (`portal_svc`) is used by both.
* Custom application logs (like `LLMAgentLogs_CL`) are high-value targets for uncovering the "brain" of an automated attack.

---

**Report Completed By:** Devansh Sharma
**Status:** ✅ All flags investigated and confirmed
