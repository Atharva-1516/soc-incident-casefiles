1. Alert Summary

Alert Name: High Volume Outbound Traffic

Source: Firewall / Network Monitoring System

Severity: Critical

Time Detected: 2026-02-16 01:42:18

2. Initial Hypothesis

A workstation generated outbound traffic significantly higher than its established behavioral baseline.

Potential causes include:

Data exfiltration

Unauthorized cloud upload

Malware communicating with command-and-control infrastructure

Legitimate but misconfigured backup process

Given the unusual volume and timing, potential data exfiltration is suspected.

3. Evidence Collected

Firewall Log Entry

Source IP: 10.0.5.23
Destination IP: 185.193.127.45
Destination Port: 443
Protocol: TCP
Bytes Sent: 78,432,221
Time Window: 6 minutes
User: CORP\jdoe


Baseline outbound traffic for this workstation typically does not exceed 5 MB in similar time windows.

4. Log Analysis

The source host (10.0.5.23) is assigned to user CORP\jdoe.

The outbound traffic volume (78 MB in 6 minutes) is significantly above baseline.

The traffic occurred outside normal business hours.

The destination IP is external and not associated with known corporate cloud providers.

Port 443 suggests encrypted HTTPS traffic, limiting payload inspection without SSL decryption.

This pattern is consistent with potential staged data exfiltration over encrypted channels.

5. Indicators of Compromise (IOCs)

Source Host: 10.0.5.23

User Account: CORP\jdoe

Destination IP: 185.193.127.45

Destination Port: 443

Outbound Volume: 78 MB within 6 minutes

Further enrichment of the destination IP is required to determine reputation or threat association.

6. MITRE ATT&CK Mapping

Tactic: Exfiltration

Technique: T1041 – Exfiltration Over C2 Channel

Technique: T1567 – Exfiltration Over Web Services

Reasoning:
Large outbound encrypted traffic to an unknown external IP aligns with ATT&CK techniques involving data exfiltration over web protocols or command-and-control channels.

7. Detection Logic

Trigger alert when:

Outbound traffic > 25 MB within a defined time window

Destination IP not in approved allowlist

Occurs outside business hours

Source is user workstation (not server or backup host)

Example pseudo-logic:

if bytes_sent > 25000000
AND destination_ip NOT IN approved_list
AND time_of_day NOT BETWEEN 08:00-18:00
THEN alert "Potential Data Exfiltration"

8. False Positives / Tuning Considerations

Potential false positives:

Cloud backup applications

Software updates

Large file transfers via legitimate services

Video uploads

Tuning strategies:

Maintain allowlist of approved SaaS/cloud destinations

Baseline traffic per department

Apply thresholds differently for servers vs user endpoints

Integrate DLP tools for content-aware inspection

9. Remediation Steps

Immediately isolate the affected workstation.

Verify whether the transfer was authorized.

Identify what files were accessed prior to transmission.

Enrich destination IP using threat intelligence sources.

Review additional logs:

File access logs

Proxy logs

Endpoint telemetry

Reset credentials of the affected account.

Initiate formal incident response if data leakage is confirmed.

10. Lessons Learned

Baseline-based detection is critical for identifying anomalies.

Encrypted traffic can conceal malicious activity.

Network monitoring should be paired with endpoint telemetry for full visibility.

Data exfiltration detection requires behavioral analysis, not just signature-based alerts.

Structured documentation improves SOC investigation repeatability and defensibility.

Analyst Conclusion

The observed outbound traffic volume, timing, and destination strongly indicate potential data exfiltration activity. Although encrypted HTTPS traffic limits content visibility, the behavioral anomalies justify escalation for deeper forensic review.

This event should be treated as a potential security incident until validated otherwise.
