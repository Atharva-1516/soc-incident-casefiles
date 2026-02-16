Multiple Failed Logins Followed by Successful Authentication – Suspected Brute-Force Attack
1. Alert Summary

Alert Name: Multiple Failed Login Attempts Followed by Success

Source: Windows Security Event Logs

Severity: High

Time Detected: 2026-02-18 03:14:09

2. Initial Hypothesis

A high volume of failed login attempts followed by a successful authentication may indicate:

Brute-force password attack

Password spraying

Compromised credentials

Automated attack script

Given the pattern observed, a brute-force attack against a domain account is suspected.

3. Evidence Collected
Windows Security Event ID 4625 – Failed Logon
Event ID: 4625
Account Name: jdoe
Source IP Address: 192.168.1.55
Logon Type: 3 (Network)
Failure Reason: Unknown username or bad password
Occurrences: 18 within 2 minutes

Windows Security Event ID 4624 – Successful Logon
Event ID: 4624
Account Name: jdoe
Source IP Address: 192.168.1.55
Logon Type: 3 (Network)
Time: 03:13:58


A successful authentication occurred immediately after multiple failed attempts.

4. Log Analysis

18 failed login attempts occurred within a 2-minute window.

All attempts originated from the same internal IP address.

Logon Type 3 indicates network-based authentication.

A successful login occurred seconds after repeated failures.

The activity occurred outside standard working hours.

This pattern strongly indicates credential brute-forcing.

5. Indicators of Compromise (IOCs)

Target Account: jdoe

Source IP: 192.168.1.55

Event IDs: 4625 (Failed Logon), 4624 (Successful Logon)

Logon Type: 3 (Network)

Time Window: 2 minutes

6. MITRE ATT&CK Mapping

Tactic: Credential Access

Technique: T1110 – Brute Force

Reasoning:
Repeated authentication failures followed by success aligns directly with MITRE ATT&CK brute-force techniques used to gain unauthorized access.

7. Detection Logic

Trigger alert when:

Event ID 4625 occurs ≥ 5 times within 5 minutes

Followed by Event ID 4624 for same user

From same source IP

Example pseudo-detection:

IF count(EventID=4625) >= 5 within 5 minutes
AND EventID=4624 occurs
AND same AccountName
AND same SourceIP
THEN alert "Potential Brute Force Attack"

8. False Positives / Tuning Considerations

Potential false positives:

User mistyping password

Expired credentials

Service account authentication retries

Misconfigured applications

Tuning strategies:

Exclude known service accounts

Apply stricter thresholds outside business hours

Monitor privileged accounts separately

Correlate with endpoint behavior after login

9. Remediation Steps

Immediately lock or disable the affected account.

Reset user password.

Investigate source IP (internal host compromise possibility).

Check for lateral movement attempts.

Review privileged group membership changes.

Enforce account lockout policies if not already configured.

Consider implementing MFA.

10. Lessons Learned

Authentication logs are critical for early intrusion detection.

Correlating failed + successful logins improves detection fidelity.

Brute-force detection must balance sensitivity and false positives.

MFA significantly reduces brute-force risk.

Structured log correlation improves SOC efficiency.

Analyst Conclusion

The authentication pattern observed is consistent with a brute-force attack resulting in account compromise. Immediate credential rotation and investigation of the source system are required to prevent further unauthorized access.

This activity should be escalated as a confirmed security incident.
