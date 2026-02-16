Suspicious PowerShell Execution – Encoded Command
1. Alert Summary

Alert Name: Suspicious PowerShell Encoded Command

Source: Sysmon (Event ID 1 – Process Creation)

Severity: High

Time Detected: 2026-02-14 02:17:32

2. Initial Hypothesis

The alert suggests that PowerShell was executed with an encoded command parameter.
This behavior is commonly associated with:

Malware execution

Obfuscated command-and-control activity

Living-off-the-land techniques

Credential harvesting scripts

Encoded PowerShell commands are frequently used to evade detection.

3. Evidence Collected

Sysmon Event ID 1 – Process Creation

Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -EncodedCommand SQBFAFgA...
ParentImage: C:\Windows\explorer.exe
User: CORP\jdoe
Hash: SHA256=3f2c7a8b1a2b4e1f7a...


The command was executed under a standard domain user account.

og Analysis

The process was launched from explorer.exe, indicating user-level interaction.

The -EncodedCommand parameter was used, which hides the actual PowerShell script.

The -NoProfile flag suggests the attacker wanted to avoid loading user profile scripts that might trigger logging or security tools.


5. Indicators of Compromise (IOCs)

Process: powershell.exe

Suspicious Flag: -EncodedCommand

User Account: CORP\jdoe

Parent Process: explorer.exe

Hash (SHA256): 3f2c7a8b1a2b4e1f7a...

No external IPs or domains were observed in this specific event, but encoded PowerShell execution is a high-risk behavioral indicator.

6. MITRE ATT&CK Mapping

Tactic: Execution

Technique: T1059.001 – PowerShell

Sub-technique: Command and Scripting Interpreter

Reasoning:
PowerShell was used to execute an obfuscated command, aligning with ATT&CK technique T1059.001. The encoded command parameter is commonly leveraged to evade detection.

No legitimate enterprise software in the environment is known to use encoded PowerShell commands.

This strongly indicates obfuscated script execution.

7. Detection Logic

Trigger an alert when:

Event ID = 1 (Sysmon Process Creation)

Image = powershell.exe

CommandLine contains "-EncodedCommand"

Example Detection Logic (pseudo-Sigma):

selection:
  EventID: 1
  Image|endswith: powershell.exe
  CommandLine|contains: -EncodedCommand
condition: selection

8. False Positives / Tuning Considerations

Potential false positives:

Legitimate administrative scripts

IT automation tools

Software deployment tools

Tuning strategies:

Exclude known management servers

Exclude known service accounts

Alert only when executed by standard user accounts
