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
