# THM-FridayOvertime
Malware analysis and threat-intelligence CTF from TryHackMe’s “Friday Overtime.” Includes SHA1 validation, framework correlation, MITRE ATT&amp;CK mapping, and OSINT pivots by Slade Venter.


# TryHackMe – Friday Overtime
Author: Slade Venter
Category: Malware Analysis / Threat Intelligence

# Scenario
-It’s late Friday at PandaProbe Intelligence when SwiftSpend Finance opens a high-priority ticket reporting suspicious DLL files.
As the only analyst still on shift, you must download the attachments, examine them in a controlled environment, and determine whether they indicate a targeted intrusion or a false alarm.
The engagement involves verifying file hashes, correlating with known frameworks, identifying ATT&CK mappings, and confirming the scope of potential compromise.


# Environment 
| Component | Details                                                                            |
| --------- | ---------------------------------------------------------------------------------- |
| Platform  | TryHackMe “Friday Overtime” room                                                   |
| Tools     | DocIntel portal, sha1sum, CyberChef, VirusTotal, MITRE ATT&CK Navigator            |
| Artifacts | `samples.zip` containing `pRsm.dll`                                                |
| Goal      | Analyse malware, map to framework and techniques, extract indicators of compromise |

# Question 1
Who shared the malware samples?

-Look at who sent the email-
Inside the DocIntel ticket metadata, the “Reporter” field lists SwiftSpend Finance as the originator. 
This establishes the context of a client submission rather than an internal detection — important for triage priority and chain-of-custody.

# Question 2
SHA1 hash of pRsm.dll

Hashing confirms file integrity and provides a pivot point for threat-intel lookup. 
Uploading this hash to VirusTotal immediately returned multiple detections labelled as MgBot modules, suggesting a known modular malware framework rather than a new sample.

<img width="1920" height="849" alt="1" src="https://github.com/user-attachments/assets/4bc97d77-277d-4cac-a652-5556242e9e25" />

# Question 3
Which malware framework utilizes these DLLs as add-on modules?

-Use VirusTotal and MITREATT@CK-

MgBot is a modular espionage framework where each DLL extends core capabilities such as keylogging, audio capture, and data exfiltration. 
The VirusTotal behavior tab showed references to microphone and network activity consistent with MgBot’s plugin structure. Correlating the hash with threat feeds confirmed the match.

<img width="1920" height="858" alt="2 Virus Toatl" src="https://github.com/user-attachments/assets/e9591416-54ac-420a-974d-6cccb1cf481b" />

# Question 4
Which MITRE ATT&CK technique is linked to pRsm.dll in MgBot?

-USE MITRE ATT@CK-
VirusTotal’s automated mapping initially suggested T1574 (Side-Loading) and T1129 (Shared Modules) these describe how the DLL is loaded. 
However, manual research into MgBot’s MITRE profile showed that pRsm.dll functions as an audio recorder.
This distinction demonstrates critical analysis beyond automation.

<img width="1920" height="860" alt="Mitre Attack" src="https://github.com/user-attachments/assets/8962375c-5289-46f2-aef7-def1d7c9b816" />


# Question 5
CyberChef defanged URL (first seen 2020-11-02)

Using CyberChef’s Defang URL recipe ensures the malicious address remains readable but harmless. 
The domain masquerades as a legitimate Tencent update service, a common MgBot tactic for trust abuse and social engineering.

<img width="1920" height="851" alt="Defanged" src="https://github.com/user-attachments/assets/8b6d5690-cf74-4433-9d75-352f8c9d6d82" />

#Question 6
CyberChef defanged C2 IP (first detected 2020-09-14)

This C2 address appeared in DocIntel’s IOC timeline and was confirmed via VirusTotal and AbuseIPDB as historically linked to multiple MgBot campaigns.
Defanging prevents accidental connection while preserving the indicator for future blocklists and YARA rules.

<img width="826" height="285" alt="Network Defang" src="https://github.com/user-attachments/assets/9b6b3e86-f023-429c-9ced-8dd67da47ac5" />

# Question 7
MD5 hash of SpyAgent sample hosted on same IP (June 2025)

Pivoting from the C2 IP in VirusTotal’s “Relations” tab revealed an Android spyware sample classified as SpyAgent. Its presence alongside MgBot payloads suggests shared infrastructure between desktop and mobile surveillance operations.
A sign of actor resource reuse or cross-platform campaign design.

<img width="1920" height="853" alt="Virus total one" src="https://github.com/user-attachments/assets/0fc3a049-9468-4c4e-8e3e-5d0591b6f174" />

# Reflection
This challenge simulated the pace and structure of real-world CTI analysis:
-Collecting and validating hashes
-Performing cross-platform pivoting (VirusTotal → DocIntel → MITRE)
-Interpreting automation critically instead of blindly accepting it

As my first malware-analysis CTF, this is for practise and to begin building a profile, it reinforced structured investigation, evidence documentation, and clear reporting
              “Curiosity, not tools, makes the analyst.”
