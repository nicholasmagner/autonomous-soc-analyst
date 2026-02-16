
# Autonomous SOC Analyst (Agentic AI Security Automation) 

This project shows how I approach building an AI-assisted SOC workflow using agentic reasoning for threat hunting, alert triage, and investigation reporting.

The goal here isn’t to replace analysts. It’s to take the repetitive parts of investigations — the pattern matching, the structuring, the mapping to MITRE — and speed them up while keeping a human in control.

I built this to show how I think about:

- Turning a simple prompt into a structured investigation  
- Backing findings with evidence  
- Mapping activity clearly to MITRE ATT&CK  
- Producing clean, consistent writeups that a real SOC could use  

## What this shows

- How I break down an investigation from start to finish  
- How I use MITRE ATT&CK as a reasoning framework, not just a buzzword  
- How I validate AI output instead of blindly trusting it  
- How I think about AI in a security environment: evidence first, human oversight always  

---

# MITRE ATT&CK Walkthrough with Evidence

Below is a full walkthrough of the hunt across the MITRE ATT&CK lifecycle.

For each tactic, I show the execution and the actual output produced during the investigation.

<img width="3744" height="1828" alt="mitre attack" src="https://github.com/user-attachments/assets/6b47e9a2-8013-46e2-8877-36492d8da8ab" />

---

## Reconnaissance

This is where attackers start gathering information. Domain lookups, scanning, enumeration — it’s the early “feeling around in the dark” phase.

If you catch this stage early, you can stop an attack before it turns into something bigger.

![Recon - Run main.py](https://github.com/user-attachments/assets/a36253a6-c522-4cbe-8335-9146d7800a24)

![Recon - Output 1]<img width="3837" height="2189" alt="3" src="https://github.com/user-attachments/assets/77a05b66-64e6-4c35-a3df-e9fb718063d2" />

![Recon - Output 2]<img width="3839" height="2210" alt="4" src="https://github.com/user-attachments/assets/6fec20e1-65c8-45e5-9e3e-7c48fcaf1ec4" />

---

## Resource Development

This is the preparation phase. Infrastructure gets built. Tools get staged. Accounts get created.

A lot of SOC teams miss this because it doesn’t look noisy — but it’s often the calm before the storm.

![Resource Development - Output 1]<img width="3778" height="2203" alt="5" src="https://github.com/user-attachments/assets/a1804c3a-9f50-4717-aa15-0dbe8bdae407" />

![Resource Development - Output 2]<img width="3819" height="2232" alt="6" src="https://github.com/user-attachments/assets/89b35285-8667-42aa-ac7d-c869504c5845" />

![Resource Development - Output 3]<img width="3835" height="2196" alt="7" src="https://github.com/user-attachments/assets/a07deafc-81c2-4e55-855a-cde32cbcfe6e" />

---

## Initial Access

This is the first real foothold. Phishing. Exploit. Credential misuse.

If you stop it here, the breach ends here.

![Initial Access - Output 1]<img width="3576" height="2275" alt="8" src="https://github.com/user-attachments/assets/c8769f0f-5639-442c-a3f5-ee41d12ad1be" />

![Initial Access - Output 2]<img width="3596" height="2233" alt="9" src="https://github.com/user-attachments/assets/d45ca44c-4131-4d5a-81de-c1aee3f1bbc4" />

![Initial Access - Output 3]<img width="2862" height="435" alt="10" src="https://github.com/user-attachments/assets/013cdb18-a558-44a2-8789-788e9dab2869" />

---

## Execution

This is when something actually runs. PowerShell. Scripts. Dropped binaries.

This is usually where the SOC starts getting louder alerts.

![Execution - Output 1]<img width="3085" height="1048" alt="11" src="https://github.com/user-attachments/assets/c03d4ac2-117a-42b1-b23a-67743b728ee2" />

![Execution - Output 2]<img width="3073" height="1416" alt="12" src="https://github.com/user-attachments/assets/804d48d9-f8e9-4fa3-9676-d5fb48764967" />

![Execution - Output 3]<img width="3107" height="1746" alt="13" src="https://github.com/user-attachments/assets/bf73ed37-92c4-4894-9cd5-6a56fab53ec6" />

---

## Persistence

This is where attackers try to survive reboots, password resets, or partial remediation.

Miss this, and they’re back tomorrow.

![Persistence - Output 1]<img width="2284" height="1020" alt="14" src="https://github.com/user-attachments/assets/16fbb432-5984-4515-a659-1f9b4f06928b" />

![Persistence - Output 2]<img width="3082" height="1350" alt="15" src="https://github.com/user-attachments/assets/5ac01192-0619-48c4-a398-db13228bda14" />

![Persistence - Output 3]<img width="2453" height="1281" alt="16" src="https://github.com/user-attachments/assets/7f61e435-5852-450b-930c-eb2be22ca575" />

![Persistence - Output 4]<img width="3153" height="1347" alt="17" src="https://github.com/user-attachments/assets/7a9f0d25-9cda-4458-9256-af4ebe7247a1" />

![Persistence - Output 5]<img width="3127" height="1312" alt="18" src="https://github.com/user-attachments/assets/b8125904-3090-4ca9-9a6c-8f6cfef52fac" />

---

## Privilege Escalation

This is where things get serious. Moving from user-level access to admin or SYSTEM.

More privilege means more damage.

![Privilege Escalation - Output 1](https://github.com/user-attachments/assets/ffa2140b-1021-40a9-a2a7-706f769aa4dd)
![Privilege Escalation - Output 2](https://github.com/user-attachments/assets/d6efc2a2-332d-4c3f-a9f7-114cce3024d9)

---

## Defense Evasion

This is when attackers start trying to hide. Clearing logs. Disabling tools. Living off the land.

This stage often determines how long they stay undetected.

![Defense Evasion - Output 1](https://github.com/user-attachments/assets/666b0485-eb67-4925-b4d0-917b8cfac77c)
![Defense Evasion - Output 2](https://github.com/user-attachments/assets/d2396fd3-69e2-4a05-9fc8-9d6235e794e2)
![Defense Evasion - Output 3](https://github.com/user-attachments/assets/50a46908-976d-4a8b-ba18-5e798320ba59)
![Defense Evasion - Output 4](https://github.com/user-attachments/assets/b7b6c3a3-a789-4a3f-bab9-66dd25679830)

---

## Credential Access

Here’s where attackers grab hashes, tokens, or plaintext credentials.

If they get valid creds, detection becomes much harder.

![Credential Access - Output 1](https://github.com/user-attachments/assets/b176638f-6437-43df-beba-1930f6d955b4)
![Credential Access - Output 2](https://github.com/user-attachments/assets/d23e5b73-e862-4511-8a0d-9fe88c10ddeb)

---

## Discovery

Once inside, attackers map the environment. Users. Shares. Trust relationships.

Discovery is what enables lateral movement.

![Discovery - Output 1](https://github.com/user-attachments/assets/53e17571-c5fd-4454-9214-3626e39b6618)
![Discovery - Output 2](https://github.com/user-attachments/assets/12aeb3af-0cdf-4f90-ae20-1e0b1f0ee775)
![Discovery - Output 3](https://github.com/user-attachments/assets/6c48939a-46b1-4b9b-b094-88aca4ad66f1)
![Discovery - Output 4](https://github.com/user-attachments/assets/1ef40b97-3f9e-4f68-8201-2ccbc160674f)

---

## Lateral Movement

This is where one compromised system becomes several.

RDP abuse. Pass-the-hash. Token impersonation.

![Lateral Movement - Output 1](https://github.com/user-attachments/assets/ce71157f-89d0-411a-9e4b-1449de66cf01)
![Lateral Movement - Output 2](https://github.com/user-attachments/assets/5e815344-26a8-4208-9ac4-a66b3c6e46d7)
![Lateral Movement - Output 3](https://github.com/user-attachments/assets/70696bf9-ad59-4270-837f-6feae537d4e9)
![Lateral Movement - Output 4](https://github.com/user-attachments/assets/9fa59b70-ba0d-4ddd-901e-8f07b48bbfc1)

---

## Collection

Now data starts getting staged. Files copied. Screenshots taken. Databases accessed.

This is often the last warning sign before exfiltration.

![Collection - Output 1](https://github.com/user-attachments/assets/be4eeaed-2c53-45e3-94dc-f93f59c86040)
![Collection - Output 2](https://github.com/user-attachments/assets/0aa27ee5-6d63-426b-87ea-8a9be7d413b8)
![Collection - Output 3](https://github.com/user-attachments/assets/22c469e5-9da3-446c-83b0-98275e1234ca)

---

## Command and Control

This is how attackers maintain remote control of compromised systems.

Kill C2, and you limit their ability to continue.

![C2 - Output 1](https://github.com/user-attachments/assets/4ce465a2-bf95-4a26-987c-486d68cc945d)
![C2 - Output 2](https://github.com/user-attachments/assets/5a44b575-4df4-4157-87b6-71069e9b5134)
![C2 - Output 3](https://github.com/user-attachments/assets/76e7cc18-09b9-49dd-b034-f6bc9fd1540f)

---

## Exfiltration

This is where data leaves the environment.

If this stage succeeds, it becomes a business and legal problem.

![Exfiltration - Output 1](https://github.com/user-attachments/assets/0d113ca2-de1e-499f-a88c-70d71801aa81)
![Exfiltration - Output 2](https://github.com/user-attachments/assets/a3be3aa4-34a0-4859-a385-7f54f79322b3)

---

## Impact

This is the endgame. Ransomware. Destruction. Service disruption.

This is where operations break.

![Impact - Output 1](https://github.com/user-attachments/assets/7916d3d4-1ee1-48c6-a377-2b26c90d39f2)
![Impact - Output 2](https://github.com/user-attachments/assets/cd90e832-ee4b-4f70-9d3d-5ffb5aead163)
![Impact - Output 3](https://github.com/user-attachments/assets/b2d60c75-246b-439d-ba40-ba957ca28abc)
![Impact - Output 4](https://github.com/user-attachments/assets/3287ad7e-9b09-4186-850a-21a62b6a28d2)

---

The purpose of this project is simple: show how an AI-assisted workflow can follow an attack chain end-to-end in a structured, explainable way.

Not hype. Not magic. Just investigation with evidence.
