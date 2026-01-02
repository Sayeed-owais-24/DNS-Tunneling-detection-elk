# DNS Tunneling Detection – ELK Stack

## Objective
Develop and test a custom SIEM detection to identify DNS tunneling activity using Packetbeat logs and KQL-based correlation rules.

## Lab Architecture
- Elasticsearch & Kibana: Windows host  
- Packetbeat: Linux VM  
- Data Source: DNS network traffic  
- Detection Engine: Kibana Security (Custom Query Rule)

## Attack Simulation
Simulated DNS tunneling by generating abnormally long and encoded subdomain queries to a test domain (`eviltest.com`) using `dig`.

## Detection Logic
The rule detects suspicious DNS activity based on unusually long DNS query names, which is a common indicator of data exfiltration via DNS.

**Rule Logic (KQL):**
event.dataset : "dns" and strlen(dns.question.name) > 50 and network.protocol : "dns"

## Alert & Evidence
- Packetbeat successfully captured DNS traffic
- Custom detection rule triggered alerts for suspicious DNS queries
- Evidence screenshots included:
  - Raw DNS logs
  - Alert triggered view
  - Alert detail panel

## MITRE ATT&CK Mapping
- **Tactic:** Command and Control  
- **Technique:** Application Layer Protocol  
- **Sub-technique:** DNS  
- **MITRE ID:** T1071.004

## Outcome
Successfully detected simulated DNS tunneling activity using custom correlation rules, validating the effectiveness of Packetbeat-based DNS monitoring in a SOC environment.
