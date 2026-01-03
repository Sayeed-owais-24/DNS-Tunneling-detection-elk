# DNS Tunneling Detection Report

## Analyst Details
- Role: SOC Analyst (L1)
- Toolset: ELK Stack (Elasticsearch, Kibana), Packetbeat
- Detection Type: Custom Correlation Rule
- Date: 2026-01-01

---

## 1. Objective
To detect DNS tunneling activity by identifying abnormal DNS queries that indicate possible data exfiltration using DNS as a covert channel.

---

## 2. Environment Overview
- **Elasticsearch & Kibana:** Windows host
- **Packetbeat Agent:** Linux virtual machine
- **Traffic Type Monitored:** DNS (UDP/53)
- **Index Used:** `.ds-packetbeat-*`

---

## 3. Attack Simulation
DNS tunneling behavior was simulated by generating DNS queries with:
- Unusually long subdomains
- Randomized/encoded strings
- Repeated DNS requests to a controlled domain (`eviltest.com`)

Example activity:
- Multiple DNS queries with long subdomain names exceeding normal length
- Queries resolved successfully, indicating outbound DNS communication

---

## 4. Log Source & Evidence
Packetbeat captured DNS traffic with the following key fields:
- `dns.question.name`
- `dns.question.subdomain`
- `network.protocol`
- `event.dataset`
- `@timestamp`

Evidence confirmed:
- DNS queries containing long, suspicious subdomains
- Traffic direction: outbound (egress)
- Protocol: UDP / DNS

---

## 5. Detection Logic
A custom query rule was created in Kibana to identify DNS tunneling patterns.

### KQL Rule
event.dataset : "dns"
and strlen(dns.question.name) > 50
and network.protocol : "dns"

-----

### Rationale
DNS tunneling tools encode data into subdomains, increasing query length beyond normal DNS usage. This rule flags such anomalies.

---

## 6. Alert Triggered
- Alert Name: **DNS Tunneling Detection**
- Severity: Medium
- Status: Triggered successfully
- Detection Engine: Kibana Security – Custom Query Rule

The alert fired immediately upon execution of simulated tunneling queries.

---

## 7. MITRE ATT&CK Mapping
- **Tactic:** Command and Control
- **Technique:** Application Layer Protocol
- **Sub-technique:** DNS
- **Technique ID:** T1071.004

---

## 8. Analyst Action (SOC Response)
Recommended response steps:
1. Validate DNS query destination and domain reputation
2. Identify affected host generating the traffic
3. Review volume and frequency of DNS queries
4. Block malicious domain at DNS/firewall level
5. Escalate to L2 if repeated or confirmed exfiltration

---

## 9. Outcome
- DNS tunneling activity was successfully detected
- Custom SIEM rule functioned as expected
- Packetbeat proved effective for DNS-level visibility
- Detection aligns with real-world SOC monitoring practices

---

## 10. Conclusion
This exercise demonstrates the ability to design, test, and validate a custom SIEM detection for DNS tunneling. The approach is scalable and can be enhanced further by adding frequency-based thresholds and entropy analysis.



