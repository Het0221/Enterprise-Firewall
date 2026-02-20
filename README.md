# Enterprise Firewall & Access Control Lab (IPFire)

![Domain](https://img.shields.io/badge/Domain-Network%20Security%20%26%20Access%20Control-2962FF?style=for-the-badge&logoColor=white)
![Techniques](https://img.shields.io/badge/Techniques-Firewall%20Rules%20%7C%20NAT%20%7C%20Zero--Trust-00C853?style=for-the-badge&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-IPFire%20%7C%20VMware%20%7C%20Kali%20Linux-FF6D00?style=for-the-badge&logoColor=white)
![Tools](https://img.shields.io/badge/Tools-IPFire%20%7C%20curl%20%7C%20SSH%20%7C%20Wireshark-8E24AA?style=for-the-badge&logoColor=white)

---

## Objective

This lab demonstrates the design and implementation of an **enterprise-style firewall** using IPFire to enforce traffic control between trusted (GREEN/internal) and untrusted (RED/external) network zones. The goal was to build a secure gateway following **defense-in-depth** and **zero-trust** principles — only explicitly permitted traffic is allowed, everything else is dropped by default.

Key focus areas include protocol-based access control, NAT with port forwarding, threat intelligence-based blocking (Shodan scanners), and comprehensive firewall logging for audit and forensic purposes.

---

## What This Lab Demonstrates

- How to segment a network into internal (GREEN) and external (RED) security zones
- Protocol-specific firewall rule design (HTTP, HTTPS, ICMP, DNS, SSH)
- Default-deny security posture and zero-trust implementation
- NAT with port forwarding for secure external access to internal services
- Threat intelligence blocking using host groups (Shodan scanner IPs)
- Layer 2 vs Layer 3 traffic behavior — why intra-subnet traffic bypasses firewall inspection
- Firewall logging for security monitoring, incident triage, and compliance

---

## Tools & Technologies

| Tool | Purpose |
|------|---------|
| **IPFire 3.29** | Open-source enterprise firewall/gateway |
| **VMware Workstation** | 4-VM lab environment |
| **Kali Linux** | Internal (`kali_in`, `kali_in_2`) and external (`kali_out`) test machines |
| **curl** | HTTP/HTTPS traffic testing and TLS handshake verification |
| **SSH** | Port-forwarded remote access validation |
| **IPFire Firewall Logs** | Traffic audit, rule verification, forensic review |

---

## Network Topology

```
                    ┌─────────────────────────────┐
                    │         IPFire Gateway        │
                    │  GREEN: 192.168.129.10/24     │
                    │  RED:   10.0.0.201            │
                    └────────────┬────────────┬─────┘
                                 │            │
              ┌──────────────────┘            └──────────────────┐
              │ GREEN (Internal/Trusted)        RED (External)   │
    ┌─────────┴────────┐                   ┌────────────────────┐
    │   kali_in         │                   │     kali_out       │
    │ 192.168.129.21    │                   │   10.0.0.3         │
    ├─────────────────  │                   └────────────────────┘
    │   kali_in_2       │
    │ 192.168.129.22    │
    └───────────────────┘
```

| VM | Role | Network | IP Address |
|----|------|---------|------------|
| IPFire | Firewall/Gateway | GREEN + RED | 192.168.129.10 / 10.0.0.201 |
| kali_in | Internal trusted client | GREEN (VMnet1) | 192.168.129.21 |
| kali_in_2 | Internal trusted client | GREEN (VMnet1) | 192.168.129.22 |
| kali_out | External untrusted client | RED (Bridged) | 10.0.0.3 |

---

## Part 1 — Lab Setup

### VM Network Configuration

All internal VMs (`kali_in`, `kali_in_2`) connected to **VMnet1 (Host-only)** — isolated internal segment routed through IPFire GREEN interface.

`kali_out` connected to **Bridged (Automatic)** — simulates external/internet attacker with no direct path to GREEN network.

### Baseline Verification

```bash
# Verify kali_in network config
ifconfig
# eth0: 192.168.129.21 — on GREEN segment, routed through IPFire

# Verify kali_out cannot reach kali_in directly
ping 192.168.129.21
# Result: Request timeout — firewall blocking cross-zone traffic ✓

# Verify kali_in has internet via IPFire
# Browser test: google.com accessible from kali_in ✓
```

---

## Part 2 — Firewall Rules Configuration

### Rule 1 — Allow HTTPS, Block HTTP

```
Rule 1: GREEN → RED, TCP port 443 → ACCEPT  (Allow HTTPS)
Rule 2: GREEN → RED, TCP port 80  → DROP    (Block HTTP)
```

**Verification:**

```bash
# On kali_in — HTTP blocked
curl http://example.org -v
# Result: Network is unreachable — firewall drops all port 80 traffic ✓

# On kali_in — HTTPS allowed
curl https://www.northeastern.edu -v
# Result: TLS handshake completes, SSL certificate verified ✓
# TLSv1.2 / DHE-RSA-AES128-GCM-SHA256 — SSL certificate verify ok
```

---

### Rule 2 — Block Outbound ICMP

```
Rule 3: GREEN → RED, ICMP (All types) → DROP
```

**Verification:**

```bash
# On kali_in — external ping blocked
ping -c 2 8.8.8.8
# Result: 2 packets transmitted, 0 received, 100% packet loss ✓

# On kali_in — internal ping still works (same subnet = Layer 2, bypasses firewall)
ping 192.168.129.22
# Result: 64 bytes from 192.168.129.22 — succeeds ✓
```

> **Key Insight:** Traffic between `kali_in` and `kali_in_2` never crosses the IPFire firewall because both are on the same GREEN subnet. Layer 2 switching handles intra-subnet communication directly — firewall rules only apply to inter-zone (Layer 3 routed) traffic. This is a critical architecture consideration when designing network security controls.

---

### Rule 3 — Default Deny Policy

Configured IPFire firewall policy to DROP all unmatched traffic:

```
Forward policy:  DROP (default)
Outgoing policy: DROP (default)
Input policy:    DROP (default)
```

**Verification:**

```bash
# With only HTTPS rule active and default-deny enabled
curl https://www.exploit-db.com/ -v
# Result: Connection timed out — DNS not yet permitted, default-deny in effect ✓
```

After adding DNS rules (UDP/TCP port 53 GREEN → RED):

```bash
curl https://www.exploit-db.com/ -v
# Result: TLS handshake completes — exploit-db.com accessible via HTTPS ✓
# SSL using TLSv1.3 / TLS_AES_256_GCM_SHA384
```

---

### Rule 4 — Block Shodan Scanner IPs

Created a **host group** `Shodan_Scanners` with 10 known Shodan scanner IPs:

| Host | IP Address |
|------|-----------|
| census 1 | 198.20.69.74 |
| census 2 | 198.20.69.98 |
| census 3 | 198.20.70.114 |
| census 4 | 198.20.99.130 |
| census 5 | 93.120.27.62 |
| census 6 | 66.240.236.119 |
| census 7 | 71.6.135.131 |
| census 8 | 66.240.192.138 |
| census 9 | 71.6.167.142 |
| census 10 | 82.221.105.6 |

```
Rule (Position 1): Source=Shodan_Scanners → Destination=RED, ALL protocols → DROP + LOG
```

> Placed at **rule position 1** so it's evaluated before any inbound allow rules — ensuring scanner traffic is always dropped regardless of other rules.

---

### Rule 5 — NAT Port Forwarding (SSH)

Configured Destination NAT to expose internal SSH securely via a non-standard external port:

```
External: IPFire RED interface : port 223
Internal: kali_in (192.168.129.21) : port 22
Protocol: TCP
```

**Verification from kali_out:**

```bash
ssh -p 223 het@10.0.0.3
# Connected to kali_in via forwarded port ✓
# ED25519 key fingerprint: SHA256:7rLmdDFNpUS+It1Z5FNLqO464CWvCZL9jgdq
```

> Using external port 223 instead of 22 reduces exposure to automated SSH scanners targeting the default port — a simple but effective security hardening technique.

---

## Firewall Rules Summary

| # | Protocol | Source | Destination | Action | Purpose |
|---|----------|--------|-------------|--------|---------|
| 1 | All | Shodan_Scanners | RED | DROP | Block known scanners |
| 2 | UDP/TCP | GREEN | RED:53 | ACCEPT | Allow outbound DNS |
| 3 | TCP | GREEN | RED:443 | ACCEPT | Allow HTTPS |
| 4 | TCP | GREEN | RED:80 | DROP | Block HTTP |
| 5 | ICMP | GREEN | RED | DROP | Block outbound ping |
| 6 | TCP | ANY | RED:223→22 | ACCEPT+NAT | SSH port forward |
| — | ALL | ANY | ANY | DROP | Default deny |

---

## Key Security Concepts Demonstrated

- **Defense-in-Depth:** Multiple layered controls — protocol filtering + default-deny + threat intel blocking
- **Zero-Trust Architecture:** No traffic permitted unless explicitly allowed
- **Least Privilege:** Only required protocols (HTTPS, DNS, SSH) are permitted
- **Principle of Perimeter Security:** GREEN/RED zone separation mirrors real enterprise DMZ design
- **Threat Intelligence Integration:** Proactive blocking of known malicious IPs (Shodan scanners)
- **Layer 2 vs Layer 3 Security Gap:** Intra-subnet traffic bypasses firewall — important consideration for micro-segmentation design
- **Audit Trails:** All rules configured with logging enabled — critical for forensic investigation and compliance

---

## Challenges Faced

**Challenge 1 — Default Deny Broke DNS**
After enabling default-deny, all outbound traffic including DNS stopped working. `curl` could resolve nothing. Had to explicitly add UDP and TCP port 53 rules (GREEN → RED) before HTTPS access worked — a good lesson in how DNS dependency affects all application-layer rules.

**Challenge 2 — ICMP Block Didn't Stop Internal Pings**
After adding the ICMP block rule, pings to `kali_in_2` still succeeded from `kali_in`. This was expected behavior — both machines are on the same GREEN subnet. Layer 2 switching handles this traffic directly without routing through IPFire. Firewall rules only intercept inter-zone (routed) traffic.

**Challenge 3 — Shodan Rule Ordering**
Initially the Shodan block rule was placed below the DNS allow rule. This meant scanner traffic matching the DNS allow rule would pass through before being evaluated against the Shodan block. Moving the Shodan DROP rule to position 1 ensured it was always evaluated first.

**Challenge 4 — Port Forwarding Requires NAT + Firewall Rule**
Port forwarding alone didn't work — IPFire requires both a Destination NAT rule AND a corresponding firewall ACCEPT rule for the forwarded traffic. Missing either one results in silently dropped connections.

---

## Disclaimer

This lab was conducted in an isolated VMware environment for **self-directed learning** in network security, firewall administration, and enterprise access control design. All techniques demonstrated are intended to build defensive security awareness.
