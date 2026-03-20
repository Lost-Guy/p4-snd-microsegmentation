# Zero-Trust Micro-Segmentation & DDoS Mitigation Data Plane

A production-grade, software-defined data plane implementation written in P4_16 (`v1model`) and deployed across a Leaf-Spine topology using BMv2 and Mininet within a Dockerized environment (`p4lang/p4app`).

This architecture delivers hardware-enforced Zero-Trust micro-segmentation, line-rate volumetric DDoS flood mitigation using dual-rate token bucket meters, and real-time per-flow telemetry counters.

---

## Architecture Overview

```text
               ┌─────────────────────────────────────────┐
               │          Ingress IPv4 Packet            │
               └────────────────────┬────────────────────┘
                                    │
                                    ▼
               ┌─────────────────────────────────────────┐
               │       TopIngressTelemetry               │  --> Direct per-flow packet & byte counting
               └────────────────────┬────────────────────┘
                                    │
                                    ▼
               ┌─────────────────────────────────────────┐
               │       TopDDoSProtection                 │  --> Meter execution (CIR/PIR packet rate limit)
               └────────────────────┬────────────────────┘
                                    │
                                    ├──> Mark to Drop (If Meter Color == RED)
                                    ▼
               ┌─────────────────────────────────────────┐
               │          TopIngress                     │  --> L3 LPM IPv4 Routing Resolution
               └────────────────────┬────────────────────┘
                                    │
                                    ▼
               ┌─────────────────────────────────────────┐
               │      TopMicrosegmentation               │  --> Default-Deny ACL Table Verification
               └────────────────────┬────────────────────┘
                                    │
                                    ├──> Mark to Drop (If Match Miss / Explicit Drop)
                                    ▼
               ┌─────────────────────────────────────────┐
               │           Egress Forwarding             │
               └─────────────────────────────────────────┘

```

* **Default-Deny Micro-Segmentation**: All inter-host communication is blocked by default via `tbl_microsegmentation`. Flow access is granted explicitly based on source IP, destination IP, and L4 protocol.
* **Line-Rate DDoS Rate Limiting**: Ingress traffic is metered per port using `MeterType.packets`. Traffic exceeding calibrated Peak Information Rates (PIR) is assigned `MeterColor.RED` (`2`) and immediately dropped by `mark_to_drop()` prior to downstream routing or forwarding.
* **Direct Flow Telemetry**: Data-plane security policy actions update `direct_counter` instances (`CounterType.packets_and_bytes`), providing zero-overhead, real-time auditability.
* **Host Namespace Integration**: Eliminates Mininet virtualized network inconsistencies by programmatically injecting static ARP table entries into host namespaces (`nsenter`) and disabling hardware offloads (`ethtool -K tx off rx off`).

---

## Security Policy & Rate-Limiting Matrix

| Ingress Host | Egress Host | Protocol | Micro-Seg Policy | DDoS Meter Limits (CIR / PIR) | Operational Purpose |
| --- | --- | --- | --- | --- | --- |
| `h1` (`10.0.0.1`) | `h2` (`10.0.0.2`) | ICMP (`1`) / UDP (`17`) | **PERMIT** | `100 pps` (CIR) / `400 pps` (PIR) | Permitted Intra-switch flow |
| `h1` (`10.0.0.1`) | `h3` (`10.0.0.3`) | ICMP (`1`) | **PERMIT** | `100 pps` (CIR) / `400 pps` (PIR) | Permitted Inter-switch flow |
| `h2` (`10.0.0.2`) | `h3` (`10.0.0.3`) | Any | **DEFAULT DROP** | Rate-limited | Prevents lateral movement |
| Any Host | `h4` (`10.0.0.4`) | Any | **DEFAULT DROP** | Rate-limited | Host isolation / Quarantine |

---

## Repository Structure

```text
.
├── p4src/
│   ├── main.p4             # Main P4_16 pipeline (Telemetry, DDoS, L3 Routing, Micro-seg)
│   ├── headers.p4          # Protocol header definitions & metadata structures
│   ├── parser.p4           # Ethernet & IPv4 packet parser logic
│   ├── ingress.p4          # Standard forwarding actions & LPM lookup tables
│   └── telemetry.p4        # Direct telemetry counter blocks
├── controller/
│   └── p4runtime_client.py # Dynamic Thrift CLI rule program, ARP setup, and meter manager
├── tests/
│   ├── test_microsegmentation.py # Automated test runner for Zero-Trust policy matrix
│   └── test_ddos_mitigation.py   # Socket-level test runner for low-rate vs. volumetric flood
├── Makefile                # Compilation & Mininet orchestration targets
└── README.md               # Project documentation

```

---

## Meter Calibration & DDoS Tuning Specs

To account for virtualized veth pair constraints in Mininet, meter parameters are calibrated as follows:

* **CIR (Committed Information Rate)**: `0.0001` pkts/$\mu$s ($100\text{ pkts/sec}$)
* **CBS (Committed Burst Size)**: `10` packets
* **PIR (Peak Information Rate)**: `0.0004` pkts/$\mu$s ($400\text{ pkts/sec}$)
* **PBS (Peak Burst Size)**: `15` packets

---

## Deployment & Verification Guide

### 1. Build Network & Launch Topology

Compile the P4 pipeline into BMv2 JSON format and instantiate the Mininet Leaf-Spine topology:

```bash
make run-topo

```

### 2. Program Baseline Rules & Meters

Inject switch routing tables, static ARP entries into host namespaces, baseline micro-segmentation policies, and DDoS meter rates:

```bash
docker exec -it $(docker ps -q --filter ancestor=p4lang/p4app) python /workspace/controller/p4runtime_client.py

```

### 3. Verify Zero-Trust Micro-Segmentation Matrix

Run the automated micro-segmentation test suite to validate allowed flows, default-deny drops (lateral movement), and dynamic flow unblocking:

```bash
docker exec -it $(docker ps -q --filter ancestor=p4lang/p4app) python /workspace/tests/test_microsegmentation.py

```

**Expected Result:**

```text
==================================================
  ZERO-TRUST MICRO-SEGMENTATION AUTOMATED SUITE
==================================================

<........>

--- Testing Baseline Micro-Segmentation Policy Matrix ---
[PASS] Intra-switch Permitted (h1 -> h2)          | Expected: ALLOW | Got: ALLOW
[PASS] Inter-switch Permitted (h1 -> h3)          | Expected: ALLOW | Got: ALLOW
[PASS] Inter-switch Lateral Drop (h2 -> h3)       | Expected: BLOCK | Got: BLOCK
[PASS] Host Quarantine Drop (h1 -> h4)            | Expected: BLOCK | Got: BLOCK
[PASS] Host Quarantine Drop (h2 -> h4)            | Expected: BLOCK | Got: BLOCK
[PASS] Host Quarantine Drop (h3 -> h4)            | Expected: BLOCK | Got: BLOCK

--- Testing Dynamic Policy Enforcement (Unblocking h1 -> h4) ---
[+] Dynamically PERMITTED flow: 10.0.0.1 <-> 10.0.0.4 (proto 1) on port 9090
[+] Dynamically PERMITTED flow: 10.0.0.1 <-> 10.0.0.4 (proto 1) on port 9091
[PASS] Dynamic Policy Modification (h1 -> h4) | Expected: ALLOW | Got: ALLOW

<........>

==================================================
 TEST RESULTS: 7/7 TEST CASES PASSED
==================================================

```

### 4. Verify DDoS Mitigation & Volumetric Flood Protection

Run the socket-level DDoS mitigation test suite to verify that low-rate traffic passes cleanly while unthrottled high-rate floods are mitigated at line rate:

```bash
docker exec -it $(docker ps -q --filter ancestor=p4lang/p4app) python /workspace/tests/test_ddos_mitigation.py

```

**Expected Result:**

```text
==================================================
    DDoS FLOOD MITIGATION TEST SUITE (P4 METER)
==================================================

<........>

[+] Dynamically permitting UDP traffic (proto 17) for h1 <-> h2...
[+] Dynamically PERMITTED flow: 10.0.0.1 <-> 10.0.0.2 (proto 17) on port 9090
[+] Dynamically PERMITTED flow: 10.0.0.1 <-> 10.0.0.2 (proto 17) on port 9091

--- Test 1: Low-Rate Legitimate Traffic (5 pkts @ 10 pkts/sec) ---
Sent: 5 packets | Received: 5 packets
[PASS] Low-rate traffic permitted through data plane.

--- Test 2: Volumetric Flood Attack (300 pkts back-to-back) ---
Sent: 300 packets | Received: 22 packets | Dropped: 278 packets (92.7% Loss)
[PASS] Volumetric flood mitigated at line rate by P4 meter (RED drops).

==================================================
          DDoS MITIGATION TEST COMPLETE
==================================================

```

### 5. Inspect Direct Telemetry Counters

Fetch live data-plane telemetry counters from active switch tables:

```bash
docker exec -it $(docker ps -q --filter ancestor=p4lang/p4app) python -c "
import sys; sys.path.append('/workspace/controller')
import p4runtime_client
p4runtime_client.fetch_telemetry(9090, 's1')
"

```
