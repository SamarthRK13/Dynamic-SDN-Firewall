# Project Report: Dynamic SDN Firewall with Centralized Security Event Logger

**Course:** Computer Networks — SDN & Socket Programming Mini Project (Jackfruit)  
**Deliverables:** Deliverable 1 (15 Marks) & Deliverable 2 (25 Marks) — Total: 40 Marks  
**Repository Directory:** `SDN-Firewall-FINAL`  

---

## 1. Executive Summary & Team Contributions

This project designs, implements, and evaluates an automated, adaptive network security architecture combining low-level **TCP socket programming** with **Software-Defined Networking (SDN)**. Traditional static firewalls rely on pre-configured IP/port access control lists (ACLs) and lack the intelligence to inspect dynamic traffic rates or react to volumetric distributed threats. Under heavy attacks like TCP SYN connection floods or aggressive port scans, static firewalls allow malicious traffic to overwhelm server sockets and consume bottleneck link bandwidth.

Our solution deploys a **POX OpenFlow 1.0 SDN controller** managing an **Open vSwitch (OVS)** data plane in **Mininet**. The controller dynamically classifies every incoming TCP connection, maintains a real-time sliding-window traffic anomaly detector, automatically installs proactive line-rate OpenFlow `DROP` rules on the hardware switch table, supports exponential penalty escalation for repeat offenders, enables automatic recovery via switch-enforced `hard_timeout`, and streams auditable security events over an independent TCP channel to a **Centralized Security Event Logger**.

### Team Work Division

| Team Member | Role & Responsibilities | Key Code Components |
|---|---|---|
| **Member 1** | **TCP Sockets & Centralized Logging Server** | `app/server.py`, `app/client.py`, `app/logger_server.py` |
| **Member 2** | **SDN Controller, Rules & Dynamic Defense Engine** | `controller/firewall.py`, `controller/rules.py`, `config/policy.json` |
| **Member 3** | **Mininet Topology, Attack Simulation & Benchmarking** | `topology/`, `traffic/attacker.py`, `tests/`, `experiments/` |

---

## 2. Problem Statement & Motivation

### Why Traditional Firewalls Fail
1. **Static Rules Cannot Detect Volumetric Behavior:** A static firewall allows traffic to port 8080 because the service is public. An attacker flooding 150 connection requests per second to port 8080 matches the `ALLOW` rule and exhausts server sockets and buffer memory.
2. **End-Host Overhead:** Traditional software firewalls (e.g., Linux `iptables`) inspect and drop packets on the host operating system kernel, consuming server CPU cycles and link bandwidth.
3. **Lack of Automated Recovery & Escalation:** Static rules require human intervention to blacklist and whitelist IP addresses.

### The SDN Solution
SDN decouples the **control plane** (routing and security decisions) from the **data plane** (packet forwarding). When a flood occurs, the SDN controller detects the rate anomaly and pushes a line-rate `DROP` flow rule directly into the OpenFlow switch flow table. The switch drops all subsequent attack packets in hardware/fast-path *before* they ever traverse the bottleneck link or touch the server operating system.

---

## 3. System Architecture & Topology

### Physical & Logical Topology

```
             +-------------------------------------------------------+
             |                 POX SDN CONTROLLER                    |
             |             (controller/firewall.py)                  |
             +---------------------------+---------------------------+
                                         | OpenFlow 1.0 (TCP :6633)
                                         | [PacketIn / FlowMod / Barrier]
                                         v
   +-------------------------------------------------------------------------+
   |                        Open vSwitch s1 (Mininet)                        |
   |              Flow Table: Default PacketIn + Priority 60000 Drop         |
   +-----+-------------------+-------------------+---------------------+-----+
         |                   |                   |                     |
         |                   |                   |                     | 10 Mbit/s (Bottleneck)
         |                   |                   |                     v
   +-----+------+      +-----+------+      +-----+------+       +------+------+
   |  Host h1   |      |  Host h2   |      |  Host h3   |       | Server srv  |
   | 10.0.0.1   |      | 10.0.0.2   |      | 10.0.0.3   |       | 10.0.0.100  |
   | (Admin)    |      | (Client)   |      | (Client)   |       | :8080 Service|
   +------------+      +------------+      +------------+       | :2222 Admin |
                                                                +-------------+
         |
   +-----+------+                                               +-------------+
   |  Host h4   |                                               | Logger Host |
   | 10.0.0.4   |                                               | 10.0.0.200  |
   | (Attacker) |                                               | :9999 TCP   |
   +------------+                                               +------+------+
                                                                       ^
                                  Centralized Security Event Stream    |
                                  (JSON over TCP socket connection)----+
```

### Static Policy Table (`config/policy.json`)

Rules are evaluated sequentially (**first match wins**):

| Rule ID | Source IP | Destination IP | Destination Port | Protocol | Action | Traffic Class | Description |
|---|---|---|---|---|---|---|---|
| **R1** | `10.0.0.1` | `10.0.0.100` | `2222` | TCP | `ALLOW` | `ADMIN` | Admin host granted access to management port. |
| **R2** | `any` | `10.0.0.100` | `2222` | TCP | `DENY` | `ADMIN` | All other hosts denied access to admin port. |
| **R3** | `10.0.0.0/24`| `10.0.0.100` | `8080` | TCP | `ALLOW` | `SERVICE`| Legitimate subnet clients allowed access to app. |
| **R4** | `any` | `any` | `23` | TCP | `DENY` | `TELNET` | Insecure Telnet traffic dropped network-wide. |
| **Default**| `any` | `any` | `any` | Any | `ALLOW` | `OTHER` | ARP, ICMP, and standard flows forwarded. |

---

## 4. Implementation Details

### A. TCP Socket Implementation & Concurrency (`app/`)
* **Multi-threaded Server (`app/server.py`):** Listens on dual ports (`8080` for service, `2222` for admin). Uses a master listening socket with `SO_REUSEADDR`, spawning an independent worker thread per client connection via Python's `threading` module.
* **Concurrency Protection:** Uses a `threading.BoundedSemaphore(50)`. When active connections exceed 50, incoming clients receive `ERR BUSY` before clean socket shutdown, preventing socket starvation.
* **Application Protocol:** Text-line framing terminated by `\n`. Supports `PING` $\to$ `PONG`, `ECHO <msg>`, `DATA <bytes>` (raw binary payload streaming), `STATS`, and `QUIT`.
* **Centralized Logger Server (`app/logger_server.py`):** Runs on TCP port `9999`. Receives JSON-serialized events from the controller, appending to both human-readable `logs/security_events.log` and machine-readable `logs/security_events.jsonl`.
* **Resilient Non-Blocking Event Sender (`controller/firewall.py`):** The controller uses a dedicated background thread with an unbounded memory queue. If the logger crashes, events buffer in memory and automatically flush upon reconnection.

### B. Dynamic SDN Controller & Threat Detection (`controller/`)
* **Packet-In Processing:** First packets of new TCP flows (TCP SYN) trigger `PacketIn` events. The controller parses Ethernet, IPv4, and TCP headers.
* **Sliding-Window Anomaly Detector (`controller/rules.py`):** Maintains a rolling 5-second sliding window for each source IP, evaluating three simultaneous behavioral vectors:
  1. `CONN_FLOOD`: $\ge 25$ new TCP connections within 5 seconds.
  2. `PORT_SCAN`: $\ge 8$ unique destination ports or IPs probed within 5 seconds.
  3. `POLICY_VIOLATION`: $\ge 5$ attempts matching `DENY` rules within 5 seconds.
* **Hardware Enforcement (`block()`):**
  1. Sends OpenFlow `OFPFC_DELETE` to purge existing active flows for that IP.
  2. Installs a high-priority wildcard flow (`priority=60000`, `nw_src=<ip>`, `actions=[]` (DROP)) with `hard_timeout`.
  3. Dispatches an OpenFlow `BarrierRequest` and awaits `BarrierReply` to confirm exact hardware installation timing.
* **Automatic Recovery & Escalation:** When `hard_timeout` expires, Open vSwitch purges the rule automatically and sends `OFPT_FLOW_REMOVED` to the controller with byte/packet drop counters. Repeat offenders face exponential penalty:
  $$\text{Block Duration} = 20\text{ s} \times 2^{(\text{offence} - 1)} \quad (\text{capped at } 160\text{ s})$$

---

## 5. Live Experimental Evaluation & Results

The live benchmark was executed inside the Ubuntu Mininet environment using:
```bash
sudo python3 experiments/run_experiments.py --repeat 1 && python3 experiments/plot_results.py
```

### Table 1: Legitimate Users (`h1`–`h3`) Performance Under Attack

| Traffic Condition | Firewall Mode | Success Rate (%) | Average Latency (ms) | Goodput (Mbit/s) | Attack Successes | Attack Blocked After (ms) | Controller Packet-Ins |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **No Attack** | Static Baseline | 100.0% | 54.4 ms | 1.92 Mbit/s | — | — | 1,672 |
| **No Attack** | Dynamic SDN | 100.0% | 35.1 ms | 1.92 Mbit/s | — | — | 1,757 |
| **Connection Flood** | Static Baseline | **87.5%** | **1,169.0 ms** | **0.37 Mbit/s** | **2,198** | *(Never Blocked)* | **5,149** |
| **Connection Flood** | **Dynamic SDN** | **100.0%** | **42.0 ms** | **1.91 Mbit/s** | **2** | **266.4 ms** | **1,831** |
| **Port Scan** | Static Baseline | 100.0% | 32.2 ms | 1.93 Mbit/s | 1 *(Port 8080 exposed)* | *(Never Blocked)* | 3,863 |
| **Port Scan** | **Dynamic SDN** | **100.0%** | **44.0 ms** | **1.93 Mbit/s** | **0** *(No ports found)* | **71.4 ms** | **1,601** |

### Table 2: Reaction Time vs. Flood Rate (Dynamic Firewall)

$$\text{Total Response Time} = T_{\text{detection}} + T_{\text{rule\_install}}$$

| Flood Rate (conn/s) | Evidence Detection ($T_{\text{detection}}$) | Rule Installation ($T_{\text{install}}$) | Total Response Time |
|:---:|:---:|:---:|:---:|
| **10 conn/s** | 2,389.5 ms | 48.0 ms | 2,437.5 ms |
| **25 conn/s** | 943.7 ms | 61.1 ms | 1,004.9 ms |
| **50 conn/s** | 470.3 ms | 18.0 ms | 488.3 ms |
| **100 conn/s** | 221.6 ms | 45.2 ms | 266.8 ms |
| **200 conn/s** | 215.7 ms | 76.0 ms | 291.7 ms |

---

## 6. Graphical Analysis

### Figure 1: Success Rate & Latency Comparison (`fig1_normal_users.png`)
<p align="center">
  <img src="results/fig1_normal_users.png" width="85%" alt="Figure 1: Success Rate & Latency Comparison">
</p>

* **Analysis:** Under normal conditions, both architectures achieve 100% success. However, during a TCP connection flood, the Static Firewall suffers severe degradation: legitimate client success drops to **87.5%**, and latency spikes by **2,048%** (from 54.4 ms to 1,169.0 ms). In contrast, the Dynamic SDN firewall maintains **100.0% success** and **42.0 ms latency**, completely shielding legitimate clients.

### Figure 2: Legitimate Client Latency Timeline (`fig2_flood_timeline.png`)
<p align="center">
  <img src="results/fig2_flood_timeline.png" width="85%" alt="Figure 2: Latency Timeline during Flood">
</p>

* **Analysis:** At time $t = 5\text{ s}$, `h4` begins flooding connections. In the Static Firewall (orange curve), legitimate latency immediately climbs above 1,000 ms and remains elevated for the entire duration of the attack due to socket buffer exhaustion. In the Dynamic Firewall (blue curve), latency experiences a momentary blip for 266 ms before immediately dropping back to baseline (~40 ms) as the switch drop rule takes effect.

### Figure 3: Response Time Scaling (`fig3_response_time.png`)
<p align="center">
  <img src="results/fig3_response_time.png" width="75%" alt="Figure 3: Response Time Scaling vs Flood Rate">
</p>

* **Analysis:** As attack velocity increases from 10 conn/s to 200 conn/s, detection time plummets from 2,389.5 ms down to 215.7 ms. The sliding-window detector accumulates the 25 required anomaly samples faster under aggressive attacks, demonstrating that the system responds fastest when threat severity is highest.

---

## 7. Mandatory Screenshots (SS) Checklist for Submission

| # | Screenshot Identifier | What to Capture in VM | Rubric Mapping |
|:---:|---|---|---|
| **SS 1** | **Mininet Topology & Pingall** | Terminal running `net` and `pingall` showing 0% packet loss across all hosts (`h1`–`h4`, `srv`, `log`). | D1.1, D1.3 |
| **SS 2** | **Concurrent TCP Sockets** | Output of `h2 python3 app/client.py --count 8 --parallel 4` showing parallel multi-client requests. | D1.2, D1.4 |
| **SS 3** | **Centralized Logger Output** | Terminal showing `logger_server.py` receiving JSON events (`SWITCH_CONNECTED`, `DENY`, `BLOCK`). | D1.2, D2.1 |
| **SS 4** | **Policy Classification** | Terminal showing `h1` allowed on admin port 2222 while `h2` is denied on port 2222. | D2.1, D2.2 |
| **SS 5** | **Dynamic Attack Block (OVS)** | Terminal showing controller logging `BLOCK 10.0.0.4 CONN_FLOOD` and `ovs-ofctl dump-flows s1` with `priority=60000,actions=drop`. | D2.2, D2.3 |
| **SS 6** | **Auto-Recovery & Escalation** | Terminal showing switch `FlowRemoved` log followed by repeat attack with `hard_timeout=40`. | D2.2, D2.3 |
| **SS 7** | **Performance Benchmark & Report**| Terminal output of `system_check.py` (12/12 passed) and the 3 generated PNG plots. | D1.5, D2.4 |

---

## 8. Conclusion

The Dynamic SDN Firewall successfully fulfills all criteria of the Jackfruit mini-project rubric. By uniting Python low-level TCP socket programming with POX OpenFlow control, the system eliminates the vulnerabilities of static packet filtering. Real-time experimental validation confirms that volumetric connection floods and stealth port scans are detected and mitigated within **266.4 ms** and **71.4 ms** respectively, preserving **100% goodput and low latency** for legitimate clients.
