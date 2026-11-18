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

$$\text{Total Response Time} = T_{\text{detection}} + T_{\text{install}}$$

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

## 7. Experimental Verification & Live Demonstration Screenshots

The following screenshots were captured live during the system execution and evaluation demo on the Ubuntu Virtual Machine, validating every requirement of the D1 (15 Marks) and D2 (25 Marks) evaluation rubrics.

### Screenshot 1: Mininet Network Topology & Concurrent TCP Sockets (Step a)
<p align="center">
  <img src="screenshots/VirtualBox_Ubuntu_18_11_2026_19_45_34.png" width="95%" alt="Screenshot 1: Mininet Topology and Concurrent TCP Clients">
</p>

* **Rubric Mapping:** **D1.1** (Problem Understanding & Architecture), **D1.2** (TCP Sockets & Concurrency), **D1.3** (Mininet Topology).
* **Technical Observation:** Terminal 3 displays the Mininet link topology (`net`) connecting hosts `h1`–`h4` to Open vSwitch `s1` and application server `srv`. Host `h2` launches 4 concurrent client threads making simultaneous requests to `srv:8080`, all completing with 100% success (`8/8 ok`). In Terminal 1, the centralized security logger is online and recording active connections over TCP port 9999.

---

### Screenshot 2: Traffic Classification by IP, Port & Protocol (Step b)
<p align="center">
  <img src="screenshots/VirtualBox_Ubuntu_18_11_2026_19_47_05.png" width="95%" alt="Screenshot 2: Policy-Based Traffic Classification">
</p>

* **Rubric Mapping:** **D2.1** (Application Functionality), **D2.2** (Policy Classification Engine).
* **Technical Observation:** Privileged host `h1` connects to management port 2222 and is **ALLOWED** under Rule R1. Host `h2` attempts to connect to the same port 2222 and is immediately **DENIED** with connection timeout under Rule R2. Legacy unencrypted Telnet (port 23) is dropped network-wide (Rule R4). In Terminal 2, the controller logs `DENY 10.0.0.2 -> 10.0.0.100:2222 (ADMIN, rule R2)`, and Terminal 1 captures the corresponding JSON `DENY` event.

---

### Screenshot 3: TCP Connection Flood & Dynamic Hardware DROP Rule (Step c)
<p align="center">
  <img src="screenshots/VirtualBox_Ubuntu_18_11_2026_19_47_48.png" width="95%" alt="Screenshot 3: Dynamic Attack Detection and Hardware Drop Enforcement">
</p>

* **Rubric Mapping:** **D2.2** (Dynamic SDN Defense), **D2.3** (Challenging Scenario — Volumetric Flood).
* **Technical Observation:** Adversary host `h4` launches an aggressive multi-threaded connection flood against `srv:8080`. The sliding-window detector triggers an anomaly verdict in **266 ms**. Terminal 2 logs `BLOCK 10.0.0.4 CONN_FLOOD, offence #1, 20s`. The controller purges old flows via `OFPFC_DELETE` and installs a line-rate drop rule into switch `s1` (`priority=60000, dl_type=0x800, nw_src=10.0.0.4, actions=drop`). Subsequent pings from `h4` suffer **100% packet loss**, while legitimate client `h2` continues transacting with **100% success** (`3/3 ok`).

---

### Screenshot 4: Autonomous Switch Recovery via hard_timeout (Step d)
<p align="center">
  <img src="screenshots/VirtualBox_Ubuntu_18_11_2026_19_48_54.png" width="95%" alt="Screenshot 4: Autonomous Hardware Recovery">
</p>

* **Rubric Mapping:** **D2.2** (Automatic Recovery & Switch Timers).
* **Technical Observation:** After the 20-second `hard_timeout` expires, Open vSwitch `s1` automatically purges the drop flow from hardware without requiring controller polling. OVS dispatches an asynchronous `OFPT_FLOW_REMOVED` message containing dropped packet counters. Terminal 2 logs `RECOVERY 10.0.0.4: block expired, packets dropped`, and Terminal 1 streams an `UNBLOCK` event. Host `h4` connectivity is fully restored.

---

### Screenshot 5: Repeat Offender Exponential Penalty Escalation (Step e)
<p align="center">
  <img src="screenshots/VirtualBox_Ubuntu_18_11_2026_19_49_08.png" width="95%" alt="Screenshot 5: Repeat Offender Escalation">
</p>

* **Rubric Mapping:** **D2.2** (Dynamic SDN Policy), **D2.3** (Robustness & Escalation).
* **Technical Observation:** Upon recovering, host `h4` launches a second flood attack. The controller queries `self.offences['10.0.0.4']` and doubles the penalty duration. Terminal 2 logs `BLOCK 10.0.0.4 CONN_FLOOD ... offence #2, blocked for 40s`. The switch flow table dump confirms `hard_timeout=40`.

---

### Screenshot 6: Port Scan Detection & Mitigation (Step f)
<p align="center">
  <img src="screenshots/VirtualBox_Ubuntu_18_11_2026_19_49_49.png" width="95%" alt="Screenshot 6: Port Scan Detection">
</p>

* **Rubric Mapping:** **D2.3** (Challenging Scenario — Reconnaissance Attack).
* **Technical Observation:** Host `h3` initiates an automated TCP port scan. After probing 8 distinct target ports, the detector identifies horizontal reconnaissance and blocks `h3` in just **71.4 ms**. The scanner output confirms: `open ports found: none - h3 was blocked after 8 probes`. Terminal 2 logs `BLOCK 10.0.0.3 PORT_SCAN`.

---

### Screenshot 7: Persistent Policy Violations — Whole Host Quarantine (Step g)
<p align="center">
  <img src="screenshots/VirtualBox_Ubuntu_18_11_2026_19_50_02.png" width="95%" alt="Screenshot 7: Policy Violation Quarantine">
</p>

* **Rubric Mapping:** **D2.2** (Dynamic Filtering), **D2.3** (Persistent Unauthorized Access).
* **Technical Observation:** Host `h2` repeatedly attempts to probe the restricted management port 2222. After 5 consecutive denied attempts within 5 seconds, the detector flags `POLICY_VIOLATION`. The controller isolates the entire host, revoking even its legitimate access to public application port 8080.

---

### Screenshot 8: Robustness Under Centralized Logger Outage (Step h)
<p align="center">
  <img src="screenshots/VirtualBox_Ubuntu_18_11_2026_19_50_43.png" width="95%" alt="Screenshot 8: Logger Outage Buffering">
</p>

* **Rubric Mapping:** **D2.3** (Fault Tolerance & Subsystem Failures).
* **Technical Observation:** The central logger process is intentionally killed to simulate service failure. While the logger is down, the controller buffers security events in an in-memory queue without dropping packets or stalling control loop threads. When the logger restarts, the background `EventSender` thread reconnects and immediately flushes all buffered events with zero log loss.

---

### Screenshot 9: Controller Outage & Fail-Closed Security Posture (Step i)
<p align="center">
  <img src="screenshots/VirtualBox_Ubuntu_18_11_2026_19_51_02.png" width="95%" alt="Screenshot 9: Controller Failure and Fail-Closed OVS">
</p>

* **Rubric Mapping:** **D2.3** (System Robustness & Fail-Closed Architecture).
* **Technical Observation:** The POX controller process is terminated. Because Open vSwitch is configured with `failMode='secure'`, the switch refuses to forward unauthenticated new flows (fails closed). When the controller is restarted, switch `s1` seamlessly re-establishes OpenFlow communication (`SWITCH_CONNECTED`), restoring normal operations.

---

### Screenshot 10: Centralized Security Audit Log & Performance Results (Step j & k)
<p align="center">
  <img src="screenshots/VirtualBox_Ubuntu_18_11_2026_19_51_51.png" width="95%" alt="Screenshot 10: Centralized Audit Trail and Results Table">
</p>

* **Rubric Mapping:** **D2.1** (Centralized Logging), **D2.4** (Performance Comparison).
* **Technical Observation:** Inspection of `logs/security_events.log` confirms an immutable audit trail of all `SWITCH_CONNECTED`, `DENY`, `BLOCK`, `BLOCK_ENFORCED`, and `UNBLOCK` records. Below, the final live performance evaluation table displays the empirical comparison between Static and Dynamic firewall modes.

---

### Screenshot 11: End-to-End System Check Validation (12 / 12 Passed)
<p align="center">
  <img src="screenshots/VirtualBox_Ubuntu_18_11_2026_19_54_04.png" width="95%" alt="Screenshot 11: 12 of 12 System Checks Passed">
</p>

* **Rubric Mapping:** **D1.5** (Initial Testing & Verification), **D2.5** (Reproducible Final Demonstration).
* **Technical Observation:** Execution of `sudo python3 tests/system_check.py` confirms that all 12 end-to-end integration tests pass with 100% success, validating pingall connectivity, socket concurrency, bulk data transfer (7.61 Mbit/s), dynamic blocking (248 ms), auto-recovery (8.5 s), repeat offender doubling, and port scan defense.

---

## 8. Conclusion

The Dynamic SDN Firewall successfully fulfills all criteria of the Jackfruit mini-project rubric. By uniting Python low-level TCP socket programming with POX OpenFlow control, the system eliminates the vulnerabilities of static packet filtering. Real-time experimental validation confirms that volumetric connection floods and stealth port scans are detected and mitigated within **266.4 ms** and **71.4 ms** respectively, preserving **100% goodput and low latency** for legitimate clients.
