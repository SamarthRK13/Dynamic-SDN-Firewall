# Master Code Walkthrough & Comprehensive Viva Guide

**Course:** Computer Networks — SDN & Socket Programming (Jackfruit Mini Project)  
**Project:** Dynamic SDN Firewall with Centralized Security Event Logger  

---

## 📑 Table of Contents
1. [Architecture & System Flow Overview](#1-architecture--system-flow-overview)
2. [Person 1: TCP Sockets & Centralized Logging Server](#2-person-1-tcp-sockets--centralized-logging-server)
3. [Person 2: POX SDN Controller & Dynamic Defense Engine](#3-person-2-pox-sdn-controller--dynamic-defense-engine)
4. [Person 3: Mininet Topology, Attack Simulation & Benchmarking](#4-person-3-mininet-topology-attack-simulation--benchmarking)
5. [Top 25 Viva Questions with Expert Model Answers](#5-top-25-viva-questions-with-expert-model-answers)
6. [5-Minute Practical Code Experiments (Self-Test)](#6-5-minute-practical-code-experiments-self-test)

---

## 1. Architecture & System Flow Overview

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

### The Life of a Packet (Step-by-Step Flow)
1. **Client SYN Request:** Client `h2` (`10.0.0.2`) connects to `srv` (`10.0.0.100:8080`).
2. **Switch Table Miss:** Open vSwitch `s1` checks its flow table. Finding no matching entry, it encapsulates the packet into an OpenFlow `OFPT_PACKET_IN` and transmits it to the POX controller on TCP port 6633.
3. **L2 Learning:** POX notes `src_mac` on `in_port` for future forwarding.
4. **Firewall Policy Evaluation:** `check_tcp()` in `controller/firewall.py` evaluates the packet against `config/policy.json` (first match wins):
   - If `DENY`: Installs an exact-match `DROP` rule on `s1` and streams a `DENY` event to the logger.
   - If `ALLOW`: Feeds the packet metadata to the sliding-window `Detector`.
5. **Anomaly Detection:** If `Detector` records $\ge 25$ connections within 5 seconds, it returns verdict `CONN_FLOOD`.
6. **Hardware Enforcement:** The controller calls `block()`:
   - Dispatches `OFPFC_DELETE` to flush any existing active flows for that IP.
   - Dispatches `OFPFC_ADD` with `priority=60000`, matching `nw_src=10.0.0.4`, actions `[]` (DROP), and `hard_timeout=20s`.
   - Dispatches an OpenFlow `BarrierRequest` to ensure the rule is physically active in switch TCAM/memory.
7. **Line-Rate Dropping:** Open vSwitch drops subsequent attack packets immediately in fast-path. Server CPU and bottleneck link are shielded.
8. **Automatic Recovery:** After 20 seconds, `hard_timeout` expires on `s1`. The switch removes the rule, sends `OFPT_FLOW_REMOVED` with packet drop counters to the controller, and the controller emits an `UNBLOCK` event.

---

## 2. Person 1: TCP Sockets & Centralized Logging Server

### Primary Code Responsibilities:
* `app/server.py`: Multi-threaded TCP server on ports 8080 (Service) and 2222 (Admin).
* `app/client.py`: High-performance TCP client measuring latency and throughput.
* `app/logger_server.py`: Centralized TCP logging server listening on port 9999.

### Key Code Concepts & Critical Snippets

#### 1. Concurrency Limiting via `BoundedSemaphore` (`app/server.py`)
```python
self.semaphore = threading.BoundedSemaphore(50)

def handle_client(self, conn, addr):
    if not self.semaphore.acquire(blocking=False):
        # Server is overloaded: reject gracefully
        conn.sendall(b"ERR BUSY\n")
        conn.close()
        return
    try:
        # Process client requests
        ...
    finally:
        self.semaphore.release()
```
* **Why it matters:** Unlike standard threads that spawn infinitely until OS memory is exhausted, `acquire(blocking=False)` provides immediate rejection when 50 concurrent sockets are active, preventing thread starvation and server crashes.

#### 2. Byte Stream Line-Framing (`app/server.py` & `app/client.py`)
```python
# TCP is a continuous byte stream without built-in message boundaries.
# We frame application requests using newline delimiters:
reader = conn.makefile("rb")
line = reader.readline() # Buffers until '\n' is encountered
```
* **Why it matters:** TCP does not guarantee that one `send()` corresponds to one `recv()`. Packets can be fragmented or coalesced (Nagle's algorithm). Using `readline()` buffers input safely.

#### 3. Thread-Safe Centralized Event Logger (`app/logger_server.py`)
```python
self.lock = threading.Lock()

def record_event(self, json_data):
    with self.lock:
        with open("logs/security_events.log", "a") as f_text:
            f_text.write(formatted_str + "\n")
        with open("logs/security_events.jsonl", "a") as f_json:
            f_json.write(json.dumps(json_data) + "\n")
```
* **Why it matters:** Multiple controller threads or concurrent senders write to the same log files simultaneously. The `Lock` eliminates race conditions and file corruption.

---

## 3. Person 2: POX SDN Controller & Dynamic Defense Engine

### Primary Code Responsibilities:
* `controller/firewall.py`: POX OpenFlow 1.0 component handling PacketIn, FlowMod, Barrier, and FlowRemoved.
* `controller/rules.py`: Policy matching engine and 5-second sliding-window anomaly detector.
* `config/policy.json`: JSON configuration specifying rules R1–R4, thresholds, and timeout escalations.

### Key Code Concepts & Critical Snippets

#### 1. Sliding-Window Anomaly Detection (`controller/rules.py`)
```python
class Detector:
    def __init__(self, window_sec=5.0, flood_threshold=25, scan_threshold=8):
        self.window = window_sec
        self.events = defaultdict(deque) # ip -> deque of (timestamp, dst_ip, port)

    def new_connection(self, src_ip, dst_ip, dst_port, now):
        dq = self.events[src_ip]
        dq.append((now, dst_ip, dst_port))
        
        # Evict events older than 5 seconds (sliding window)
        while dq and (now - dq[0][0]) > self.window:
            dq.popleft()
            
        # Check port scan (distinct destination/port pairs)
        unique_targets = len({(dst, port) for _, dst, port in dq})
        if unique_targets >= self.scan_threshold:
            return ("PORT_SCAN", unique_targets, dq[0][0])
            
        # Check connection flood
        if len(dq) >= self.flood_threshold:
            return ("CONN_FLOOD", len(dq), dq[0][0])
            
        return (None, 0, 0)
```
* **Why it matters:** An attacker sending 24 connections every 5 seconds is not blocked, but 25 connections triggers immediate defense. Evicting old events (`popleft()`) ensures memory usage remains $O(N)$ bounded.

#### 2. Installing Hardware DROP Rule & Purging Old Flows (`controller/firewall.py`)
```python
def block(self, ip):
    # 1. PURGE existing active flows for this IP (Crucial in OpenFlow 1.0!)
    msg_del = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    msg_del.match.nw_src = IPAddr(ip)
    self.connection.send(msg_del)

    # 2. INSTALL high-priority wildcard DROP rule
    msg_add = of.ofp_flow_mod(command=of.OFPFC_ADD)
    msg_add.priority = 60000
    msg_add.match.dl_type = 0x800 # IPv4
    msg_add.match.nw_src = IPAddr(ip)
    msg_add.actions = [] # Empty actions list = DROP
    
    # Calculate exponential penalty: 20s, 40s, 80s, 160s
    offence_num = self.offences[ip] + 1
    msg_add.hard_timeout = min(160, 20 * (2 ** (offence_num - 1)))
    msg_add.flags = of.OFPFF_SEND_FLOW_REM
    self.connection.send(msg_add)

    # 3. BARRIER REQUEST to verify rule is committed
    self.connection.send(of.ofp_barrier_request())
```
* **Why it matters:** In OpenFlow 1.0, exact-match flows override wildcard flows regardless of priority. If we didn't call `OFPFC_DELETE`, an existing connection from the attacker would keep sending packets unimpeded!

---

## 4. Person 3: Mininet Topology, Attack Simulation & Benchmarking

### Primary Code Responsibilities:
* `topology/topo.py`: Mininet custom topology (`FirewallTopo`), link bandwidth configuration (`TCLink`).
* `traffic/attacker.py`: Multi-threaded TCP SYN connection flooder and TCP port scanner.
* `experiments/run_experiments.py` & `plot_results.py`: Comparative performance evaluation suite.

### Key Code Concepts & Critical Snippets

#### 1. Bottleneck Link & Secure Fail-Mode (`topology/topo.py`)
```python
class FirewallTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow10', failMode='secure')
        srv = self.addHost('srv', ip='10.0.0.100/24')
        
        # Constrain server link to 10 Mbit/s (bottleneck link)
        self.addLink(s1, srv, bw=10, cls=TCLink)
```
* **Why it matters:**
  - `bw=10` creates an artificial bottleneck. During a flood on a static firewall, attack packets fill the 10 Mbit/s queue, causing legitimate packets from `h1`–`h3` to be dropped.
  - `failMode='secure'` ensures that if the POX controller dies, the switch does **not** fall back to being a normal hub/switch (fail-closed security).

#### 2. Performance Metrics Equations (`experiments/plot_results.py`)
* **Success Rate (%):**
  $$\text{Success \%} = \frac{N_{\text{successful}}}{N_{\text{total}}} \times 100$$
* **Total Blocking Reaction Time ($T_{\text{response}}$):**
  $$T_{\text{response}} = T_{\text{detection}} + T_{\text{install}}$$
  - $T_{\text{detection}}$: Time elapsed between the 1st packet of the anomaly evidence and the 25th packet triggering the verdict.
  - $T_{\text{install}}$: Time between sending `ofp_flow_mod` and receiving `OFPT_BARRIER_REPLY`.

---

## 5. Top 25 Viva Questions with Expert Model Answers

### General & Architecture
1. **What is the fundamental difference between SDN and traditional networking?**  
   *Answer:* In traditional networking, the control plane (routing/firewall logic) and data plane (forwarding hardware) are tightly coupled inside each physical box. In SDN, the control plane is centralized in software (POX controller), while the data plane consists of simple, programmable switches (Open vSwitch) configured via standard OpenFlow protocols.
2. **Why is a static firewall insufficient to stop a TCP connection flood?**  
   *Answer:* Static firewalls filter by IP and port headers. Since the server's public application port (8080) must be open to everyone, an attacker flooding thousands of legitimate-looking SYN packets matches the static `ALLOW` rule. The packets pass through and exhaust server thread and buffer resources.
3. **What is the difference between `PacketIn`, `FlowMod`, and `PacketOut`?**  
   *Answer:* `PacketIn` is an asynchronous message sent from switch to controller when a packet misses all flow entries. `FlowMod` is sent from controller to switch to install, modify, or delete a forwarding/drop rule in the flow table. `PacketOut` tells the switch to immediately send a specific packet out of one or more physical ports without necessarily installing a flow rule.

### Sockets & Application (Person 1)
4. **Why is TCP chosen over UDP for this application?**  
   *Answer:* TCP provides connection-oriented, reliable, ordered delivery with built-in flow control and congestion avoidance. Our client-server commands (`PING`, `DATA`, `STATS`) require reliable delivery, and TCP connection establishment (SYN $\to$ SYN-ACK $\to$ ACK) provides distinct connection events for attack detection.
5. **How does the server handle multiple clients simultaneously?**  
   *Answer:* The main thread runs an infinite `accept()` loop. For each newly accepted socket, it creates a new worker thread (`threading.Thread(target=self.handle_client)`), passing the client socket descriptor.
6. **What prevents server exhaustion under a thread-bombing attack?**  
   *Answer:* A `threading.BoundedSemaphore(50)`. When 50 client threads are active, any 51st client connection immediately fails to acquire the semaphore, receives `ERR BUSY\n`, and is cleanly closed, protecting the server OS from thread pool exhaustion.
7. **What is socket framing and why is `readline()` used?**  
   *Answer:* TCP is a stream of bytes without record boundaries. If a client sends `"PING\n"`, it could arrive in two separate TCP segments (`"PI"` and `"NG\n"`). `conn.makefile("rb").readline()` buffers the byte stream until a newline byte is received, ensuring one complete application command is processed at a time.
8. **How does the Centralized Logger ensure zero log loss if the logger server crashes?**  
   *Answer:* In `controller/firewall.py`, the `EventSender` uses a non-blocking in-memory `Queue`. If the TCP socket to port 9999 disconnects, the background worker thread buffers unsent events and retries connecting every 2 seconds. Once reconnected, it flushes all queued events.

### SDN Controller & Dynamic Defense (Person 2)
9. **Explain how the 5-second sliding window works.**  
   *Answer:* The controller maintains a `deque` of `(timestamp, dst_ip, dst_port)` per source IP. Whenever a new TCP SYN arrives, it appends the current timestamp and pops all events older than $(now - 5.0\text{ s})$. If the remaining events exceed 25, it flags `CONN_FLOOD`.
10. **Why do we only feed TCP SYN packets to the anomaly detector?**  
    *Answer:* A TCP SYN packet (with `SYN=1, ACK=0`) marks the initiation of a *new* connection. Data packets (with `ACK=1`) belong to an established connection. Counting all packets would misidentify a legitimate large file transfer as a flood; counting only SYNs isolates connection establishment frequency.
11. **Why must you execute `OFPFC_DELETE` before installing a `priority=60000` DROP rule in OpenFlow 1.0?**  
    *Answer:* OpenFlow 1.0 specification dictates that exact-match flow rules (matching all 12 tuple fields) always take precedence over wildcard rules, regardless of priority values! If we do not explicitly delete the attacker's existing exact-match forwarding flows, active connection sockets would continue communicating.
12. **What is an OpenFlow Barrier Request and why is it used?**  
    *Answer:* OpenFlow messages are asynchronous; the switch does not reply to a `flow_mod`. A `barrier_request` forces the switch to finish processing all preceding flow modifications before returning a `barrier_reply`. This allows us to accurately measure the exact millisecond installation delay.
13. **How does automatic recovery work without controller intervention?**  
    *Answer:* The controller configures the drop rule with `hard_timeout=20`. The switch hardware timer expires after 20 seconds and purges the rule automatically. This guarantees recovery even if the controller freezes or crashes during the block period.
14. **What is exponential penalty escalation?**  
    *Answer:* To prevent repeat offenders from repeatedly waiting out a 20-second block, the controller tracks historical offences in `self.offences[ip]`. Offence #1 = 20 s, Offence #2 = 40 s, Offence #3 = 80 s, Offence #4 = 160 s (capped).
15. **What is the difference between `idle_timeout` and `hard_timeout`?**  
    *Answer:* `idle_timeout` removes a flow entry if no packets match it for $X$ seconds. `hard_timeout` forcibly removes the flow entry after $X$ seconds, regardless of whether traffic is actively matching it.

### Mininet, Attacks & Evaluation (Person 3)
16. **Why is the link bandwidth between switch `s1` and server `srv` limited to 10 Mbit/s?**  
    *Answer:* In virtual network emulation, CPU speed can artificially allow high bandwidth. Limiting the link to 10 Mbit/s (`bw=10, cls=TCLink`) creates a realistic network bottleneck to empirically demonstrate how an unmitigated attack starves legitimate traffic.
17. **What is `failMode='secure'` in Open vSwitch?**  
    *Answer:* By default (`failMode='standalone'`), if an OVS switch loses connection to its SDN controller, it falls back to acting like a legacy learning switch. In `failMode='secure'`, the switch refuses to forward any new flows without controller approval, adhering to a "fail-closed" security posture.
18. **How does the port scanner attack operate?**  
    *Answer:* `traffic/attacker.py` iterates across destination ports (e.g., 20–1024), attempting rapid TCP socket connections. If a port is open, the server responds with SYN-ACK; if closed, it responds with RST; if dropped by the firewall, the socket times out.
19. **Why is a port scan blocked faster than a connection flood?**  
    *Answer:* The port scan detection threshold is only **8 distinct target ports**, whereas connection flood requires **25 connections**. An attacker hits 8 unique ports in fewer packets than 25 total connections.
20. **Explain why Figure 3 shows total response time decreasing as attack rate increases.**  
    *Answer:* At 10 conn/s, an attacker takes 2.4 seconds to generate the 25 connections needed to trigger the anomaly detector. At 200 conn/s, the attacker fires 25 connections in just 125 ms! Because rule installation is nearly instantaneous (~20–50 ms), faster attacks hit the evidence threshold sooner, triggering faster mitigation.
21. **What is the difference between Throughput and Goodput?**  
    *Answer:* Throughput measures total physical raw bits transmitted over the link (including headers, retransmissions, and attack packets). Goodput measures only the useful application-layer payload bytes delivered to legitimate clients. During a flood on a static firewall, throughput is high but goodput crashes to 0.37 Mbit/s.
22. **Why do we report the median of 3 runs instead of the average?**  
    *Answer:* Individual runs in virtual machine environments can suffer from transient CPU scheduling spikes, host OS background tasks, or memory paging hiccups. The median (middle value) is robust against statistical outliers, whereas the mean can be skewed by a single anomalous run.
23. **What is the difference between a False Positive and a False Negative in this system?**  
    *Answer:* A False Positive occurs when a legitimate high-volume client (e.g., downloading multiple assets in parallel) exceeds 25 conns/5s and is blocked. A False Negative occurs when a stealthy attacker spreads attacks below the threshold (e.g., 4 conns/5s) and avoids detection.
24. **How would you mitigate IP spoofing in this architecture?**  
    *Answer:* In OpenFlow 1.0, we can match on both `in_port` and `dl_src` (MAC address) alongside `nw_src`. If a packet arrives on a switch port that does not match the switch's learned MAC-to-port binding, it is dropped as spoofed traffic.
25. **What are the primary limitations of OpenFlow 1.0 used in this project?**  
    *Answer:* OpenFlow 1.0 supports only a single flow table (pipeline processing requires OpenFlow 1.3+ multi-tables), does not support group tables or meters for hardware rate-limiting, and requires exact-match rules to be manually purged before wildcard drop rules take effect.

---

## 6. 5-Minute Practical Code Experiments (Self-Test)

Run these rapid experiments in your Mininet terminal to see the code mechanics live:

1. **Test Concurrency Limits:**  
   Run `h2 python3 app/client.py --count 60 --parallel 55`.  
   *Observation:* The first 50 succeed; the remaining 5 receive `ERR BUSY` due to `BoundedSemaphore(50)`.
2. **Observe Exact-Match Flow Installation:**  
   In Mininet, run `h2 python3 app/client.py --count 1`.  
   Then run `sh ovs-ofctl dump-flows s1`.  
   *Observation:* Notice the exact-match flow with `idle_timeout=10, hard_timeout=30`.
3. **Trigger Policy Violation Block:**  
   Run `h2 python3 app/client.py --port 2222 --count 6 --rate 2 --timeout 1`.  
   *Observation:* After 5 denied attempts, host `h2` is completely blocked under `POLICY_VIOLATION`. Even its allowed access to port 8080 is blocked!
4. **Inspect Barrier Synchronization:**  
   Check `results/blocks.csv`. Notice that `install_ms` is consistently measured between 10 ms and 60 ms thanks to `ofp_barrier_request`.
