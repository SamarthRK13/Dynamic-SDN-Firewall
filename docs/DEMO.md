# Live Demo Presentation Script & Examiner Q&A Guide

**Duration:** ~10 minutes  
**Format:** 3-Pane Integrated Tmux View (`bash scripts/demo.sh`) or 3 Independent Terminals  
**Team Roster:**  
* **Speaker 1 (Suharshitha):** Sockets, Architecture, Concurrency & Centralized Logger (`app/`)
* **Speaker 2 (Shrey Shetty):** SDN Controller, Rules R1–R4, Sliding-Window Detector & Hardware Drop (`controller/`)
* **Speaker 3 (Samarth RK):** Mininet Topology, TCLink Bottleneck, Attack Simulation & Benchmark Graphs (`topology/`, `traffic/`, `experiments/`)

---

## 🖥️ Screen Layout During the Demo

```
+------------------------------------+------------------------------------+
| TERMINAL 1 (Top-Left)              | TERMINAL 2 (Top-Right)             |
| Centralized Security Event Logger  | POX OpenFlow SDN Controller        |
| listening on TCP port 9999         | running Dynamic Firewall Component |
+------------------------------------+------------------------------------+
| TERMINAL 3 (Bottom)                                                     |
| Mininet Interactive Topology & Guided CLI (s1, h1-h4, srv, log)         |
+-------------------------------------------------------------------------+
```

---

## 🎬 Step-by-Step Presentation Script

### Phase 1: Startup & System Architecture (Minutes 0:00 – 2:00)
* **Action:** Run `bash scripts/demo.sh` (or show the three running panes).
* **Who Speaks:** **Suharshitha** & **Samarth RK**
* **What to Show on Screen:**
  - Terminal 1 (Top-Left): Logger displays `LOGGER_SERVER_ONLINE: listening on 127.0.0.1:9999`.
  - Terminal 2 (Top-Right): Controller displays `POX ichthyosaur connected to switch s1 (dpid=1)`.
  - Terminal 3 (Bottom): Press **Enter** for Step (a). Mininet executes `net` and `pingall` with **0.0% dropped**.
* **What to Say to the Examiner:**
  > *"Good morning Professor. Our project implements a Dynamic SDN Firewall combined with a Centralized Security Event Logger.*  
  > *Here in Terminal 3, we have instantiated an Open vSwitch topology `s1` connecting four hosts `h1` through `h4`, our application server `srv`, and a dedicated security logger `log`. The server link is deliberately rate-limited to 10 Mbit/s using Linux `TCLink` to simulate a realistic network bottleneck.*  
  > *In Terminal 2, our POX SDN Controller acts as the intelligent control plane over OpenFlow 1.0. In Terminal 1, an independent multi-threaded TCP logging server listens on port 9999 to maintain an auditable stream of all network security events."*

---

### Phase 2: TCP Sockets & Multi-Client Concurrency (Minutes 2:00 – 3:30)
* **Action:** Mininet runs parallel requests: `h2 python3 app/client.py --count 8 --parallel 4 --rate 1`.
* **Who Speaks:** **Suharshitha**
* **What to Show on Screen:**
  - 4 parallel client worker threads receiving `PONG` and application data payloads at line rate (~9.8 Mbit/s).
  - Terminal 1 shows active TCP connection metadata logged.
* **What to Say to the Examiner:**
  > *"In this step, we demonstrate our low-level TCP socket implementation. Client `h2` spawns 4 concurrent threads making simultaneous requests to `srv:8080`.*  
  > *On the server side (`app/server.py`), each connection is handed to an isolated worker thread. To prevent thread starvation and Denial-of-Service attacks, we enforce concurrency control via a `BoundedSemaphore(50)`. If more than 50 clients connect simultaneously, the server gracefully returns `ERR BUSY`.*  
  > *Notice that because this is a new TCP connection, the very first packet (TCP SYN) triggers an OpenFlow `PacketIn` to our controller, which installs an exact-match forwarding rule for that flow."*

---

### Phase 3: Traffic Classification by IP, Port & Protocol (Minutes 3:30 – 5:00)
* **Action:** Press **Enter** for Step (b). Mininet runs:
  ```bash
  h1 python3 app/client.py --port 2222 --request STATS --count 1
  h2 python3 app/client.py --port 2222 --request STATS --count 1
  h2 nc -zv -w 2 10.0.0.3 23
  ```
* **Who Speaks:** **Shrey Shetty**
* **What to Show on Screen:**
  - `h1` $\to$ port 2222: **ALLOWED** (Admin Rule R1).
  - `h2` $\to$ port 2222: **DENIED** with connection timeout (Rule R2).
  - Port 23 (Telnet): **DROPPED** (Rule R4).
  - Terminal 2 displays: `DENY 10.0.0.2 -> 10.0.0.100:2222 (ADMIN, rule R2)`.
  - Terminal 1 logs: `{"event": "DENY", "src": "10.0.0.2", "rule": "R2"}`.
* **What to Say to the Examiner:**
  > *"Here we demonstrate our policy classification engine (`controller/rules.py`). Both `h1` and `h2` attempt to access the sensitive management port 2222.*  
  > *Rule R1 allows `10.0.0.1`, so `h1` succeeds. Rule R2 blocks all other sources, so `h2` is immediately denied. In addition, Rule R4 blocks legacy unencrypted Telnet on port 23 network-wide.*  
  > *Notice that the controller installs an exact-match flow with an empty actions list on switch `s1` (`actions=drop`), and streams an auditable `DENY` event to the centralized logger."*

---

### Phase 4: Volumetric Attack Detection & Line-Rate Mitigation (Minutes 5:00 – 7:00)
* **Action:** Press **Enter** for Step (c). Host `h4` runs `traffic/attacker.py flood`.
* **Who Speaks:** **Shrey Shetty** & **Samarth RK**
* **What to Show on Screen:**
  - Attacker `h4` fires rapid TCP SYNs. After ~24 attempts, all remaining attempts output `TIMEOUT`.
  - Terminal 2 displays: `BLOCK 10.0.0.4 CONN_FLOOD, offence #1, 20s, response 266.4 ms`.
  - Mininet runs `sh ovs-ofctl dump-flows s1 | grep priority=60000`:
    `priority=60000, dl_type=0x800, nw_src=10.0.0.4 actions=drop`.
  - `h4 ping -c 2 10.0.0.100` shows **100% packet loss**.
  - `h2 python3 app/client.py --count 3` shows **100% OK** for legitimate client `h2`!
* **What to Say to the Examiner:**
  > *"This is the core dynamic capability of our project. Host `h4` launches a high-rate TCP connection flood to saturate the server.*  
  > *Our POX controller maintains a 5-second sliding window per source IP. As soon as `h4` exceeds the threshold of 25 connections, the detector triggers a `CONN_FLOOD` verdict in just 266 milliseconds.*  
  > *To enforce the block, the controller first purges existing flows using `OFPFC_DELETE`, then installs a wildcard hardware `DROP` rule with `priority=60000` directly into switch `s1`.*  
  > *Notice the result: Attacker `h4` is completely isolated (100% ping loss), while legitimate host `h2` continues transacting with zero packet loss!"*

---

### Phase 5: Autonomous Recovery & Repeat Offender Escalation (Minutes 7:00 – 8:30)
* **Action:** Press **Enter** for Step (d) and Step (e).
* **Who Speaks:** **Shrey Shetty**
* **What to Show on Screen:**
  - After 20 seconds, the block rule automatically disappears from switch `s1`.
  - Terminal 2 displays: `RECOVERY 10.0.0.4: block expired, 215 packets dropped`.
  - Attacker `h4` floods again. Terminal 2 logs: `offence #2, blocked for 40 s` (`hard_timeout=40`).
* **What to Say to the Examiner:**
  > *"Notice that recovery is completely autonomous. The controller set `hard_timeout=20` on the switch. Even if the controller had crashed, switch `s1` removes the rule by itself when the hardware timer expires.*  
  > *When `h4` launches a second attack, our controller recognizes a repeat offender and doubles the penalty to 40 seconds. Further offences escalate exponentially up to 160 seconds."*

---

### Phase 6: Performance Evaluation & Empirical Charts (Minutes 8:30 – 10:00)
* **Action:** Press **Enter** for Step (k). The 3 benchmark charts open on screen.
* **Who Speaks:** **Samarth RK**
* **What to Show on Screen:**
  - Display `fig1_normal_users.png`, `fig2_flood_timeline.png`, and `fig3_response_time.png`.
* **What to Say to the Examiner:**
  > *"Finally, we evaluated our dynamic firewall against a traditional static firewall across multiple attack vectors:*  
  > *1. **Figure 1:** In a static firewall under attack, legitimate user success crashes to 87.5% and latency explodes by over 2,000% to 1,169 ms. Under our dynamic firewall, legitimate users retain 100% success and 42 ms latency.*  
  > *2. **Figure 2:** This timeline shows that the dynamic firewall shields users within 266 ms, returning latency to normal baseline while the static firewall stays saturated for the entire attack.*  
  > *3. **Figure 3:** Shows our blocking response time as a function of attack velocity. Because detection relies on gathering 25 anomaly samples, higher attack rates trigger faster detection, scaling from 2.4 seconds at 10 conn/s down to 266 milliseconds at 100 conn/s."*

---

## 💡 Quick Tips for Viva Examiners
1. If the examiner asks: *"Can an attacker bypass your firewall by changing ports?"*  
   **Answer:** *"No, because `nw_src=10.0.0.4` is wildcarded for all destination ports and protocols. Once blocked, all IPv4 traffic from that host is dropped at the switch ingress."*
2. If the examiner asks: *"What happens if the controller dies?"*  
   **Answer:** *"Because we set `failMode='secure'`, Open vSwitch fails closed. It will not forward unverified new flows, preventing security leaks."*
3. If the examiner asks: *"Where are the events stored?"*  
   **Answer:** *"The controller streams JSON events over TCP to port 9999. The logging server persists them to `logs/security_events.log` for humans and `logs/security_events.jsonl` for automated SIEM parsing."*
