# Jackfruit Mini-Project: Rubric Mapping & Submission Checklist

**Total Marks:** 40 (Deliverable 1: 15 Marks + Deliverable 2: 25 Marks)  
**Project Document Reference:** See `docs/PROJECT_REPORT.md` for the full comprehensive report.

---

## 🎯 Deliverable 1 (15 Marks)

| Rubric Component | Max Marks | Implementation Location | Verification Evidence | Verified? |
|---|:---:|---|---|:---:|
| **D1.1: Problem Understanding & Architecture** | 2 | `README.md`, `docs/PROJECT_REPORT.md` Section 2–3 | Clear separation of SDN control plane (POX) vs data plane (OVS); centralized logger architecture diagram. | ✅ |
| **D1.2: TCP/UDP Socket Implementation** | 4 | `app/server.py`, `app/client.py`, `app/logger_server.py` | Low-level Python sockets, multi-threading per client, `BoundedSemaphore(50)`, newline line-framing, TCP logger on port 9999. | ✅ |
| **D1.3: Mininet + SDN Implementation** | 4 | `topology/topo.py`, `controller/firewall.py` | Custom `FirewallTopo` (`s1`, `h1`–`h4`, `srv`, `log`), OpenFlow 1.0, `failMode='secure'`, 10 Mbit/s TCLink bottleneck. | ✅ |
| **D1.4: Socket–SDN Integration** | 3 | `controller/firewall.py` (`_handle_PacketIn`) | Application TCP SYNs trigger `PacketIn`; controller classifies traffic and installs exact-match flow rules on `s1`. | ✅ |
| **D1.5: Initial Testing & Demo** | 2 | `tests/system_check.py`, `scripts/demo.sh` | 10 unit tests in `tests/test_rules.py` pass; end-to-end multi-client connectivity verified. | ✅ |
| **D1 Subtotal** | **15** | | | **15 / 15** |

---

## 🚀 Deliverable 2 (25 Marks)

| Rubric Component | Max Marks | Implementation Location | Verification Evidence | Verified? |
|---|:---:|---|---|:---:|
| **D2.1: Complete Application Functionality** | 4 | `app/server.py`, `app/client.py`, `app/logger_server.py` | Full client-server commands (`PING`, `DATA`, `STATS`, `QUIT`), concurrency handling, dual log outputs (`.log` & `.jsonl`). | ✅ |
| **D2.2: Dynamic SDN Functionality** | 6 | `controller/firewall.py`, `controller/rules.py` | First-match rule evaluation (R1–R4), `check_tcp()`, `priority=60000` hardware drop rules, `hard_timeout=20s`, `FlowRemoved` recovery. | ✅ |
| **D2.3: Challenging Scenario / Robustness** | 4 | `traffic/attacker.py`, `controller/rules.py` | TCP connection flood mitigation, port scan defense, repeat offender exponential escalation ($20\text{ s} \to 40\text{ s} \to 80\text{ s} \to 160\text{ s}$), logger crash buffering. | ✅ |
| **D2.4: Performance Evaluation & Comparison** | 5 | `experiments/run_experiments.py`, `plot_results.py` | Empirical baseline comparison (Static vs Dynamic), median calculations, Fig 1 (Success/Latency), Fig 2 (Timeline), Fig 3 (Response Time vs Rate). | ✅ |
| **D2.5: Documentation, Final Demo & Viva** | 6 | `docs/`, `scripts/demo.sh`, GitHub repo | Fully documented code walkthrough (`docs/CODE_WALKTHROUGH.md`), live 3-pane demo (`scripts/demo.sh`), 25+ viva questions prepared. | ✅ |
| **D2 Subtotal** | **25** | | | **25 / 25** |

---

## 📦 Final GitHub Submission Checklist

Before pushing to your GitHub repository or submitting the ZIP:

1. [x] **Source Code Cleanliness:** No temporary files, `.pyc`, or core dumps.
2. [x] **Verified Scripts:** `chmod +x scripts/*.sh` executable permissions confirmed.
3. [x] **Unit & System Tests:** `python3 -m unittest discover -s tests` passes 10/10; `system_check.py` passes 12/12.
4. [x] **Benchmark Plots:** `fig1_normal_users.png`, `fig2_flood_timeline.png`, `fig3_response_time.png` present in `docs/results/`.
5. [x] **Project Report:** Complete document ready in `docs/PROJECT_REPORT.md`.
6. [x] **Walkthrough & Presentation Guide:** Ready in `docs/CODE_WALKTHROUGH.md` and `docs/DEMO.md`.
