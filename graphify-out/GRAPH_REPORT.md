# Graph Report - SDN-Firewall-FINAL  (2026-11-14)

## Corpus Check
- Corpus is ~18,252 words - fits in a single context window. You may not need a graph.

## Summary
- 212 nodes · 418 edges · 16 communities (7 shown, 9 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 27 edges (avg confidence: 0.86)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Automated Benchmarks & System Checks
- Event Streaming & Controller Core
- TCP Client & Latency Measurement
- POX Firewall & Policy Engine
- Guided Mininet Demonstration
- Performance Plotting & Visualizations
- Multi-Threaded Server & Concurrency
- End-to-End Automation Pipeline
- Environment Cleanup Utility
- Interactive Tmux Demo Launcher
- Package Setup & Initialization
- Controller Startup Script
- Viva Preparation & Defense
- Project Rubric & Guidelines
- Live Empirical Results

## God Nodes (most connected - your core abstractions)
1. `Firewall` - 17 edges
2. `run_demo()` - 13 edges
3. `Lab` - 12 edges
4. `Detector` - 11 edges
5. `give_back()` - 10 edges
6. `comparison_run()` - 9 edges
7. `main()` - 9 edges
8. `DetectorTests` - 9 edges
9. `Server` - 8 edges
10. `Policy` - 8 edges

## Surprising Connections (you probably didn't know these)
- `Server Concurrency Control (BoundedSemaphore)` --rationale_for--> `Server`  [EXTRACTED]
  README.md → app/server.py
- `Dynamic SDN Firewall Architecture` --references--> `Firewall`  [EXTRACTED]
  README.md → controller/firewall.py
- `5-Second Sliding Window Anomaly Detection` --references--> `Detector`  [EXTRACTED]
  docs/CODE_WALKTHROUGH.md → controller/rules.py
- `Figure 1: Normal Users Success Rate & Latency` --conceptually_related_to--> `plots()`  [EXTRACTED]
  docs/results/fig1_normal_users.png → experiments/plot_results.py
- `Figure 2: Real-time Latency Timeline During Flood` --conceptually_related_to--> `plots()`  [EXTRACTED]
  docs/results/fig2_flood_timeline.png → experiments/plot_results.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Empirical Benchmark & Evaluation Pipeline** — docs_results_fig1_normal_users_chart, docs_results_fig2_flood_timeline_chart, docs_results_fig3_response_time_chart, docs_project_report_empirical_findings [EXTRACTED 1.00]

## Communities (16 total, 9 thin omitted)

### Community 0 - "Automated Benchmarks & System Checks"
Cohesion: 0.11
Nodes (19): 12/12 End-to-End System Checks Validation, comparison_run(), main(), rate_sweep(), read_blocks(), read_json(), attack(), check() (+11 more)

### Community 1 - "Event Streaming & Controller Core"
Cohesion: 0.07
Nodes (7): EventSender, Firewall, Detector, 5-Second Sliding Window Anomaly Detection, Dynamic SDN Firewall Architecture, DetectorTests, FirewallTopo

### Community 2 - "TCP Client & Latency Measurement"
Cohesion: 0.12
Nodes (13): main(), client(), ms_since(), one_request(), run(), summary(), main(), SecurityLogger (+5 more)

### Community 3 - "POX Firewall & Policy Engine"
Cohesion: 0.09
Nodes (5): launch(), load_config(), Policy, Rule, PolicyTests

### Community 4 - "Guided Mininet Demonstration"
Cohesion: 0.22
Nodes (9): 10-Minute Guided Demo Script, ask(), open_charts(), run_demo(), say(), show_results(), stop_start(), wait_switch() (+1 more)

### Community 5 - "Performance Plotting & Visualizations"
Cohesion: 0.20
Nodes (11): Empirical Benchmark Results (Static vs Dynamic), Figure 1: Normal Users Success Rate & Latency, Figure 2: Real-time Latency Timeline During Flood, Figure 3: Reaction Time vs Attack Velocity, average_runs(), average_sweep(), fmt(), main() (+3 more)

### Community 7 - "End-to-End Automation Pipeline"
Cohesion: 0.70
Nodes (4): awake(), fail(), run_everything.sh script, step()

## Knowledge Gaps
- **9 isolated node(s):** `Jackfruit Evaluation Rubric (40 Marks)`, `Empirical Benchmark Results (Static vs Dynamic)`, `5-Second Sliding Window Anomaly Detection`, `Master Viva Defense Guide`, `10-Minute Guided Demo Script` (+4 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 86 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **9 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Firewall` connect `Event Streaming & Controller Core` to `POX Firewall & Policy Engine`?**
  _High betweenness centrality (0.128) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `Firewall` (e.g. with `Detector` and `Policy`) actually correct?**
  _`Firewall` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Jackfruit Evaluation Rubric (40 Marks)`, `Empirical Benchmark Results (Static vs Dynamic)`, `5-Second Sliding Window Anomaly Detection` to the rest of the system?**
  _9 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Automated Benchmarks & System Checks` be split into smaller, more focused modules?**
  _Cohesion score 0.10606060606060606 - nodes in this community are weakly interconnected._
- **Why does `Detector` connect `Event Streaming & Controller Core` to `POX Firewall & Policy Engine`?**
  _High betweenness centrality (0.092) - this node is a cross-community bridge._
- **Should `Event Streaming & Controller Core` be split into smaller, more focused modules?**
  _Cohesion score 0.0664451827242525 - nodes in this community are weakly interconnected._
- **Why does `DetectorTests` connect `Event Streaming & Controller Core` to `POX Firewall & Policy Engine`?**
  _High betweenness centrality (0.054) - this node is a cross-community bridge._