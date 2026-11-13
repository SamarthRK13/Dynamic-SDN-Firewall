# Results (1 run each)

## Normal users (h1-h3) while the attack runs

| Condition | Mode | Success % | Avg latency ms | Goodput Mbit/s | Attack successes | Blocked after ms | Controller packet-ins |
|---|---|---|---|---|---|---|---|
| No attack | Static firewall (baseline) | 100.0 | 54.4 | 1.92 | - | - | 1672 |
| No attack | Dynamic firewall | 100.0 | 35.1 | 1.92 | - | - | 1757 |
| Connection flood | Static firewall (baseline) | 87.5 | 1169.0 | 0.37 | 2198 | - | 5149 |
| Connection flood | Dynamic firewall | 100.0 | 42.0 | 1.91 | 2 | 266.4 | 1831 |
| Port scan | Static firewall (baseline) | 100.0 | 32.2 | 1.93 | 1 (open ports found: 8080) | - | 3863 |
| Port scan | Dynamic firewall | 100.0 | 44.0 | 1.93 | 0 (open ports found: none) | 71.4 | 1601 |

## Blocking response time vs flood rate (dynamic)

| Flood rate (conn/s) | Detection ms | Rule install ms | Total response ms |
|---|---|---|---|
| 10 | 2389.5 | 48.0 | 2437.5 |
| 25 | 943.7 | 61.1 | 1004.9 |
| 50 | 470.3 | 18.0 | 488.3 |
| 100 | 221.6 | 45.2 | 266.8 |
| 200 | 215.7 | 76.0 | 291.7 |
