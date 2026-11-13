# System check: 12 / 12 passed (Sat Oct 31 10:46:20 2026)

| Test | Result | Details |
|---|---|---|
| Mininet connectivity | PASS | pingall loss 0.0% |
| Controller -> logger over TCP | PASS | 1 SWITCH_CONNECTED events in the central log |
| 3 clients on 3 hosts at the same time | PASS | h1:10/10 h2:10/10 h3:10/10 |
| Bulk transfer DATA 500 kB | PASS | 7.61 Mbit/s |
| Classification by source: admin port 2222 | PASS | h1 allowed (R1): True, h2 denied (R2): True |
| DENY events reach the logger | PASS | 1 DENY events for h2 |
| Flood detected and blocked | PASS | response 248.2 ms (detection 236.9 + install 11.3); attacker: {'ok': 24, 'timeout': 176} |
| Attacker cut off, others unaffected | PASS | h4 ping blocked: True, h2 5/5 ok |
| Automatic recovery after 8s | PASS | UNBLOCK after 8.5 s, 215 packets dropped; h4 3/3 ok |
| Repeat offender is blocked longer | PASS | block durations for h4: [8, 16] s |
| Repeated denied access -> whole host blocked | PASS | POLICY_VIOLATION after 5 denied attempts; h2 -> port 8080 now: blocked |
| Port scan detected and blocked | PASS | response 36.8 ms; scanner found open ports none, got 7 answers out of 202 |
