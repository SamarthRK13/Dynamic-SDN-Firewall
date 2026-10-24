# Dynamic SDN Firewall with Security Event Logger

## Project Overview

This project implements a dynamic firewall using Software-Defined Networking (SDN). It monitors TCP traffic, detects suspicious traffic patterns, dynamically applies firewall rules, and records security events using a centralized logging server.

## Objectives

- Implement TCP client-server communication.
- Create a virtual network using Mininet.
- Integrate an SDN controller using Ryu.
- Inspect traffic based on source IP, destination IP, protocol, and port.
- Dynamically block suspicious traffic using OpenFlow rules.
- Record security events in a centralized logger.
- Implement automatic recovery after temporary blocking.
- Measure firewall response time, network latency, and throughput.

## Technologies Used

- Python
- Ryu SDN Controller
- Mininet
- Open vSwitch
- OpenFlow 1.3
- TCP sockets
- Ubuntu Linux

## Project Structure

```text
dynamic-sdn-firewall/
├── client/
│   ├── tcp_client.py
│   └── attack.py
├── controller/
│   └── firewall.py
├── logger/
│   └── logger_server.py
├── network/
│   └── topology.py
├── server/
│   └── tcp_server.py
├── README.md
├── requirements.txt
└── .gitignore
```

## Modules

### 1. TCP Client and Server
Implements TCP communication between network hosts.

### 2. Mininet Network
Creates a virtual network containing hosts and an SDN switch.

### 3. Dynamic Firewall
Uses the Ryu controller to monitor traffic and install OpenFlow blocking rules when configured detection thresholds are exceeded.

### 4. Security Event Logger
Records security events, including source IP, destination IP, port, action, and timestamp.

### 5. Automatic Recovery
Removes temporary blocking rules after the configured blocking period.

### 6. Performance Evaluation
Measures blocking response time, latency, throughput, and packet loss.

## Installation

Install the required system packages on Ubuntu:

```bash
sudo apt update
sudo apt install mininet openvswitch-switch python3-venv git -y
```

Create a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the Python dependencies listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Team Contributions

Team members should work on their assigned modules and commit their changes with descriptive messages.

Recommended approach:
- Use separate branches for individual modules.
- Submit pull requests for review.
- Test changes before merging into the main branch.

## Testing and Evaluation

The project will be evaluated using an isolated Mininet test network.

Evaluation metrics:
- Detection and blocking response time
- Network latency
- TCP throughput
- Packet loss
- Correctness of security event logging
- Successful recovery after temporary blocking

## Project Status

Under development.

## Safety

Run traffic-generation tests only in the isolated, authorized project environment.
