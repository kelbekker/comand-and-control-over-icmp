# 

# ICMP-based Command and Control (C&C) - Educational Lab

> **Disclaimer:** This project is created **strictly for educational purposes** and to demonstrate network security concepts (ICMP tunneling) within an isolated laboratory environment. Do not use this tool on public networks or systems you do not own. Misuse of this software may be illegal and could be flagged as malicious activity.
> 

## 📋 Overview

This project demonstrates an ICMP-based command-and-control (C&C) communication channel between a "victim" host and an "attacker" host on a private network.

The main objective is to understand how standard network protocols can be abused for covert data exfiltration and command execution, as well as how to detect and analyze such traffic using network monitoring tools.

## 🏛 Architecture

```
[ Victim (Private Network) ]
       <--- ICMP (Request/Reply) --->
[ Attacker (Control Node) ]
```

- **Victim:** Runs on a host inside a private network, signals availability, executes received commands, and sends back results.
- **Attacker:** Listens for incoming ICMP traffic from the victim, issues base64-encoded commands, and handles file exfiltration.

## ✨ Features (Lab Only)

- **Remote Shell Execution:** Execute shell commands (`ls`, `dir`, `whoami`, etc.) on the victim host.
- **File Transfer:** Retrieve files from the victim host to the attacker machine over ICMP.
- **Data Encoding & Chunking:** Exfiltrate data in Base64-encoded chunks over ICMP Echo Request/Reply packets.

## 🛠 File Structure

| File | Description |
| --- | --- |
| `attacker.py` | ICMP-based listener; sends base64 commands and receives output/files. |
| `victim.py` | Client running on the private network; executes commands and transfers files. |
| `README.md` | Project documentation (this file). |

## ⚙️ Configuration

Before running in your isolated lab, update the network configuration variables inside both `attacker.py` and `victim.py`:

- `ICMP_ID`: Session ID (must match on both attacker and victim).
- `DESTINATION_IP`: Target IP address (Attacker IP in `victim.py`; Victim IP in `attacker.py`).
- `TTL`: Standard Time To Live for ICMP packets (default: `64`).
- `INTERFACE`: Network interface to listen on/send packets through (e.g., `eth0`, `enp8s0f1`).

## 🔄 Data Flow

1. **Beaconing:** Victim sends an `IMREADY` signal over ICMP Echo Request to the attacker.
2. **Identification:** Attacker receives `IMREADY` and identifies the victim's IP address.
3. **Command Delivery:** Attacker sends base64-encoded commands embedded in ICMP Echo Replies.
4. **Execution & Response:** Victim decodes and executes commands locally, returning the output via ICMP Echo Requests.
5. **File Transfer:** File exfiltration is handled in sequential Base64-encoded chunks over ICMP packets.

## 🚀 Running the Lab

Root privileges are required on both hosts because the scripts use raw sockets / packet sniffing on the network layer.

### 1. On the Victim machine:

```
sudo python3 victim.py
```

### 2. On the Attacker machine:

```
sudo python3 attacker.py
```

> **Educational Tip:** Run **Wireshark** or `tcpdump` on your lab interface during execution to observe how the payload is encapsulated within ICMP packets and analyze detection signatures.
>
