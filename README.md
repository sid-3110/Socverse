<div align="center">

# 🛡️ SOCVerse

### Interactive Enterprise Network & SOC Attack Simulation Platform

Visualize Enterprise Networks • Simulate Cyber Attacks • Investigate Security Alerts • Learn SOC Operations

---

![Version](https://img.shields.io/badge/Version-v1.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Framework](https://img.shields.io/badge/Framework-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-success?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Maintained](https://img.shields.io/badge/Maintained-Yes-green?style=for-the-badge)

</div>

---

# 📖 Overview

SOCVerse is an interactive cybersecurity learning platform that recreates a modern enterprise infrastructure together with a Security Operations Center (SOC).

Instead of learning networking, attack simulation, SIEM investigations, and enterprise architecture separately, SOCVerse combines everything into one interactive platform.

Users can:

- 🌐 Explore Enterprise Network Architecture
- 📦 Visualize Packet Traversal
- 🎯 Launch Attack Simulations
- 🛡️ Investigate SOC Alerts
- 📊 Analyze Security Events
- 📚 Learn Enterprise Networking
- 🔍 Understand Detection Engineering
- ⚔️ Practice Blue Team Operations

Designed for:

- SOC Analysts
- Blue Team Engineers
- Cybersecurity Students
- Educators
- Security Researchers
- Enterprise Security Teams

---

# 🚀 Key Features

## 🌐 Enterprise Network Visualization

- Interactive Enterprise Network Topology
- Animated Packet Flow
- Realistic Routing
- Clickable Devices
- Zoom & Pan Controls
- Professional Enterprise Layout

---

## 📦 Packet Flow Simulation

Visualize traffic moving through:

- ISP
- Edge Router
- Border Router
- NGFW
- DMZ
- WAF
- Reverse Proxy
- Load Balancer
- Web Servers
- Application Servers
- Database Servers
- Core Switch
- Distribution Switch
- Access Switch
- VLANs
- Domain Controller
- Cloud Infrastructure

---

# 🖥️ Enterprise Infrastructure

## Networking

- Edge Router
- Border Router
- Core Router
- Layer 2 Switch
- Layer 3 Switch
- Distribution Switch
- Core Switch
- Access Switch

## Security

- Next Generation Firewall
- IDS
- IPS
- WAF
- VPN Gateway
- SIEM
- SOAR
- EDR/XDR

## Infrastructure

- Active Directory
- DNS
- DHCP
- Mail Server
- File Server
- Database Server
- Backup Server
- Web Server
- Application Server

## Endpoints

- HR Department
- Finance Department
- IT Department
- SOC Department
- Windows Systems
- Linux Servers

## Cloud

- AWS
- Microsoft Azure
- Google Cloud Platform

---

# 🎯 Attack Simulations

Current simulations include:

- Port Scanning
- SQL Injection
- Cross Site Scripting (XSS)
- SSH Brute Force
- RDP Brute Force
- DNS Tunneling
- ARP Spoofing
- MITM
- DoS
- DDoS
- Malware Delivery
- Ransomware
- Reverse Shell
- PowerShell Attack
- Credential Dumping
- Pass-the-Hash
- Kerberoasting
- Golden Ticket
- Silver Ticket
- SMB Lateral Movement
- Data Exfiltration
- Beaconing

Each simulation provides:

- Attack Animation
- Packet Visualization
- Generated Logs
- SOC Alerts
- MITRE ATT&CK Mapping
- Timeline Replay

---

# 📊 SOC Dashboard

The SOC Dashboard includes:

- Alert Dashboard
- Incident Timeline
- Packet Inspector
- Threat Intelligence
- Device Health
- Active Alerts
- Investigation Panel
- MITRE ATT&CK Mapping
- Network Statistics

---

# 📚 Learning Mode

Every device includes educational content:

- Device Purpose
- OSI Layer
- Packet Processing
- Common Protocols
- Default Ports
- Enterprise Usage
- Common Attacks
- Detection Techniques
- Investigation Workflow
- Hardening Best Practices

---

# 🏢 Enterprise Architecture

```text
                   Internet
                       │
                     ISP
                       │
                Edge Router
                       │
              Border Router
                       │
        Next Generation Firewall
                       │
                      DMZ
        ┌──────────┬───────────┬──────────┐
        │          │           │
 Reverse Proxy    WAF     Load Balancer
        │
   Web Servers
        │
 Application Servers
        │
 Database Servers
        │
    Core Switch
        │
 Distribution Switches
        │
 Access Switches
        │
 ┌──────┼──────┬──────┬──────┐
 HR   Finance   IT    SOC   Guest
        │
 Active Directory
 DNS
 DHCP
 File Server
 Cloud Services
```

---

# ⚙️ Technology Stack

| Component | Technology |
|------------|------------|
| Frontend | Streamlit |
| Backend | Python |
| Visualization | NetworkX |
| Graphs | Graphviz |
| Charts | Plotly |
| Database | SQLite |
| Data Format | JSON |

---

# 📂 Project Structure

```text
SOCVerse/
│
├── app.py
├── README.md
├── requirements.txt
│
├── assets/
├── attacks/
├── config/
├── core/
├── database/
├── devices/
├── logs/
├── network/
├── pages/
├── simulation/
├── soc/
├── tests/
├── ui/
└── utils/
```

---

# 🚀 Installation

```bash
git clone https://github.com/yourusername/SOCVerse.git

cd SOCVerse

python -m venv .venv
```

Windows

```bash
.venv\Scripts\activate
```

Linux/macOS

```bash
source .venv/bin/activate
```

Install requirements

```bash
pip install -r requirements.txt
```

Run

```bash
streamlit run app.py
```

---

# 🛣️ Roadmap

- Live Packet Animation
- PCAP Replay
- Threat Hunting Lab
- Detection Engineering
- Sigma Rules
- YARA Rules
- Active Directory Lab
- Purple Team Scenarios
- Cloud Attack Simulation
- Kubernetes Security
- Multi-user Support
- AI SOC Assistant

---

# 🤝 Contributing

Contributions are always welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push your branch
5. Open a Pull Request

---

# 👨‍💻 Authors

| Author | Contribution |
|---------|--------------|
| **Sairaj Deora** | Project Architecture, Backend Development, System Design |
| **Vishal Dalimbe** | Security Research, Attack Simulation, Documentation, QA |
| **Siddharth Kamble** | Frontend Development, UI/UX, Testing & Optimization |

---

# 📄 License

This project is licensed under the **MIT License**.

---

# ⭐ Support

If you found SOCVerse useful:

⭐ Star the repository

🐛 Report bugs

💡 Suggest features

🤝 Contribute to the project

---

<div align="center">

## 🛡️ Learn • Simulate • Detect • Defend

**Built for the Cybersecurity Community ❤️**

</div>
