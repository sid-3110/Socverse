🛡️ SOCVerse
Interactive Enterprise Network & SOC Attack Simulation Platform
SOCVerse is an interactive cybersecurity learning platform that simulates a real-world enterprise network and Security Operations Center (SOC). It enables users to visualize packet traversal, understand enterprise network architecture, simulate cyber attacks, and investigate alerts from a defender's perspective.
The platform is designed for students, SOC analysts, blue teamers, cybersecurity professionals, and educators who want hands-on experience with enterprise networking and security operations.

🚀 Project Vision
Traditional cybersecurity labs often separate networking, attack simulation, and SOC operations into different tools.
SOCVerse combines them into a single interactive platform where users can:
* Visualize enterprise network traffic
* Understand packet traversal
* Learn how enterprise devices work
* Simulate cyber attacks
* Observe how attacks propagate through the network
* Monitor SOC alerts in real time
* Investigate incidents using realistic workflows
The goal is to bridge the gap between networking fundamentals and real-world Security Operations Center practices.

✨ Features
🌐 Enterprise Network Visualization
* Interactive enterprise network topology
* Animated packet traversal
* Professional enterprise layout
* Clickable network devices
* Realistic routing paths
* Zoom, pan and reset controls

📦 Packet Flow Simulation
Visualize packets travelling through:
* ISP
* Edge Router
* Border Router
* Next Generation Firewall
* DMZ
* WAF
* Reverse Proxy
* Load Balancer
* Web Servers
* Application Servers
* Database Servers
* Core Switch
* Distribution Switch
* Access Switches
* Department VLANs
* Domain Controller
* Cloud Services

🖥 Enterprise Devices
The simulator includes realistic enterprise infrastructure:
Networking
* Edge Routers
* Core Routers
* Layer 2 Switches
* Layer 3 Switches
* Access Switches
* Core Switches
* Distribution Switches
Security
* Next Generation Firewalls
* IDS
* IPS
* Web Application Firewalls
* Forward Proxy
* Reverse Proxy
* VPN Gateway
* SIEM
* SOAR
* EDR/XDR
Infrastructure
* Active Directory
* DNS
* DHCP
* File Server
* Mail Server
* Database Server
* Application Server
* Web Server
* Backup Server
Endpoints
* HR Workstations
* Finance Workstations
* IT Workstations
* SOC Analyst Systems
* Linux Servers
* Windows Servers
Cloud
* AWS
* Azure
* Google Cloud

🎯 Attack Simulations
SOCVerse includes interactive simulations for common enterprise attacks.
Examples include:
* Port Scanning
* SQL Injection
* Cross Site Scripting (XSS)
* SSH Brute Force
* RDP Brute Force
* DNS Tunneling
* ARP Spoofing
* Man-in-the-Middle (MITM)
* Denial of Service (DoS)
* Distributed Denial of Service (DDoS)
* Malware Delivery
* Ransomware
* PowerShell Attacks
* Reverse Shell
* SMB Lateral Movement
* Credential Dumping
* Pass-the-Hash
* Kerberoasting
* Golden Ticket
* Silver Ticket
* Data Exfiltration
* Beaconing
Each simulation includes:
* Animated attack path
* Packet visualization
* Device interaction
* Generated logs
* SOC alerts
* Timeline replay
* MITRE ATT&CK mapping

📊 SOC Dashboard
Monitor simulated enterprise activity through a live dashboard.
Includes:
* Alert Dashboard
* Incident Timeline
* Packet Inspector
* Network Health
* Bandwidth Monitoring
* Device Status
* Active Alerts
* Threat Indicators
* MITRE ATT&CK Mapping
* Investigation Panel

🧠 Learning Mode
Every network component includes educational content.
Learn about:
* Purpose
* OSI Layer
* Packet Processing
* Protocols
* Common Ports
* Enterprise Usage
* Common Attacks
* Detection Techniques
* Investigation Workflow
* Hardening Best Practices

🏢 Enterprise Topology
SOCVerse models a realistic enterprise architecture.
Internet
↓
ISP
↓
Edge Router
↓
Border Router
↓
Next Generation Firewall
↓
DMZ
* Reverse Proxy
* WAF
* Load Balancer
* Web Servers
↓
Internal Network
* Core Switch
* Distribution Switches
* Access Switches
↓
Departments
* HR
* Finance
* IT
* SOC
* Guest
↓
Infrastructure
* Active Directory
* DNS
* DHCP
* File Server
* Database
* Application Servers
↓
Cloud
* AWS
* Azure
* GCP

🛠 Technology Stack
Frontend
* Streamlit
Backend
* Python
Visualization
* NetworkX
* Graphviz
* Streamlit Components
Charts
* Plotly
Database
* SQLite
Data
* JSON

📁 Project Structure
SOCVerse/
│
├── app.py
├── requirements.txt
├── README.md
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

🚀 Installation
Clone the repository:
git clone https://github.com/yourusername/SOCVerse.git
Navigate into the project:
cd SOCVerse
Create a virtual environment:
python -m venv .venv
Activate it:
Windows
.venv\Scripts\activate
Linux/macOS
source .venv/bin/activate
Install dependencies:
pip install -r requirements.txt
Run the application:
streamlit run app.py

🎯 Future Roadmap
* Interactive enterprise network visualization
* Live packet animations
* Custom attack builder
* Multi-user collaboration
* SIEM rule editor
* Sigma rule support
* PCAP replay
* Threat hunting module
* Detection engineering lab
* Blue Team training scenarios
* Active Directory attack simulations
* Cloud attack simulations
* Kubernetes security simulations
* AI-assisted SOC investigations

🤝 Contributing
Contributions are welcome.
If you'd like to improve SOCVerse:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

📄 License
This project is licensed under the MIT License.

👨‍💻 Authors
Sairaj Deora 
Vishal Dalimbe 
Siddharth Kamble

⭐ If you find this project useful, consider giving it a star on GitHub.
