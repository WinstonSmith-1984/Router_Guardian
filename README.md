🛡️ Router Guardian (v1.5.2)

Router Guardian is a high-performance, tactical security dashboard designed to intercept, analyze, and visualize router syslog data in real-time. It transforms raw network logs into a "glass cockpit" of actionable intelligence, allowing you to monitor inbound threats with the precision of a Network Operations Center.
⚡ Core Features

    Real-Time Syslog Interception: Operates a dedicated UDP listener on Port 1514 to capture ingress logs without latency.

    Geopolitical Intelligence: Automatically flags traffic from high-risk zones (RU, CN, KP, IR, VN) and known malicious ISPs.

    Tactical HUD: A dark-mode interface featuring a "Stealth Mode" for low-visibility environments.

    RAG Threat Assessment: Dynamically assigns "Red-Amber-Green" status based on hit frequency and origin risk.

    Automated Profiling: Identifies common attack vectors such as SSH brute-forcing and web service exploits based on port targeting.

🛠️ The HUD (Heads-Up Display)
🛰️ Security Hub & WAN Identity

The sidebar provides a snapshot of your hardware's health, including your local gateway status and public WAN identity. It features real-time traffic metrics to monitor DL/UL spikes during potential DDoS events.
📋 Security Event Stream

The main interface displays the Top 10 Security Events, providing a curated view of the most persistent hostile signatures.

    Flagged IP: Combines geolocation flags with source IP for instant recognition.

    Port Hits: Tracks exactly which services are being probed.

    ISP Telemetry: A Plotly-driven distribution chart showing which providers are hosting the most unique attackers.

🔧 Technical Architecture

The system is built on a robust, multi-threaded backend to ensure your security monitoring never misses a pulse:

    Asynchronous Listener: The SyslogThread runs as a daemon, decoupled from the UI, to prevent data loss during heavy traffic.

    State Management: Utilizes st.session_state and thread-safe locks (threading.Lock) to maintain data integrity across UI refreshes.

    Dynamic Fragments: Powered by @st.fragment, the dashboard refreshes every 3 seconds, providing a live "pulse" of network activity without a full page reload.

🚀 Deployment
1. Configure Your Router

Set your router's remote syslog server to your machine’s IP address on Port 1514 (Protocol: UDP).
2. Install Dependencies
Bash

pip install streamlit pandas plotly requests

3. Initialize the Guardian
Bash

streamlit run router_guardian.py

🛡️ Stealth & Ethics

The application includes a Stealth Mode toggle that utilizes custom CSS filters to reduce the visual signature of the monitor in dark environments. All intelligence is gathered via the ip-api protocol for non-intrusive metadata collection.

    “He was the guardian of the network, the watcher on the digital wall.” — Winston Smith Mode Active
