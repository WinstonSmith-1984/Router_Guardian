# 🛡️ Router Guardian (v1.6.5)
<p align="left">
Hi , I'm Derek, a cybersecurity analyst. <a href="https://www.credly.com/badges/270c2310-e8c5-4216-b474-f24ff2d9cec4/public_url" target="_blank"> 🏅</a>  Specialising in developing **Living off the Land (LOTL)** detection and internal network threat intelligence software.
<a href="mailto:derekconlon&#64;hotmail&#46;co&#46;uk" title="Email">📫</a>


**Router Guardian** is a high-performance, real-time security dashboard built with Python and Streamlit. It acts as a specialized Syslog collector that intercepts, geolocates, and analyzes blocked traffic logs from hardware routers (such as ASUS RT-series, OpenWrt, or pfSense). 

By transforming raw network logs into an interactive "Cyber-HUD," it provides instant intelligence on who is hitting your firewall and what they are looking for.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-blue?style=for-the-badge)

---

## 🚀 Key Features

* **Real-time Syslog Daemon**: A multi-threaded UDP listener (Port `1514`) that captures incoming router logs without interrupting the UI.
* **Deep Port Intelligence**: Advanced heuristics that categorize scans into specific threat profiles (e.g., Database exfiltration, IoT discovery, or C2 Malware callbacks).
* **Geographical Risk Analysis**: Automatic flagging of high-risk traffic based on Country Codes (RU, CN, KP, etc.) and known malicious ISPs.
* **Interactive HUD**:
    * **Top Security Events**: Live-sorting table with RAG (Red-Amber-Green) status alerts.
    * **ISP Distribution**: Visual breakdown of attack origins using Plotly.
    * **Intelligence Profile**: Deep-dive analysis of specific IPs with localized "Intelligence Notes."
* **Cyberpunk Aesthetic**: A sleek, dark-mode interface with a "Stealth Mode" design and two-tone UI elements.



---

## 🛠️ Installation

### 1. Requirements
Ensure you have Python 3.10+ installed.

### 2. Clone & Install
```bash
git clone [https://github.com/YOUR_USERNAME/router-guardian.git](https://github.com/YOUR_USERNAME/router-guardian.git)
cd router-guardian
pip install streamlit pandas plotly requests
