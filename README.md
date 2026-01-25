# Hi, I'm Derek <p align="right"> <a href="mailto:derekconlon&#64;hotmail&#46;co&#46;uk" title="Email">📫</a> </p>

Tactical <a href="https://www.credly.com/badges/270c2310-e8c5-4216-b474-f24ff2d9cec4/public_url" target="_blank"> cybersecurity enthusiast focused on **Living off the Land (LOTL) detection** and internal network threat intelligence.

---

## 🚀 Featured Project: LOTL-LAN

**LOTL-LAN** is a tactical internal network monitoring suite designed to detect LOTL attack vectors within a Local Area Network.

- **Active Threat Intelligence**: Analyzes lateral pivot patterns and escalates alerts.
- **East-West Threat Window**: Tracks unique internal connection strings in real time.
- **Protocol Decoder**: Insights into discovery protocols for NTLM relay and spoofing.
- **Tactical HUD**: Real-time Security Status Grid, CSV export, and zero-flicker 5s refresh.

**Technical Requirements:**
- Python 3.9+
- Streamlit, PyShark, Plotly, Pandas
- TShark installed with Root/Admin privileges

**Installation & Usage:**
```bash
sudo apt-get install tshark
pip install streamlit pyshark pandas plotly
streamlit run lotl_lan.py
