import streamlit as st
import pandas as pd
import plotly.express as px
import threading, socket, requests, re
from datetime import datetime

# =========================
# CONFIG & STATE
# =========================
SYSLOG_PORT = 1514
RISK_ZONES = ["RU", "CN", "KP", "IR", "VN"]
RISK_ISPS = ["Chinanet", "China Telecom", "Rostelecom", "Serverel", "OVH SAS"]

class HUDData:
    def __init__(self):
        self.seen_ips = {}
        self.raw_logs = ["🖧 System: Router Guardian Online. Monitoring Ingress..."]
        self.pulse_count = 0
        self.lock = threading.Lock()

if "hud_core" not in st.session_state:
    st.session_state.hud_core = HUDData()

core = st.session_state.hud_core

# --- UTILITY FUNCTIONS ---
def get_flag(country_code):
    if not country_code or country_code == "N/A": return "🏳️"
    return "".join(chr(127397 + ord(c)) for c in country_code.upper())

def get_rag_status(hits, high_risk):
    if high_risk or hits > 50: return "🔴 Critical"
    if hits > 10: return "🟡 Suspicious"
    return "🟢 Passive"

@st.cache_data(ttl=3600)
def get_public_ip_info():
    try:
        r = requests.get("http://ip-api.com/json/", timeout=2).json()
        return f"{r.get('query')} ({r.get('countryCode')})"
    except:
        return "Unknown / Offline"

def log_event(msg):
    with core.lock:
        core.raw_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        if len(core.raw_logs) > 50: core.raw_logs.pop(0)

def parse_data(msg):
    ip_match = re.search(r'SRC=([\d\.]+)', msg)
    port_match = re.search(r'DPT=(\d+)', msg)
    with core.lock:
        core.pulse_count += 1
    if ip_match and port_match:
        src_ip = ip_match.group(1)
        dst_port = port_match.group(1)
        if src_ip.startswith(("192.168.", "10.", "127.", "172.16.")): return
        with core.lock:
            if src_ip in core.seen_ips:
                core.seen_ips[src_ip]["hits"] += 1
                core.seen_ips[src_ip]["last_seen"] = datetime.now().strftime("%H:%M:%S")
            else:
                try:
                    r = requests.get(f"http://ip-api.com/json/{src_ip}", timeout=2).json()
                    c_code = r.get("countryCode", "N/A")
                    isp_name = r.get("isp", "Unknown")
                    is_high_risk = any(z in c_code for z in RISK_ZONES) or any(i in isp_name for i in RISK_ISPS)
                    core.seen_ips[src_ip] = {
                        "hits": 1, "port": dst_port, "city": r.get("city", "Unknown"),
                        "country": c_code, "isp": isp_name, "flag": get_flag(c_code),
                        "high_risk": is_high_risk, "first_seen": datetime.now().strftime("%H:%M:%S"),
                        "last_seen": datetime.now().strftime("%H:%M:%S")
                    }
                except:
                    core.seen_ips[src_ip] = {"hits": 1, "port": dst_port, "city": "N/A", "isp": "Unknown", "flag": "🏳️", "high_risk": False, "first_seen": "---", "last_seen": "---"}
        log_event(f"⚠️ THREAT: Blocked {src_ip} on Port {dst_port}")
    else:
        log_event("🖧 PULSE: Heartbeat received.")

def syslog_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: sock.bind(("", SYSLOG_PORT))
    except: return
    while True:
        try:
            data, addr = sock.recvfrom(8192)
            parse_data(data.decode(errors="ignore"))
        except: pass

if "thread_started" not in st.session_state:
    threading.Thread(target=syslog_listener, name="SyslogThread", daemon=True).start()
    st.session_state.thread_started = True

# =========================
# UI RENDERING & STYLING
# =========================
st.set_page_config(page_title="Router Guardian", layout="wide")

st.markdown("""
<style>
    .block-container { padding-top: 2.5rem !important; }
    [data-testid="stSidebarUserContent"] { padding-top: 1.2rem !important; }
    .router-box { background: #1e1e1e; padding: 12px; border-radius: 5px; border: 1px solid #333; margin-bottom: 10px; }
    .utility-header { font-size: 0.7rem; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; font-weight: bold; }
    .intel-card { background:#121212; border:1px solid #444; border-left: 4px solid #90EE90; border-radius:4px; padding:20px; color:#d1d1d1; margin-top: 10px; }
    .threat-intel { font-style: italic; color: #ff9999 !important; font-size: 1.4rem !important; margin-top: 15px; border-top: 1px solid #444; padding-top: 12px; font-weight: 800; }
    
    .coffee-btn {
        background: linear-gradient(135deg, #FFCC00 50%, #E6B800 50%);
        color: #000;
        padding: 15px;
        border-radius: 50%;
        width: 91px; 
        height: 91px;
        margin: 0 auto;
        text-align: center;
        font-size: 2.8rem;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 6px 12px rgba(0,0,0,0.4);
        cursor: pointer;
        transition: transform 0.3s ease;
    }
    .coffee-btn:hover { transform: scale(1.1); }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.header("📠 Security Hub")
    
    st.markdown(f"""
    <div class="router-box">
        <div class="utility-header">Hardware Status</div>
        <b>Model:</b> RT-AX58U<br>
        <b>Gateway:</b> 192.168.50.1<br>
        <b>Status:</b> <span style="color:#90EE90;">Active Monitoring</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="router-box">
        <div class="utility-header">WAN Identity</div>
        <b>Public IP:</b><br>{get_public_ip_info()}
    </div>
    """, unsafe_allow_html=True)

    st.subheader("📡 Connection Traffic")
    c1, c2 = st.columns(2)
    with c1: st.metric("DL Speed", "42 Mbps", "2.4")
    with c2: st.metric("UL Speed", "1.2 Mbps", "-0.1")

    if st.button("🗑️ Reset Event Log", width="stretch"):
        with core.lock: 
            core.seen_ips = {}
            core.pulse_count = 0
        st.rerun()

    st.markdown("<br>" * 3, unsafe_allow_html=True) 
    
    st.markdown('''
        <a href="https://paypal.me/conlon1984" target="_blank" style="text-decoration: none;">
            <div class="coffee-btn">☕</div>
        </a>
        <div style="margin-top: 20px; padding: 10px; border-top: 1px solid #333; font-size: 0.65rem; color: #666; text-align: center; line-height: 1.2;">
            <b>Licensing & Open Source</b><br>
            This software is released under the <b>GNU General Public License (GPL)</b>. 
            You are free to use, modify, and distribute this tool. 
            Donations are strictly voluntary and support the devs for ongoing security updates.
        </div>
    ''', unsafe_allow_html=True)

# --- MAIN DASHBOARD ---
st.title("🖧 Router Guardian Dashboard")

@st.fragment(run_every=3)
def render_dynamic_content():
    with core.lock:
        if core.seen_ips:
            df = pd.DataFrame.from_dict(core.seen_ips, orient='index').reset_index().rename(columns={'index': 'IP'})
            df["Flagged IP"] = df["flag"] + " " + df["IP"]
            df["Status"] = df.apply(lambda x: get_rag_status(x['hits'], x['high_risk']), axis=1)
            df["Port / Pkt Count"] = df["port"].astype(str) + " (" + df["hits"].astype(str) + ")"
        else:
            df = pd.DataFrame()

    col1, col2 = st.columns([1.5, 1])
    
    with col1:
        st.subheader("📋 Top Security Events")
        if not df.empty:
            st.dataframe(
                df.sort_values("hits", ascending=False).head(10)[["Status", "Flagged IP", "city", "Port / Pkt Count"]], 
                width="stretch", 
                hide_index=True
            )
        else:
            st.info("Passive sensors active. No hostile signatures detected.")

    with col2:
        st.subheader("📊 Traffic Distribution")
        if not df.empty:
            isp_counts = df.groupby("isp").size().reset_index(name='Unique IPs').sort_values("Unique IPs", ascending=False).head(10)
            fig = px.bar(isp_counts, x='Unique IPs', y='isp', orientation='h', template="plotly_dark")
            st.plotly_chart(fig, width="stretch")

    # =========================
    # ENHANCED PORT INTELLIGENCE
    # =========================
    if not df.empty:
        st.divider()
        selected = st.selectbox("Intelligence Profile View:", ["-- Select IP --"] + list(df.sort_values("hits", ascending=False)["IP"].head(10)))
        
        if selected != "-- Select IP --":
            t = core.seen_ips.get(selected)
            p_val = int(t['port'])
            p_str = str(t['port'])
            
            # 1. Direct Common Port Mapping
            port_intel = {
                "21": "FTP: Targeted for credential sniffing or file theft.",
                "22": "SSH: Secure Shell; targeted for brute-force access.",
                "23": "Telnet: Unencrypted remote access; high-risk IoT target.",
                "25": "SMTP: Mail server; scanned for relay exploits.",
                "53": "DNS: Name resolution; targeted for amplification attacks.",
                "80": "HTTP: Web traffic; scanned for SQLi or Path Traversal.",
                "443": "HTTPS: Secure web; probed for SSL/TLS vulnerabilities.",
                "1433": "MSSQL: Database probe seeking default admin access.",
                "3306": "MySQL: Scanning for unprotected database instances.",
                "3389": "RDP: Windows Remote Desktop; high-value ransomware entry point.",
                "5060": "SIP: VoIP protocol; targeted for toll-fraud or call hijacking.",
                "5900": "VNC: Remote Desktop probe seeking unauthenticated screens."
            }
            
            # 2. Service Class Fallback Heuristics
            if p_str in port_intel:
                intel_msg = port_intel[p_str]
            elif 1 <= p_val <= 1024:
                intel_msg = f"Privileged System Port ({p_str}): Probing for OS-level vulnerabilities or kernel exploits."
            elif 1433 <= p_val <= 3306:
                intel_msg = f"Database Range ({p_str}): Target is likely a database server for data exfiltration."
            elif 5000 <= p_val <= 5005:
                intel_msg = f"UPnP/IoT Discovery ({p_str}): Searching for vulnerable smart-home devices."
            elif 25565 <= p_val <= 27015:
                intel_msg = f"Game Server Range ({p_str}): Scanning for Minecraft/Steam server vulnerabilities."
            elif 49152 <= p_val <= 65535:
                intel_msg = f"Dynamic/Ephemeral Range ({p_str}): Often used by advanced malware for C2 (Command & Control) callbacks."
            else:
                intel_msg = f"Registered App Port ({p_str}): Scanning for specific vendor software (NAS, VPN, or Backup agents)."

            st.markdown(f"""
            <div class="intel-card">
                <h4 style="margin:0;">{t['flag']} IP Profile: {selected}</h4>
                <p style="font-size:1.1rem; margin-top:10px;">
                    <b>Location:</b> {t["city"]} | <b>ISP:</b> {t["isp"]}<br>
                    <b>Activity:</b> {t["hits"]} packets intercepted on Port {p_str}
                </p>
                <div class="threat-intel">Intelligence Note: {intel_msg}</div>
            </div>
            """, unsafe_allow_html=True)

    with st.expander("LIVE EVENT STREAM", expanded=True):
        with core.lock:
            st.code("\n".join(core.raw_logs[::-1]), language="text")

render_dynamic_content()
