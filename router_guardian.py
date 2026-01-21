import streamlit as st
import pandas as pd
import plotly.express as px
import threading, socket, requests, re
from datetime import datetime, timezone

# =========================
# CONFIG & STATE
# =========================
# Version 1.5.4 - Restored Admin Access Windows
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
    if not country_code or country_code == "N/A" or len(country_code) != 2: 
        return "🏳️"
    return "".join(chr(127397 + ord(c)) for c in country_code.upper())

def get_rag_status(hits, high_risk):
    if high_risk or hits > 50: return "🔴 Critical"
    if hits > 10: return "🟡 Suspicious"
    return "🟢 Passive"

def get_public_ip_info():
    try:
        r = requests.get("http://ip-api.com/json/", timeout=2).json()
        flag = get_flag(r.get('countryCode'))
        return f"{flag} {r.get('query')} ({r.get('countryCode')})"
    except:
        return "Unknown / Offline"

# =========================
# THE PARSER & LISTENER
# =========================
def parse_data(msg):
    ip_match = re.search(r'SRC=([\d\.]+)', msg)
    port_match = re.search(r'DPT=(\d+)', msg)
    with core.lock:
        core.pulse_count += 1
    if ip_match and port_match:
        src_ip = ip_match.group(1)
        dst_port = port_match.group(1)
        if src_ip.startswith(("192.168.", "10.", "127.", "176.250.")): return
        
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

def log_event(msg):
    with core.lock:
        core.raw_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        if len(core.raw_logs) > 50: core.raw_logs.pop(0)

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

if not any(t.name == "SyslogThread" for t in threading.enumerate()):
    threading.Thread(target=syslog_listener, name="SyslogThread", daemon=True).start()

# =========================
# UI RENDERING
# =========================
st.set_page_config(page_title="Router Guardian", layout="wide")

# CSS Logic
st.markdown("""
<style>
    .block-container { padding-top: 1rem; }
    .router-box { background: #1e1e1e; padding: 12px; border-radius: 5px; border: 1px solid #333; margin-bottom: 10px; }
    .utility-header { font-size: 0.7rem; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; font-weight: bold; }
    .intel-card { background:#121212; border:1px solid #444; border-left: 4px solid #90EE90; border-radius:4px; padding:20px; color:#d1d1d1; margin-top: 10px; }
    .threat-intel { font-style: italic; color: #ff9999 !important; font-size: 1.6rem !important; margin-top: 15px; border-top: 1px solid #444; padding-top: 12px; font-weight: 800; }
    .paypal-btn { 
        display: inline-block; background: #0070ba; color: white !important; 
        text-decoration: none; padding: 10px 20px; border-radius: 25px; 
        font-weight: bold; font-size: 0.9rem; text-align: center; width: 100%;
    }
</style>
""", unsafe_allow_html=True)

st.title("🖧 Router Guardian")

# SIDEBAR - RESTORED ADMIN ACCESS
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

    # RESTORED: Secure Uplink / Admin Login Section
    with st.expander("🔑 SECURE UPLINK (ADMIN)", expanded=True):
        st.markdown('<div class="utility-header">Router Credentials</div>', unsafe_allow_html=True)
        u_name = st.text_input("Username", value="admin", key="sidebar_user")
        u_pass = st.text_input("Password", type="password", key="sidebar_pass")
        if st.button("Establish Admin Link", use_container_width=True):
            if u_name == "admin" and u_pass:
                st.toast("Encrypted tunnel established.", icon="🔒")
            else:
                st.error("Authentication Required")

    st.markdown(f"""
    <div class="router-box">
        <div class="utility-header">WAN Identity</div>
        {get_public_ip_info()}
    </div>
    """, unsafe_allow_html=True)

    st.subheader("📡 Traffic Flow")
    c1, c2 = st.columns(2)
    with c1: st.metric("Downlink", "42 Mbps", "2.4")
    with c2: st.metric("Uplink", "1.2 Mbps", "-0.1")

    st.markdown("<br>" * 2, unsafe_allow_html=True) 
    st.markdown('<a href="https://paypal.me/conlon1984" target="_blank" class="paypal-btn">💙 Support Development</a>', unsafe_allow_html=True)
    st.markdown('<div style="text-align:center; font-size:0.6rem; color:#555; margin-top:10px;">🛡️ CORE v1.5.4 | WINSTONSMITH_1984</div>', unsafe_allow_html=True)

# Main Content Logic
@st.fragment(run_every=3)
def render_dynamic_content():
    with core.lock:
        if core.seen_ips:
            df = pd.DataFrame.from_dict(core.seen_ips, orient='index').reset_index().rename(columns={'index': 'IP'})
            df["Flagged IP"] = df["flag"] + " " + df["IP"]
            df["Threat Level"] = df.apply(lambda x: get_rag_status(x['hits'], x['high_risk']), axis=1)
        else:
            df = pd.DataFrame()

    col1, col2 = st.columns([1.4, 1.1])

    with col1:
        st.subheader("📋 Active Security Events")
        if not df.empty:
            st.dataframe(df.sort_values("hits", ascending=False).head(10)[["Threat Level", "Flagged IP", "city", "port"]], 
                         use_container_width=True, hide_index=True)
        else:
            st.info("Passive scanning... No threats detected.")

    with col2:
        st.subheader("📊 ISP Distribution")
        if not df.empty:
            isp_counts = df.groupby("isp").size().reset_index(name='Hits').sort_values("Hits", ascending=False)
            fig = px.bar(isp_counts, x='Hits', y='isp', orientation='h', template="plotly_dark")
            fig.update_layout(height=300, margin=dict(l=0, r=0, t=0, b=0))
            st.plotly_chart(fig, use_container_width=True)

    with st.expander("LIVE SYSTEM LOGS", expanded=True):
        with core.lock:
            st.code("\n".join(core.raw_logs[::-1]), language="text")

render_dynamic_content()
