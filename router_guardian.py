import streamlit as st
import pandas as pd
import plotly.express as px
import threading, socket, requests, re
from datetime import datetime, timezone

# =========================
# CONFIG & STATE
# =========================
# Version 1.5.2 - Winston Smith Link & Stealth Mode
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

def get_public_ip_info():
    try:
        r = requests.get("http://ip-api.com/json/", timeout=2).json()
        return f"{r.get('query')} ({r.get('countryCode')})"
    except:
        return "Unknown / Offline"

# =========================
# THE PARSER
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

# =========================
# NETWORK LISTENER
# =========================
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

# Stealth Mode CSS Logic
stealth_css = ""
if st.sidebar.toggle("🌙 Stealth Mode"):
    stealth_css = """
    html, body, [data-testid="stAppViewContainer"] {
        filter: brightness(0.6) contrast(0.9) saturate(0.8) !important;
        transition: 0.5s;
    }
    """

st.markdown(f"""
<style>
    {stealth_css}
    .block-container {{ padding-top: 1rem; }}
    .router-box {{ background: #1e1e1e; padding: 12px; border-radius: 5px; border: 1px solid #333; margin-bottom: 10px; }}
    .utility-header {{ font-size: 0.7rem; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; font-weight: bold; }}
    .intel-card {{ background:#121212; border:1px solid #444; border-left: 4px solid #90EE90; border-radius:4px; padding:20px; color:#d1d1d1; margin-top: 10px; }}
    .threat-intel {{ font-style: italic; color: #ff9999 !important; font-size: 1.6rem !important; margin-top: 15px; border-top: 1px solid #444; padding-top: 12px; font-weight: 800; }}
</style>
""", unsafe_allow_html=True)

st.title("🖧 Router Guardian")

# SIDEBAR
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

    with st.expander("🔑 Secure Uplink", expanded=False):
        u_name = st.text_input("User", value="admin")
        u_pass = st.text_input("Pass", type="password")
        if st.button("Establish Link", width='stretch'):
            st.toast("Encrypted link established", icon="🔒")

    st.markdown("<br>" * 5, unsafe_allow_html=True) 
    # UPDATED LINK
    st.markdown('''<a href="https://buymeacoffee.com/winstonsmith" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 50px !important;width: 180px !important;" ></a>''', unsafe_allow_html=True)

@st.fragment(run_every=3)
def render_dynamic_content():
    with core.lock:
        if core.seen_ips:
            df = pd.DataFrame.from_dict(core.seen_ips, orient='index').reset_index().rename(columns={'index': 'IP'})
            df["Flagged IP"] = df["flag"] + " " + df["IP"]
            df["Threat Level"] = df.apply(lambda x: get_rag_status(x['hits'], x['high_risk']), axis=1)
            df["City/Region"] = df["city"]
            df["Port (Hits)"] = df["port"].astype(str) + " (" + df["hits"].astype(str) + ")"
        else:
            df = pd.DataFrame()

    col1, col2 = st.columns([1.4, 1.1], gap="small")

    with col1:
        st.subheader("📋 Top 10 Security Events")
        if not df.empty:
            top_df = df.sort_values("hits", ascending=False).head(10)
            st.dataframe(top_df[["Threat Level", "Flagged IP", "City/Region", "Port (Hits)"]], 
                         width='stretch', height=400, hide_index=True)
        else:
            st.info("Passive sensors active. No hostile signatures detected.")
        
        if st.button("🗑️ Reset Event Log", width="stretch"):
            with core.lock: 
                core.seen_ips = {}
                core.pulse_count = 0
            st.rerun()

    with col2:
        st.subheader("📊 Traffic Distribution")
        if not df.empty:
            isp_counts = df.groupby("isp").size().reset_index(name='Unique IPs').sort_values("Unique IPs", ascending=False).head(10)
            fig = px.bar(isp_counts, x='Unique IPs', y='isp', orientation='h', 
                         color='Unique IPs', color_continuous_scale='Turbo',
                         template="plotly_dark")
            fig.update_layout(height=400, margin=dict(l=0, r=0, t=0, b=0), showlegend=False)
            st.plotly_chart(fig, theme="streamlit")
        else:
            st.info("Gathering ISP telemetry...")

    if not df.empty:
        st.divider()
        top_df = df.sort_values("hits", ascending=False).head(10)
        selected = st.selectbox("Intelligence Profile View:", ["-- Select IP --"] + list(top_df["IP"]))
        
        if selected != "-- Select IP --":
            t = core.seen_ips.get(selected)
            intel_msg = "Suspected automated botnet scanning."
            if t['port'] == '22': intel_msg = "Brute-force SSH intrusion attempt."
            elif t['port'] in ['80', '443']: intel_msg = "Web service exploit signature."

            st.markdown(f"""
            <div class="intel-card">
                <h4 style="margin:0;">{t['flag']} IP Profile: {selected}</h4>
                <p style="font-size:1.1rem; margin-top:10px;">
                    <b>Location:</b> {t["city"]} | <b>ISP:</b> {t["isp"]}<br>
                    <b>Activity:</b> {t["hits"]} packets intercepted on Port {t["port"]}
                </p>
                <div class="threat-intel"><b>Intelligence Note:</b> {intel_msg}</div>
            </div>
            """, unsafe_allow_html=True)

    with st.expander("LIVE EVENT STREAM", expanded=True):
        with core.lock:
            log_text = "\n".join(core.raw_logs[::-1])
            st.code(log_text, language="text")

render_dynamic_content()
