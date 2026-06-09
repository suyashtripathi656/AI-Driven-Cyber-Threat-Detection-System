import streamlit as st
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="Threat Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM CSS
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
/* ── Global font & background ── */
html, body, [class*="css"] { font-family: 'Segoe UI', sans-serif; }

/* ── Hero banner ── */
.hero {
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    border-radius: 16px;
    padding: 2rem 2.5rem;
    margin-bottom: 1.5rem;
    color: white;
}
.hero h1 { font-size: 2.2rem; font-weight: 800; margin: 0 0 .4rem 0; }
.hero p  { font-size: 1rem; opacity: .85; margin: 0; }

/* ── Section headers ── */
.section-title {
    font-size: 1.15rem;
    font-weight: 700;
    color: #ffffff !important;
    border-left: 4px solid #4fc3f7;
    padding-left: 10px;
    margin: 1.5rem 0 .8rem 0;
}

/* ── Metric cards ── */
.card-row { display: flex; gap: 1rem; margin: 1rem 0; flex-wrap: wrap; }
.card {
    flex: 1; min-width: 160px;
    border-radius: 14px;
    padding: 1.2rem 1.5rem;
    color: white;
    box-shadow: 0 4px 15px rgba(0,0,0,.15);
}
.card.blue   { background: linear-gradient(135deg,#1565c0,#1976d2); }
.card.red    { background: linear-gradient(135deg,#b71c1c,#e53935); }
.card.green  { background: linear-gradient(135deg,#1b5e20,#388e3c); }
.card.orange { background: linear-gradient(135deg,#e65100,#f57c00); }
.card-val  { font-size: 2rem; font-weight: 800; margin: .2rem 0; }
.card-label{ font-size: .82rem; opacity: .85; text-transform: uppercase; letter-spacing:.05em; }

/* ── Info boxes ── */
.info-box {
    background: #e8f4fd;
    border: 1px solid #90caf9;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    font-size: .9rem;
    margin-bottom: 1rem;
    color: #0d47a1;
}

/* ── About box ── */
.about-box {
    background: #f8f9fa;
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1rem;
    border: 1px solid #dee2e6;
    font-size: .92rem;
    line-height: 1.7;
    color: #1a1a2e !important;
}
.about-box h4 { margin: 0 0 .5rem 0; color: #1a1a2e !important; }
.about-box p, .about-box li, .about-box ol, .about-box ul, .about-box b {
    color: #1a1a2e !important;
}

/* ── Result badge ── */
.badge-attack {
    background:#ffebee; color:#b71c1c;
    border:2px solid #ef9a9a;
    border-radius:50px; padding:.5rem 1.4rem;
    font-weight:700; font-size:1.05rem;
    display:inline-block; margin:.5rem 0;
}
.badge-normal {
    background:#e8f5e9; color:#1b5e20;
    border:2px solid #a5d6a7;
    border-radius:50px; padding:.5rem 1.4rem;
    font-weight:700; font-size:1.05rem;
    display:inline-block; margin:.5rem 0;
}

/* ── Sidebar styling ── */
section[data-testid="stSidebar"] {
    background: #0f2027;
}
section[data-testid="stSidebar"] * { color: #ecf0f1 !important; }
section[data-testid="stSidebar"] .stSlider label { color: #bdc3c7 !important; }

/* ── Tab styling ── */
button[data-baseweb="tab"] { font-size: 1rem; font-weight: 600; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# LOAD MODEL
# ═══════════════════════════════════════════════════════════════════════════════
@st.cache_resource
def load_artifacts():
    preprocessor = joblib.load("preprocessor.pkl")
    model        = joblib.load("model.pkl")
    return preprocessor, model

preprocessor, model = load_artifacts()

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
COLUMNS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
    'wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate'
]
PROTOCOL_TYPES = ['tcp', 'udp', 'icmp']
SERVICES = [
    'ftp_data','other','private','http','remote_job','name','netbios_ns',
    'eco_i','mtp','telnet','finger','domain_u','supdup','uucp_path','Z39_50',
    'smtp','csnet_ns','uucp','netbios_dgm','urp_i','auth','domain','ftp',
    'bgp','ldap','ecr_i','gopher','vmnet','systat','http_443','efs',
    'whois','imap4','iso_tsap','echo','klogin','link','sunrpc','login',
    'kshell','sql_net','time','hostnames','exec','ntp_u','discard',
    'nntp','courier','ctf','ssh','daytime','shell','netstat','pop_3',
    'nnsp','IRC','pop_2','printer','tim_i','pm_dump','red_i','netbios_ssn',
    'rje','X11','urh_i','http_8001','aol','http_2784','tftp_u','harvest'
]
FLAGS = ['SF','S0','REJ','RSTO','RSTR','SH','S1','S2','S3','OTH']

# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("## 🛡️ Control Panel")
    st.markdown("---")

    st.markdown("### ⚙️ Detection Settings")
    threshold = st.slider(
        "Detection Threshold",
        min_value=0.05, max_value=0.95, value=0.40, step=0.05,
        help="Probability cutoff to classify a connection as an attack.\nLower = more sensitive."
    )

    # Visual indicator
    if threshold <= 0.25:
        sens = "🔴 Very High Sensitivity"
    elif threshold <= 0.40:
        sens = "🟠 High Sensitivity"
    elif threshold <= 0.60:
        sens = "🟡 Balanced"
    else:
        sens = "🟢 High Precision"
    st.caption(f"Mode: **{sens}**")

    st.markdown("---")
    st.markdown("### 📊 Model Info")
    st.markdown("""
| Property | Value |
|----------|-------|
| Algorithm | Random Forest |
| Trees | 200 |
| Dataset | NSL-KDD |
| Balancing | SMOTE |
| Encoding | OHE + Binary |
| Threshold | Tunable |
""")
    st.markdown("---")
    st.markdown("### 📚 About This Project")
    st.markdown("""
A **Minor Project** demonstrating ML-based
threat detection on the NSL-KDD
benchmark dataset.

**Key techniques used:**
- Feature Engineering
- SMOTE oversampling
- Threshold tuning
- Binary classification
""")

# ═══════════════════════════════════════════════════════════════════════════════
# HERO BANNER
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="hero">
  <h1>🛡️ Threat Detection System</h1>
  <p>Machine Learning powered detection of malicious network traffic using the NSL-KDD dataset.
  Upload traffic logs or inspect individual connections in real time.</p>
</div>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════════════════════════════════
tab1, tab2, tab3 = st.tabs([
    "📁  Batch Analysis",
    "🔍  Single Connection Inspector",
    "ℹ️  How It Works"
])

# ───────────────────────────────────────────────────────────────────────────────
# TAB 1 — BATCH ANALYSIS
# ───────────────────────────────────────────────────────────────────────────────
with tab1:
    st.markdown('<div class="section-title">Upload Network Traffic File</div>', unsafe_allow_html=True)

    st.markdown("""
<div class="info-box">
📌 <b>Accepted formats:</b> Raw NSL-KDD <code>.txt</code> file (43 columns) or a pre-cleaned CSV with exactly 41 feature columns.<br>
The system will automatically detect headers and strip label columns.
</div>
""", unsafe_allow_html=True)

    uploaded = st.file_uploader("Drop your traffic file here", type=["csv", "txt"],
                                 label_visibility="collapsed")

    if uploaded:
        # ── Load & clean ──────────────────────────────────────────────────────
        raw_peek = pd.read_csv(uploaded, header=None, nrows=1)
        has_header = any(str(v).strip() in COLUMNS for v in raw_peek.iloc[0].tolist())
        uploaded.seek(0)

        df = pd.read_csv(uploaded, header=0 if has_header else None)
        n_cols = df.shape[1]

        col_info, col_run = st.columns([3, 1])
        with col_info:
            st.info(f"📋 **{n_cols} columns** · **{len(df):,} rows** detected. "
                    f"{'Header row found ✓' if has_header else 'No header — using positions.'}")

        if n_cols >= 42:
            df = df.iloc[:, :41]
        if df.shape[1] != 41:
            st.error(f"❌ Expected 41 feature columns, got {df.shape[1]}.")
            st.stop()

        df.columns = COLUMNS
        df = df[df["duration"].astype(str).str.strip() != "duration"].reset_index(drop=True)

        for col in COLUMNS:
            if col not in ['protocol_type', 'service', 'flag']:
                df[col] = pd.to_numeric(df[col], errors='coerce')
        n_bad = df.isnull().any(axis=1).sum()
        df.dropna(inplace=True)
        if n_bad:
            st.warning(f"⚠️ {n_bad} rows dropped due to invalid values.")

        with st.expander("👁️ Preview raw data (first 5 rows)"):
            st.dataframe(df.head(), use_container_width=True)

        st.markdown('<div class="section-title">Run Detection</div>', unsafe_allow_html=True)

        if st.button("🚀 Analyse Traffic", type="primary", use_container_width=True):
            with st.spinner("Running model inference…"):
                X     = preprocessor.transform(df)
                probs = model.predict_proba(X)[:, 1]
                preds = (probs >= threshold).astype(int)

            df["Attack_Probability_%"] = np.round(probs * 100, 2)
            df["Prediction"]           = np.where(preds == 1, "🔴 ATTACK", "🟢 Normal")

            total   = len(df)
            attacks = int(preds.sum())
            normals = total - attacks
            attack_rate = attacks / total * 100

            # ── KPI Cards ─────────────────────────────────────────────────────
            st.markdown('<div class="section-title">📊 Detection Summary</div>', unsafe_allow_html=True)
            st.markdown(f"""
<div class="card-row">
  <div class="card blue">
    <div class="card-label">Total Connections</div>
    <div class="card-val">{total:,}</div>
  </div>
  <div class="card red">
    <div class="card-label">🔴 Attacks Detected</div>
    <div class="card-val">{attacks:,}</div>
    <div class="card-label">{attack_rate:.1f}% of traffic</div>
  </div>
  <div class="card green">
    <div class="card-label">🟢 Normal Traffic</div>
    <div class="card-val">{normals:,}</div>
    <div class="card-label">{100-attack_rate:.1f}% of traffic</div>
  </div>
  <div class="card orange">
    <div class="card-label">⚙️ Threshold Used</div>
    <div class="card-val">{threshold:.2f}</div>
    <div class="card-label">Probability cutoff</div>
  </div>
</div>
""", unsafe_allow_html=True)

            # ── Charts ────────────────────────────────────────────────────────
            st.markdown('<div class="section-title">📈 Visual Analysis</div>', unsafe_allow_html=True)
            c1, c2, c3 = st.columns(3)

            # Pie chart
            with c1:
                fig1, ax1 = plt.subplots(figsize=(4, 4))
                wedges, texts, autotexts = ax1.pie(
                    [normals, attacks],
                    labels=["Normal", "Attack"],
                    colors=["#388e3c", "#e53935"],
                    autopct="%1.1f%%", startangle=90,
                    wedgeprops=dict(linewidth=2, edgecolor='white')
                )
                for at in autotexts:
                    at.set_fontsize(12); at.set_fontweight('bold'); at.set_color('white')
                ax1.set_title("Traffic Distribution", fontsize=13, fontweight='bold', pad=12)
                fig1.tight_layout()
                st.pyplot(fig1)

            # Protocol breakdown
            with c2:
                proto_data = df.groupby('protocol_type')['Prediction'].value_counts().unstack(fill_value=0)
                fig2, ax2 = plt.subplots(figsize=(4, 4))
                proto_data.plot(kind='bar', ax=ax2,
                                color=['#e53935','#388e3c'] if '🔴 ATTACK' in proto_data.columns else ['#388e3c'],
                                edgecolor='white', linewidth=0.5)
                ax2.set_title("Attacks by Protocol", fontsize=13, fontweight='bold')
                ax2.set_xlabel("Protocol"); ax2.set_ylabel("Count")
                ax2.tick_params(axis='x', rotation=0)
                ax2.legend(["Attack","Normal"], fontsize=9)
                fig2.tight_layout()
                st.pyplot(fig2)

            # Top attacked services
            with c3:
                atk_services = df[df["Prediction"] == "🔴 ATTACK"]["service"].value_counts().head(8)
                fig3, ax3 = plt.subplots(figsize=(4, 4))
                bars = ax3.barh(atk_services.index, atk_services.values,
                                color='#e53935', edgecolor='white')
                ax3.set_title("Top Attacked Services", fontsize=13, fontweight='bold')
                ax3.set_xlabel("Attack Count")
                ax3.invert_yaxis()
                fig3.tight_layout()
                st.pyplot(fig3)

            # ── Results Table ─────────────────────────────────────────────────
            st.markdown('<div class="section-title">🗂️ Detailed Results</div>', unsafe_allow_html=True)

            show_filter = st.radio("Show:", ["All", "Attacks Only", "Normal Only"],
                                   horizontal=True)
            display_df = df.copy()
            if show_filter == "Attacks Only":
                display_df = display_df[display_df["Prediction"] == "🔴 ATTACK"]
            elif show_filter == "Normal Only":
                display_df = display_df[display_df["Prediction"] == "🟢 Normal"]

            display_cols = ["Prediction", "Attack_Probability_%",
                            "protocol_type", "service", "flag",
                            "src_bytes", "dst_bytes", "duration",
                            "count", "serror_rate"]

            st.dataframe(
                display_df[display_cols].style
                    .map(lambda v: "background-color:#ffebee;color:#b71c1c;font-weight:bold"
                         if "ATTACK" in str(v) else
                         "background-color:#e8f5e9;color:#1b5e20;font-weight:bold",
                         subset=["Prediction"])
                    .format({"Attack_Probability_%": "{:.1f}%"}),
                use_container_width=True, height=400
            )

            st.caption(f"Showing {len(display_df):,} of {total:,} connections.")

            csv_out = df.to_csv(index=False).encode()
            st.download_button("⬇️ Download Full Results as CSV", csv_out,
                               "tds_results.csv", "text/csv", use_container_width=True)

# ───────────────────────────────────────────────────────────────────────────────
# TAB 2 — SINGLE CONNECTION
# ───────────────────────────────────────────────────────────────────────────────
with tab2:
    st.markdown('<div class="section-title">🔍 Inspect a Single Network Connection</div>', unsafe_allow_html=True)
    st.markdown("""
<div class="info-box">
Fill in the network connection features below and click <b>Analyse</b> to get an instant prediction.
This is useful for testing specific scenarios or demonstrating the model live.
</div>
""", unsafe_allow_html=True)

    with st.expander("📡 Basic Connection Features", expanded=True):
        r1c1, r1c2, r1c3, r1c4 = st.columns(4)
        with r1c1:
            duration      = st.number_input("Duration (seconds)", 0, 60000, 0,
                                            help="Length of the connection in seconds")
            src_bytes     = st.number_input("Source Bytes", 0, 10_000_000, 0,
                                            help="Bytes sent from source to destination")
            dst_bytes     = st.number_input("Destination Bytes", 0, 10_000_000, 0,
                                            help="Bytes sent from destination to source")
        with r1c2:
            protocol_type = st.selectbox("Protocol", PROTOCOL_TYPES,
                                         help="Network protocol used")
            service       = st.selectbox("Service", SERVICES,
                                         help="Network service on destination")
            flag          = st.selectbox("Connection Flag", FLAGS,
                                         help="Status of the connection")
        with r1c3:
            count         = st.number_input("Count", 0, 512, 1,
                                            help="Connections to same host in past 2 sec")
            srv_count     = st.number_input("Srv Count", 0, 512, 1,
                                            help="Connections to same service in past 2 sec")
            logged_in     = st.selectbox("Logged In", [0, 1],
                                         help="1 if successfully logged in, 0 otherwise")
        with r1c4:
            land          = st.selectbox("Land", [0, 1],
                                         help="1 if source/dest host & port are same")
            wrong_fragment= st.number_input("Wrong Fragments", 0, 10, 0)
            urgent        = st.number_input("Urgent Packets", 0, 10, 0)

    with st.expander("🔐 Intrusion Indicators"):
        i1, i2, i3 = st.columns(3)
        with i1:
            hot               = st.number_input("Hot Indicators", 0, 100, 0)
            num_failed_logins = st.number_input("Failed Logins", 0, 10, 0)
            num_compromised   = st.number_input("Compromised Conditions", 0, 1000, 0)
        with i2:
            root_shell        = st.selectbox("Root Shell", [0, 1])
            su_attempted      = st.selectbox("SU Attempted", [0, 1])
            num_root          = st.number_input("Root Accesses", 0, 1000, 0)
        with i3:
            num_file_creations= st.number_input("File Creations", 0, 100, 0)
            num_shells        = st.number_input("Shell Prompts", 0, 10, 0)
            num_access_files  = st.number_input("Access Files", 0, 10, 0)

    with st.expander("📶 Traffic Rate Features"):
        t1, t2 = st.columns(2)
        with t1:
            serror_rate         = st.slider("SYN Error Rate",          0.0, 1.0, 0.0)
            srv_serror_rate     = st.slider("Srv SYN Error Rate",       0.0, 1.0, 0.0)
            rerror_rate         = st.slider("REJ Error Rate",           0.0, 1.0, 0.0)
            srv_rerror_rate     = st.slider("Srv REJ Error Rate",       0.0, 1.0, 0.0)
            same_srv_rate       = st.slider("Same Service Rate",        0.0, 1.0, 1.0)
            diff_srv_rate       = st.slider("Different Service Rate",   0.0, 1.0, 0.0)
            srv_diff_host_rate  = st.slider("Srv Diff Host Rate",       0.0, 1.0, 0.0)
        with t2:
            dst_host_count            = st.number_input("Dst Host Count",           0, 255, 0)
            dst_host_srv_count        = st.number_input("Dst Host Srv Count",       0, 255, 0)
            dst_host_same_srv_rate    = st.slider("Dst Host Same Srv Rate",         0.0, 1.0, 0.0)
            dst_host_diff_srv_rate    = st.slider("Dst Host Diff Srv Rate",         0.0, 1.0, 0.0)
            dst_host_same_src_port_rate = st.slider("Dst Host Same Src Port Rate", 0.0, 1.0, 0.0)
            dst_host_srv_diff_host_rate = st.slider("Dst Host Srv Diff Host Rate", 0.0, 1.0, 0.0)
            dst_host_serror_rate      = st.slider("Dst Host SYN Error Rate",        0.0, 1.0, 0.0)
            dst_host_srv_serror_rate  = st.slider("Dst Host Srv SYN Error Rate",    0.0, 1.0, 0.0)
            dst_host_rerror_rate      = st.slider("Dst Host REJ Error Rate",        0.0, 1.0, 0.0)
            dst_host_srv_rerror_rate  = st.slider("Dst Host Srv REJ Error Rate",    0.0, 1.0, 0.0)

    # hidden fields
    num_outbound_cmds = 0; is_host_login = 0; is_guest_login = 0

    if st.button("🔍 Analyse This Connection", type="primary", use_container_width=True):
        row = pd.DataFrame([[
            duration, protocol_type, service, flag, src_bytes, dst_bytes, land,
            wrong_fragment, urgent, hot, num_failed_logins, logged_in,
            num_compromised, root_shell, su_attempted, num_root,
            num_file_creations, num_shells, num_access_files, num_outbound_cmds,
            is_host_login, is_guest_login, count, srv_count, serror_rate,
            srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate,
            diff_srv_rate, srv_diff_host_rate, dst_host_count, dst_host_srv_count,
            dst_host_same_srv_rate, dst_host_diff_srv_rate,
            dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
            dst_host_serror_rate, dst_host_srv_serror_rate,
            dst_host_rerror_rate, dst_host_srv_rerror_rate
        ]], columns=COLUMNS)

        X    = preprocessor.transform(row)
        prob = model.predict_proba(X)[0, 1]
        pred = int(prob >= threshold)

        st.markdown("---")
        res_col, gauge_col = st.columns([1, 2])

        with res_col:
            if pred == 1:
                st.markdown(f'<div class="badge-attack">🔴 ATTACK DETECTED</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="badge-normal">🟢 NORMAL TRAFFIC</div>', unsafe_allow_html=True)
            st.metric("Attack Probability", f"{prob*100:.1f}%")
            st.metric("Threshold", f"{threshold:.2f}")
            st.metric("Decision", "ATTACK" if pred == 1 else "NORMAL")

        with gauge_col:
            fig, ax = plt.subplots(figsize=(7, 1.5))
            bar_color = "#e53935" if pred == 1 else "#388e3c"
            ax.barh(["Risk Score"], [prob], color=bar_color, height=0.45, zorder=3)
            ax.barh(["Risk Score"], [1],    color="#eeeeee", height=0.45, zorder=2)
            ax.axvline(threshold, color="#333", linestyle="--", linewidth=2,
                       label=f"Threshold = {threshold}")
            ax.set_xlim(0, 1)
            ax.set_xlabel("Attack Probability", fontsize=11)
            ax.set_title("Connection Risk Gauge", fontsize=13, fontweight='bold')
            ax.legend(fontsize=10)
            ax.grid(axis='x', alpha=0.3, zorder=1)
            fig.tight_layout()
            st.pyplot(fig)

# ───────────────────────────────────────────────────────────────────────────────
# TAB 3 — HOW IT WORKS
# ───────────────────────────────────────────────────────────────────────────────
with tab3:
    st.markdown('<div class="section-title">📖 Project Overview</div>', unsafe_allow_html=True)

    c1, c2 = st.columns(2)

    with c1:
        st.markdown("""
<div class="about-box">
<h4>🎯 Problem Statement</h4>
Network intrusion detection is a critical cybersecurity task. 
Traditional rule-based systems struggle with novel attack patterns. 
This project applies <b>Machine Learning</b> to automatically classify 
network connections as <b>Normal</b> or <b>Attack</b> using the 
<b>NSL-KDD</b> benchmark dataset.
</div>
""", unsafe_allow_html=True)

        st.markdown("""
<div class="about-box">
<h4>📦 Dataset — NSL-KDD</h4>
<ul>
<li><b>Training set:</b> ~125,000 records</li>
<li><b>Test set:</b> ~22,500 records</li>
<li><b>Features:</b> 41 network traffic features</li>
<li><b>Classes:</b> Normal vs. Attack (binary)</li>
<li>Improved version of the original KDD Cup 1999 dataset</li>
</ul>
</div>
""", unsafe_allow_html=True)

    with c2:
        st.markdown("""
<div class="about-box">
<h4>⚙️ ML Pipeline</h4>
<ol>
<li><b>Data Loading</b> — NSL-KDD train/test split</li>
<li><b>Preprocessing</b> — OHE for protocol/flag, Binary Encoding for service (70 categories → 7 cols)</li>
<li><b>Feature Selection</b> — Mutual Information scoring</li>
<li><b>Scaling</b> — StandardScaler on all features</li>
<li><b>Balancing</b> — SMOTE oversampling on minority class</li>
<li><b>Model</b> — Random Forest (200 trees, max_depth=20)</li>
<li><b>Threshold Tuning</b> — Custom cutoff at 0.40 for best F1/Recall balance</li>
</ol>
</div>
""", unsafe_allow_html=True)

    st.markdown('<div class="section-title">📊 Model Performance</div>', unsafe_allow_html=True)
    perf_data = {
        "Metric": ["Accuracy", "Recall (Attack)", "F1-Score", "Precision"],
        "Score":  ["~82%",     "~78%",            "~80%",     "~83%"],
        "Notes":  [
            "Overall correct predictions",
            "% of actual attacks caught",
            "Harmonic mean of precision & recall",
            "% of flagged that are true attacks"
        ]
    }
    st.table(pd.DataFrame(perf_data))

    st.markdown("""
<div class="about-box">
<h4>💡 Why Threshold Tuning?</h4>
A standard classifier uses 0.5 as the decision boundary. In intrusion detection, 
<b>missing an attack (False Negative) is more costly than a false alarm (False Positive)</b>. 
By lowering the threshold to <b>0.40</b>, the model becomes more sensitive — 
catching more real attacks at the cost of slightly more false alarms. 
This trade-off is controlled via the sidebar slider.
</div>
""", unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown(
    "<center style='color:gray;font-size:.82rem'>🛡️ Threat Detection System · "
    "Minor Project · Built with Python, scikit-learn & Streamlit</center>",
    unsafe_allow_html=True
)
