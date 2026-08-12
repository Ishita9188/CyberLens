import streamlit as st

st.set_page_config(
    page_title="CyberLens",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ============================================================
# INDUSTRIAL THEME — injected as global CSS
# IMPORTANT: unsafe_allow_html=True is required or Streamlit
# will render the <style> block as plain escaped text instead
# of applying it. This must run before any other st.* calls
# that you want styled (Streamlit applies CSS globally once
# it's in the DOM, but placing it first avoids any flash of
# unstyled content).
# ============================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Oswald:wght@400;500;600;700&family=Roboto+Condensed:wght@400;500;700&family=Roboto+Mono:wght@400;500;700&display=swap');

:root {
    --steel-bg: #1a1d21;
    --steel-panel: #23272c;
    --steel-panel-hover: #2b3036;
    --steel-border: #3d434a;
    --safety-yellow: #f2b705;
    --rust-orange: #c1502e;
    --text-primary: #e8e6e1;
    --text-muted: #8b9198;
}

/* ---------- base app shell ---------- */
.stApp {
    background-color: var(--steel-bg);
    background-image:
        linear-gradient(var(--steel-border) 1px, transparent 1px),
        linear-gradient(90deg, var(--steel-border) 1px, transparent 1px);
    background-size: 42px 42px;
    background-position: -1px -1px;
}

.stApp::before {
    content: "";
    position: fixed;
    top: 0; left: 0; right: 0;
    height: 6px;
    z-index: 999;
    background: repeating-linear-gradient(
        135deg,
        var(--safety-yellow) 0px, var(--safety-yellow) 14px,
        #1a1d21 14px, #1a1d21 28px
    );
}

[data-testid="stHeader"] {
    background-color: rgba(26, 29, 33, 0.85);
    border-bottom: 1px solid var(--steel-border);
}

[data-testid="stAppViewContainer"] {
    color: var(--text-primary);
    font-family: 'Roboto Condensed', sans-serif;
}

[data-testid="stMainBlockContainer"] {
    padding-top: 3rem;
}

/* ---------- typography ---------- */
h1, h2, h3, h4, h5 {
    font-family: 'Oswald', sans-serif !important;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    color: var(--text-primary) !important;
}

h1 {
    border-left: 6px solid var(--safety-yellow);
    padding-left: 0.6em;
}

h2 {
    border-left: 4px solid var(--rust-orange);
    padding-left: 0.55em;
}

p, li, span, label, .stMarkdown {
    font-family: 'Roboto Condensed', sans-serif;
    color: var(--text-primary);
}

/* captions styled like stenciled plate labels / gauge tags */
[data-testid="stCaptionContainer"], .stCaption {
    font-family: 'Roboto Mono', monospace !important;
    text-transform: uppercase;
    letter-spacing: 0.18em;
    font-size: 0.72rem !important;
    color: var(--safety-yellow) !important;
    font-weight: 700;
}

/* ---------- dividers ---------- */
hr {
    border: none;
    height: 2px;
    background: repeating-linear-gradient(
        90deg,
        var(--steel-border) 0px, var(--steel-border) 10px,
        transparent 10px, transparent 20px
    );
    margin: 1.6rem 0;
}

/* ---------- buttons ---------- */
.stButton > button {
    font-family: 'Oswald', sans-serif;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
    border-radius: 2px;
    border: 1px solid var(--steel-border);
    background-color: var(--steel-panel);
    color: var(--text-primary);
    padding: 0.6em 1.2em;
    transition: all 0.15s ease-in-out;
    box-shadow: inset 0 0 0 1px rgba(255,255,255,0.02);
}

.stButton > button:hover {
    background-color: var(--steel-panel-hover);
    border-color: var(--safety-yellow);
    color: var(--safety-yellow);
}

.stButton > button[kind="primary"] {
    background-color: var(--rust-orange);
    border: 1px solid var(--rust-orange);
    color: #1a1d21;
}

.stButton > button[kind="primary"]:hover {
    background-color: var(--safety-yellow);
    border-color: var(--safety-yellow);
    color: #1a1d21;
}

/* ---------- bordered containers -> riveted steel panels ---------- */
[data-testid="stVerticalBlockBorderWrapper"] {
    position: relative;
}

div[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlockBorderWrapper"] {
    background-color: var(--steel-panel);
    border: 1px solid var(--steel-border) !important;
    border-radius: 3px !important;
    box-shadow: 0 4px 10px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.03);
    padding: 4px;
    transition: border-color 0.15s ease-in-out;
}

div[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlockBorderWrapper"]:hover {
    border-color: var(--safety-yellow) !important;
}

/* rivet corners on bordered panels */
div[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlockBorderWrapper"]::before,
div[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlockBorderWrapper"]::after {
    content: "";
    position: absolute;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: radial-gradient(circle at 35% 35%, #6b7178, #33383e 70%);
    box-shadow: 0 0 0 1px rgba(0,0,0,0.5);
    z-index: 2;
}
div[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlockBorderWrapper"]::before {
    top: 8px;
    left: 8px;
}
div[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlockBorderWrapper"]::after {
    bottom: 8px;
    right: 8px;
}

/* ---------- metrics -> gauge readouts ---------- */
[data-testid="stMetric"] {
    background-color: #1e2226;
    border: 1px solid var(--steel-border);
    border-radius: 2px;
    padding: 0.6rem 0.8rem;
}

[data-testid="stMetricLabel"] {
    font-family: 'Roboto Mono', monospace !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-size: 0.7rem !important;
    color: var(--text-muted) !important;
}

[data-testid="stMetricValue"] {
    font-family: 'Roboto Mono', monospace !important;
    color: var(--safety-yellow) !important;
    font-weight: 700 !important;
}
</style>
""", unsafe_allow_html=True)

st.caption("CYBER INTELLIGENCE PLATFORM")

st.title("🛡️ CyberLens")

st.subheader("Intelligent Cyber Threat Analysis")

st.write(
    "NLP-powered threat intelligence, analysis and compliance support "
    "for modern cybersecurity operations."
)

st.write(
    "Transform unstructured cybersecurity information into "
    "actionable and explainable intelligence."
)

st.write("")

col1, col2, col3, col4 = st.columns([2, 2, 1, 2])

with col2:
    if st.button(
        "Get Started  →",
        type="primary",
        use_container_width=True
    ):
        st.switch_page("pages/Register.py")

with col3:
    if st.button(
        "Sign In",
        use_container_width=True
    ):
        st.switch_page("pages/Login.py")

st.divider()

st.caption("PLATFORM OVERVIEW")

st.header("Cyber Intelligence. Unified.")

st.write(
    "CyberLens brings multiple NLP-based cybersecurity capabilities "
    "together into a single analysis platform."
)

st.write("")

col1, col2, col3 = st.columns(3, gap="large")


with col1:

    with st.container(border=True):

        st.caption("01  /  DETECTION")

        st.markdown("### 🔎 Threat Detection")

        st.write(
            "Identify phishing URLs and cybersecurity threat "
            "categories using NLP-based analysis."
        )

        st.write("")

        st.metric(
            label="Capability",
            value="Threat Detection"
        )


with col2:

    with st.container(border=True):

        st.caption("02  /  INTELLIGENCE")

        st.markdown("### 🧠 Threat Intelligence")

        st.write(
            "Extract threat entities, TTPs and meaningful intelligence "
            "from unstructured CTI reports."
        )

        st.write("")

        st.metric(
            label="Capability",
            value="CTI Analysis"
        )


with col3:

    with st.container(border=True):

        st.caption("03  /  COMPLIANCE")

        st.markdown("### ⚖️ Compliance Support")

        st.write(
            "Connect cybersecurity findings with relevant regulatory "
            "requirements and recommended actions."
        )

        st.write("")

        st.metric(
            label="Capability",
            value="Compliance"
        )
st.write("")
st.write("")

st.divider()

st.caption("ANALYSIS WORKFLOW")

st.header("From Data to Action")

st.write(
    "CyberLens processes security information through a structured "
    "NLP and machine-learning workflow."
)

st.write("")


col1, col2, col3, col4 = st.columns(4, gap="medium")


with col1:

    with st.container(border=True):

        st.caption("01")

        st.markdown("### INPUT")

        st.write(
            "URLs, CTI reports and security text."
        )


with col2:

    with st.container(border=True):

        st.caption("02")

        st.markdown("### ANALYZE")

        st.write(
            "NLP and machine-learning processing."
        )


with col3:

    with st.container(border=True):

        st.caption("03")

        st.markdown("### EXPLAIN")

        st.write(
            "Threat reasoning and intelligence."
        )


with col4:

    with st.container(border=True):

        st.caption("04")

        st.markdown("### ACT")

        st.write(
            "ATT&CK mapping and compliance support."
        )


# ============================================================
# MODULES
# ============================================================

st.write("")
st.write("")

st.divider()

st.caption("CYBERLENS CAPABILITIES")

st.header("Seven Analysis Modules")

st.write(
    "The platform is organized into seven integrated modules "
    "covering the complete cybersecurity intelligence workflow."
)

st.write("")
col1, col2, col3 = st.columns(3, gap="large")


with col1:

    with st.container(border=True):

        st.caption("MODULE 01")

        st.markdown("### 🔎 Phishing Detection")

        st.write(
            "Detect potentially malicious URLs using NLP-based "
            "features and machine-learning techniques."
        )


with col2:

    with st.container(border=True):

        st.caption("MODULE 02")

        st.markdown("### 🧠 Cyber Threat NER")

        st.write(
            "Extract cybersecurity entities from unstructured "
            "threat intelligence reports."
        )


with col3:

    with st.container(border=True):

        st.caption("MODULE 03")

        st.markdown("### 🏷️ Threat Category")

        st.write(
            "Classify identified cybersecurity threats into "
            "relevant categories."
        )

st.write("")

col1, col2, col3 = st.columns(3, gap="large")


with col1:

    with st.container(border=True):

        st.caption("MODULE 04")

        st.markdown("### 🎯 MITRE ATT&CK")

        st.write(
            "Map extracted threat intelligence to relevant "
            "MITRE ATT&CK tactics and techniques."
        )
with col2:

    with st.container(border=True):

        st.caption("MODULE 05")

        st.markdown("### 📝 Threat Summary")

        st.write(
            "Generate concise summaries from lengthy "
            "cybersecurity reports."
        )


with col3:

    with st.container(border=True):

        st.caption("MODULE 06")

        st.markdown("### ⚖️ Compliance")

        st.write(
            "Connect cybersecurity findings with relevant "
            "regulatory requirements and actions."
        )
st.write("")

col1, col2, col3 = st.columns([1, 2, 1])

with col2:

    with st.container(border=True):

        st.caption("MODULE 07")

        st.markdown("### 🔍 Explainability")

        st.write(
            "Provide understandable reasoning behind "
            "threat detection and intelligence results."
        )

st.write("")
st.write("")

st.divider()

st.caption("READY TO ANALYZE?")

st.header("Start with CyberLens")

st.write(
    "Create an account to access the CyberLens cybersecurity "
    "intelligence platform."
)

st.write("")

col1, col2, col3 = st.columns([2, 1, 2])

with col2:

    if st.button(
        "Create Account  →",
        type="primary",
        use_container_width=True
    ):
        st.switch_page("pages/Register.py")
st.write("")
st.write("")

st.divider()

st.caption(
    "CYBERLENS  •  NLP-BASED CYBER INTELLIGENCE"
)

st.caption(
    "Explainable intelligence for modern cybersecurity."
)