import streamlit as st
st.set_page_config(
    page_title="CyberLens",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)
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