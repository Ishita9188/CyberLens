import streamlit as st
from pathlib import Path

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberLens - Analyst Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ============================================================
# ANALYST DASHBOARD CSS
# ============================================================

css_path = (
    Path(__file__).parent.parent
    / "assets"
    / "analyst_dashboard.css"
)

with open(css_path, "r", encoding="utf-8") as file:
    st.markdown(
        f"<style>{file.read()}</style>",
        unsafe_allow_html=True
    )
# ============================================================
# SESSION CHECK
# ============================================================

if not st.session_state.get("logged_in", False):

    st.warning("Please sign in to access the dashboard.")

    if st.button("Go to Login →", type="primary"):
        st.switch_page("pages/Login.py")

    st.stop()


# ============================================================
# USER INFORMATION
# ============================================================

fullname = st.session_state.get(
    "fullname",
    "User"
)

username = st.session_state.get(
    "username",
    ""
)

role = st.session_state.get(
    "role",
    "Analyst"
)


# ============================================================
# HEADER
# ============================================================

st.caption("CYBERLENS  /  ANALYST OPERATIONS")

col1, col2 = st.columns([5, 1])

with col1:

    st.title("Analyst Dashboard")

    st.write(
        f"Welcome back, **{fullname}**."
    )

    st.caption(
        f"Signed in as {role}  •  @{username}"
    )


with col2:

    st.write("")

    if st.button(
        "Sign Out",
        use_container_width=True
    ):

        # Clear authentication information
        st.session_state["logged_in"] = False
        st.session_state.pop("user_id", None)
        st.session_state.pop("fullname", None)
        st.session_state.pop("username", None)
        st.session_state.pop("role", None)

        st.switch_page("app.py")


st.divider()


# ============================================================
# OPERATIONS OVERVIEW
# ============================================================

st.caption("OPERATIONS OVERVIEW")

st.header("Cyber Intelligence Workspace")

st.write(
    "Analyze suspicious URLs, extract intelligence from "
    "cybersecurity reports, map threats to MITRE ATT&CK, "
    "generate summaries and obtain explainable results."
)

st.write("")


# ============================================================
# QUICK STATISTICS
# ============================================================

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Analyses",
        "0",
        help="Total analyses performed by the current user."
    )


with col2:

    st.metric(
        "Threats Detected",
        "0",
        help="Threats identified through CyberLens."
    )


with col3:

    st.metric(
        "Reports Analyzed",
        "0",
        help="CTI reports processed by the user."
    )


with col4:

    st.metric(
        "High Risk",
        "0",
        help="High-risk findings identified."
    )


st.write("")
st.divider()


# ============================================================
# ANALYSIS MODULES
# ============================================================

st.caption("ANALYSIS MODULES")

st.header("Cyber Intelligence Modules")

st.write(
    "Select a module to begin an analysis."
)

st.write("")


# ============================================================
# ROW 1
# ============================================================

col1, col2, col3 = st.columns(3, gap="large")


with col1:

    with st.container(border=True):

        st.caption("MODULE 01")

        st.markdown("### 🔎 Phishing Detection")

        st.write(
            "Analyze URLs and identify potentially "
            "phishing or malicious websites."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="phishing",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module1_Phishing.py"
            )


with col2:

    with st.container(border=True):

        st.caption("MODULE 02")

        st.markdown("### 🧠 Threat Entity Extraction")

        st.write(
            "Extract cybersecurity entities such as "
            "threat actors, malware, vulnerabilities "
            "and organizations from CTI reports."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="ner",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module2_NER.py"
            )


with col3:

    with st.container(border=True):

        st.caption("MODULE 03")

        st.markdown("### 🏷️ Threat Classification")

        st.write(
            "Classify cybersecurity information into "
            "relevant threat categories."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="category",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module3_Threat_Category.py"
            )


# ============================================================
# ROW 2
# ============================================================

st.write("")

col1, col2, col3 = st.columns(3, gap="large")


with col1:

    with st.container(border=True):

        st.caption("MODULE 04")

        st.markdown("### 🎯 MITRE ATT&CK")

        st.write(
            "Map extracted threat intelligence to "
            "MITRE ATT&CK tactics and techniques."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="attack",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module4_ATTACK.py"
            )


with col2:

    with st.container(border=True):

        st.caption("MODULE 05")

        st.markdown("### 📝 Threat Summary")

        st.write(
            "Generate concise summaries from "
            "lengthy cybersecurity reports."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="summary",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module5_Summary.py"
            )


with col3:

    with st.container(border=True):

        st.caption("MODULE 06")

        st.markdown("### ⚖️ Compliance Support")

        st.write(
            "Identify relevant regulatory requirements "
            "and compliance-oriented actions."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="compliance",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module6_Compliance.py"
            )


# ============================================================
# ROW 3
# ============================================================

st.write("")

col1, col2, col3 = st.columns([1, 2, 1])


with col2:

    with st.container(border=True):

        st.caption("MODULE 07")

        st.markdown("### 🔍 Explainability")

        st.write(
            "Understand the reasoning behind "
            "machine-learning based threat predictions "
            "using explainable AI."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="explainability",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module7_Explainability.py"
            )


# ============================================================
# WORKFLOW
# ============================================================

st.write("")
st.divider()

st.caption("ANALYST WORKFLOW")

st.header("From Threat Data to Intelligence")

st.write("")


col1, col2, col3, col4 = st.columns(4)


with col1:

    st.markdown("### 01")

    st.markdown("**DETECT**")

    st.caption(
        "Identify suspicious URLs and threats."
    )


with col2:

    st.markdown("### 02")

    st.markdown("**EXTRACT**")

    st.caption(
        "Extract entities, TTPs and intelligence."
    )


with col3:

    st.markdown("### 03")

    st.markdown("**UNDERSTAND**")

    st.caption(
        "Summarize, classify and map threats."
    )


with col4:

    st.markdown("### 04")

    st.markdown("**EXPLAIN**")

    st.caption(
        "Provide interpretable security insights."
    )


# ============================================================
# RECENT ACTIVITY
# ============================================================

st.write("")
st.divider()

st.caption("RECENT ACTIVITY")

st.header("Analysis History")

st.write(
    "Your recent CyberLens analyses will appear here."
)

st.info(
    "No analysis activity yet. "
    "Start by opening one of the modules above."
)


# ============================================================
# FOOTER
# ============================================================

st.write("")
st.divider()

st.caption(
    "CYBERLENS  •  ANALYST OPERATIONS"
)

st.caption(
    "NLP-based cyber intelligence and explainable threat analysis."
)