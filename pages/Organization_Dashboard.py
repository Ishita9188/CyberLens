import streamlit as st


st.title("🏢 CyberLens")

st.subheader("Organization Security Dashboard")

st.write(
    "Monitor cybersecurity risks, compliance concerns, "
    "and recommended actions."
)

st.divider()

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Threats Detected", "0")

with col2:
    st.metric("High Risk", "0")

with col3:
    st.metric("Phishing Detected", "0")

with col4:
    st.metric("Compliance Issues", "0")

st.divider()

st.subheader("Security & Compliance")

col1, col2 = st.columns(2)

with col1:
    st.info("🛡️ Threat Risk Overview")
    st.info("📊 Security Analysis")
    st.info("📄 Threat Reports")

with col2:
    st.warning("⚖️ Compliance Status")
    st.success("📋 Recommendations")
    st.info("📥 Export Reports")