import streamlit as st


st.set_page_config(
    page_title="CyberLens",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# AUTHENTICATION CHECK
# ============================================================

if not st.session_state.get("logged_in", False):

    st.warning("Please sign in first.")

    if st.button(
        "Go to Login →",
        type="primary"
    ):
        st.switch_page("pages/Login.py")

    st.stop()


# ============================================================
# ROLE-BASED ROUTING
# ============================================================

role = st.session_state.get("role", "")


if role == "Organization":

    st.switch_page(
        "pages/Organization_Dashboard.py"
    )

else:

    st.switch_page(
        "pages/Analyst_Dashboard.py"
    )