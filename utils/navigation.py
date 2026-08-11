import streamlit as st


# ============================================================
# CYBERLENS ANALYST NAVIGATION
# ============================================================

def analyst_navigation(active_page=None):
    """
    Shared navigation bar for all CyberLens analyst pages.

    active_page values:
        dashboard
        phishing
        ner
        category
        attack
        summary
        compliance
        explainability
    """

    # ========================================================
    # USER CHECK
    # ========================================================

    if not st.session_state.get("logged_in", False):
        return

    # ========================================================
    # USER INFORMATION
    # ========================================================

    fullname = st.session_state.get(
        "fullname",
        "Analyst"
    )

    role = st.session_state.get(
        "role",
        "Cybersecurity Analyst"
    )

    # ========================================================
    # BRAND + USER AREA
    # ========================================================

    brand_col, user_col, signout_col = st.columns(
        [5, 3, 1.2],
        vertical_alignment="center"
    )

    # --------------------------------------------------------
    # CYBERLENS BRAND
    # --------------------------------------------------------

    with brand_col:

        st.markdown(
            "### 🛡️ CyberLens"
        )

        st.caption(
            "CYBER INTELLIGENCE OPERATIONS"
        )

    # --------------------------------------------------------
    # USER
    # --------------------------------------------------------

    with user_col:

        st.write("")

        st.caption(
            f"{fullname}  •  {role}"
        )

    # --------------------------------------------------------
    # SIGN OUT
    # --------------------------------------------------------

    with signout_col:

        st.write("")

        if st.button(
            "Sign Out",
            key="navigation_signout",
            use_container_width=True
        ):

            # Clear authentication information

            st.session_state["logged_in"] = False

            st.session_state.pop(
                "user_id",
                None
            )

            st.session_state.pop(
                "fullname",
                None
            )

            st.session_state.pop(
                "username",
                None
            )

            st.session_state.pop(
                "role",
                None
            )

            # Return to landing page

            st.switch_page(
                "app.py"
            )

    st.divider()

    # ========================================================
    # MAIN NAVIGATION
    # ========================================================

    nav1, nav2, nav3, nav4 = st.columns(
        [1.15, 1.35, 1.25, 1.55],
        gap="small"
    )

    nav5, nav6, nav7, nav8 = st.columns(
        [1.20, 1.25, 1.35, 1.55],
        gap="small"
    )

    # ========================================================
    # ROW 1
    # ========================================================

    # --------------------------------------------------------
    # COMMAND CENTER
    # --------------------------------------------------------

    with nav1:

        if st.button(
            "⌂  Command Center",
            key="nav_command_center",
            use_container_width=True,
            type=(
                "primary"
                if active_page == "dashboard"
                else "secondary"
            )
        ):

            st.switch_page(
                "pages/Analyst_Dashboard.py"
            )

    # --------------------------------------------------------
    # PHISHING INTEL
    # --------------------------------------------------------

    with nav2:

        if st.button(
            "⚡  Phishing Intel",
            key="nav_phishing",
            use_container_width=True,
            type=(
                "primary"
                if active_page == "phishing"
                else "secondary"
            )
        ):

            st.switch_page(
                "pages/Module1_Phishing.py"
            )

    # --------------------------------------------------------
    # ENTITY INTEL
    # --------------------------------------------------------

    with nav3:

        if st.button(
            "🧠  Entity Intel",
            key="nav_ner",
            use_container_width=True,
            type=(
                "primary"
                if active_page == "ner"
                else "secondary"
            )
        ):

            st.switch_page(
                "pages/Module2_NER.py"
            )

    # --------------------------------------------------------
    # THREAT CLASSIFICATION
    # --------------------------------------------------------

    with nav4:

        if st.button(
            "🏷️  Threat Classification",
            key="nav_category",
            use_container_width=True,
            type=(
                "primary"
                if active_page == "category"
                else "secondary"
            )
        ):

            st.switch_page(
                "pages/Module3_Threat_Category.py"
            )

    # ========================================================
    # ROW 2
    # ========================================================

    # --------------------------------------------------------
    # ATT&CK INTEL
    # --------------------------------------------------------

    with nav5:

        if st.button(
            "🎯  ATT&CK Intel",
            key="nav_attack",
            use_container_width=True,
            type=(
                "primary"
                if active_page == "attack"
                else "secondary"
            )
        ):

            st.switch_page(
                "pages/Module4_ATTACK.py"
            )

    # --------------------------------------------------------
    # THREAT SUMMARY
    # --------------------------------------------------------

    with nav6:

        if st.button(
            "📝  Threat Summary",
            key="nav_summary",
            use_container_width=True,
            type=(
                "primary"
                if active_page == "summary"
                else "secondary"
            )
        ):

            st.switch_page(
                "pages/Module5_Summary.py"
            )

    # --------------------------------------------------------
    # COMPLIANCE INTEL
    # --------------------------------------------------------

    with nav7:

        if st.button(
            "⚖️  Compliance Intel",
            key="nav_compliance",
            use_container_width=True,
            type=(
                "primary"
                if active_page == "compliance"
                else "secondary"
            )
        ):

            st.switch_page(
                "pages/Module6_Compliance.py"
            )

    # --------------------------------------------------------
    # RISK & EXPLAINABILITY
    # --------------------------------------------------------

    with nav8:

        if st.button(
            "🔍  Risk & Explainability",
            key="nav_explainability",
            use_container_width=True,
            type=(
                "primary"
                if active_page == "explainability"
                else "secondary"
            )
        ):

            st.switch_page(
                "pages/Module7_Explainability.py"
            )

    # ========================================================
    # SPACING
    # ========================================================

    st.write("")