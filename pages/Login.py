import streamlit as st
from auth import authenticate_user


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberLens - Login",
    page_icon="🛡️",
    layout="centered"
)


# ============================================================
# HEADER
# ============================================================

st.caption("CYBERLENS  /  SECURE ACCESS")

st.title("Welcome back")

st.write(
    "Sign in to access the CyberLens cyber intelligence platform."
)

st.divider()


# ============================================================
# LOGIN FORM
# ============================================================

username = st.text_input(
    "Username",
    placeholder="Enter your username"
)

password = st.text_input(
    "Password",
    type="password",
    placeholder="Enter your password"
)


# ============================================================
# LOGIN
# ============================================================

st.write("")

if st.button(
    "Sign In  →",
    type="primary",
    use_container_width=True
):

    if not username or not password:

        st.error(
            "Please enter your username and password."
        )

    else:

        user = authenticate_user(
            username,
            password
        )

        if user:

            # ====================================================
            # STORE USER SESSION
            # ====================================================

            st.session_state["logged_in"] = True
            st.session_state["user_id"] = user["id"]
            st.session_state["fullname"] = user["fullname"]
            st.session_state["username"] = user["username"]
            st.session_state["role"] = user["role"]

            # Store organization information if available
            st.session_state["organization_id"] = user.get(
                "organization_id"
            )

            st.session_state["organization_name"] = user.get(
                "organization_name"
            )

            st.success(
                f"Welcome, {user['fullname']}!"
            )

            # ====================================================
            # ROLE-BASED NAVIGATION
            # ====================================================

            role = str(
                user.get("role", "")
            ).strip().lower()

            if role in [
                "organization",
                "organization official",
                "organization_official",
                "admin"
            ]:

                st.switch_page(
                    "pages/Organization_Dashboard.py"
                )

            else:

                # Default = Analyst
                st.switch_page(
                    "pages/Analyst_Dashboard.py"
                )

        else:

            st.error(
                "Invalid username or password."
            )

# ============================================================
# REGISTRATION LINK
# ============================================================

st.divider()

st.write("Don't have a CyberLens account?")

if st.button(
    "Create an Account",
    use_container_width=True
):

    st.switch_page(
        "pages/Register.py"
    )