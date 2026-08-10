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

            # Store logged-in user information
            st.session_state["logged_in"] = True
            st.session_state["user_id"] = user["id"]
            st.session_state["fullname"] = user["fullname"]
            st.session_state["username"] = user["username"]
            st.session_state["role"] = user["role"]

            st.success(
                f"Welcome, {user['fullname']}!"
            )

            # Go to dashboard
            st.switch_page(
                "pages/Dashboard.py"
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