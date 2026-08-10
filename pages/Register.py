import streamlit as st
from auth import register_user


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberLens - Registration",
    page_icon="🛡️",
    layout="centered"
)


# ============================================================
# HEADER
# ============================================================

st.caption("CYBERLENS  /  ACCOUNT REGISTRATION")

st.title("Create your CyberLens account")

st.write(
    "Register to access the CyberLens cyber intelligence platform."
)

st.divider()


# ============================================================
# REGISTRATION FORM
# ============================================================

fullname = st.text_input(
    "Full Name",
    placeholder="Enter your full name"
)

email = st.text_input(
    "Email Address",
    placeholder="Enter your email address"
)

username = st.text_input(
    "Username",
    placeholder="Choose a username"
)

role = st.selectbox(
    "User Type",
    [
        "Cybersecurity Analyst",
        "SOC Analyst",
        "Security Researcher",
        "Threat Intelligence Analyst",
        "Organization"
    ]
)

password = st.text_input(
    "Password",
    type="password",
    placeholder="Create a password"
)

confirm_password = st.text_input(
    "Confirm Password",
    type="password",
    placeholder="Re-enter your password"
)


# ============================================================
# REGISTER
# ============================================================

st.write("")

if st.button(
    "Create Account",
    type="primary",
    use_container_width=True
):

    # Check required fields
    if not fullname or not email or not username or not password:

        st.error(
            "Please fill in all required fields."
        )

    # Check password confirmation
    elif password != confirm_password:

        st.error(
            "Passwords do not match."
        )

    else:

        success, message = register_user(
            fullname,
            email,
            username,
            role,
            password
        )

        if success:

            st.success(message)

            st.write(
                "Your account has been created successfully."
            )

            if st.button(
                "Continue to Login →",
                use_container_width=True
            ):
                st.switch_page("pages/Login.py")

        else:

            st.error(message)


# ============================================================
# LOGIN LINK
# ============================================================

st.divider()

if st.button(
    "Already have an account?  Sign In",
    use_container_width=True
):

    st.switch_page("pages/Login.py")