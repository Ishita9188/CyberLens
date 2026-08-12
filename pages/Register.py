import streamlit as st
from auth import register_user
st.set_page_config(
    page_title="CyberLens - Registration",
    page_icon="🛡️",
    layout="centered"
)
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

/* ---------- form field labels ---------- */
[data-testid="stWidgetLabel"] p {
    font-family: 'Roboto Mono', monospace !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-size: 0.72rem !important;
    color: white !important;
    font-weight: 700;
}

/* ---------- text inputs -> machined input slots ---------- */
.stTextInput > div > div {
    background-color: #1e2226;
    border: 1px solid var(--steel-border) !important;
    border-radius: 2px !important;
    box-shadow: inset 0 1px 3px rgba(0,0,0,0.5);
}

.stTextInput input {
    font-family: 'Roboto Mono', monospace !important;
    color: var(--text-primary) !important;
    letter-spacing: 0.02em;
}

.stTextInput input::placeholder {
    color: var(--text-muted) !important;
    opacity: 0.7;
}

.stTextInput > div > div:focus-within {
    border-color: var(--safety-yellow) !important;
    box-shadow: 0 0 0 1px var(--safety-yellow), inset 0 1px 3px rgba(0,0,0,0.5);
}

/* ---------- selectbox -> dropdown control panel ---------- */
.stSelectbox > div > div {
    background-color: #1e2226;
    border: 1px solid var(--steel-border) !important;
    border-radius: 2px !important;
    box-shadow: inset 0 1px 3px rgba(0,0,0,0.5);
}

.stSelectbox div[data-baseweb="select"] * {
    font-family: 'Roboto Mono', monospace !important;
    color: var(--text-primary) !important;
}

.stSelectbox > div > div:focus-within {
    border-color: var(--safety-yellow) !important;
    box-shadow: 0 0 0 1px var(--safety-yellow), inset 0 1px 3px rgba(0,0,0,0.5);
}

/* dropdown popover menu */
div[data-baseweb="popover"] ul {
    background-color: var(--steel-panel) !important;
    border: 1px solid var(--steel-border) !important;
}

div[data-baseweb="popover"] li {
    font-family: 'Roboto Mono', monospace !important;
    color: var(--text-primary) !important;
}

div[data-baseweb="popover"] li:hover {
    background-color: var(--steel-panel-hover) !important;
    color: var(--safety-yellow) !important;
}

/* ---------- alerts -> hazard-labelled status plates ---------- */
[data-testid="stAlert"] {
    border-radius: 2px !important;
    font-family: 'Roboto Condensed', sans-serif !important;
}

div[data-testid="stAlertContentError"] {
    color: #f5dcd4 !important;
}

div[data-testid="stNotificationContentError"] {
    background-color: rgba(193, 80, 46, 0.18) !important;
    border: 1px solid var(--rust-orange) !important;
}

div[data-testid="stNotificationContentSuccess"] {
    background-color: rgba(242, 183, 5, 0.12) !important;
    border: 1px solid var(--safety-yellow) !important;
}
</style>
""", unsafe_allow_html=True)


st.caption("CYBERLENS  /  ACCOUNT REGISTRATION")

st.title("Create your CyberLens account")

st.write(
    "Register to access the CyberLens cyber intelligence platform."
)
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

st.write("")

if st.button(
    "Create Account",
    type="primary",
    use_container_width=True
):
    if not fullname or not email or not username or not password:

        st.error(
            "Please fill in all required fields."
        )
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
st.divider()

if st.button(
    "Already have an account?  Sign In",
    use_container_width=True
):
    st.switch_page("pages/Login.py")