import streamlit as st
import pickle
import re
from urllib.parse import urlparse
from sqlalchemy import text
from utils.theme import load_theme
from database import engine
from utils.navigation import analyst_navigation

# ============================================================
# URL TOKENIZER
# MUST MATCH THE TRAINING MODEL
# ============================================================

def url_tokenizer(url):
    """
    Splits URL on common structural delimiters.
    This MUST remain identical to the training tokenizer.
    """
    return [
        token
        for token in re.split(r'[/.-?=&_:@#]', url)
        if token
    ]


# ============================================================
# PICKLE TOKENIZER SUPPORT
# ============================================================

import __main__

setattr(__main__, "url_tokenizer", url_tokenizer)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberLens - Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)
load_theme()
# ============================================================
# CHECK LOGIN SESSION
# ============================================================

if not st.session_state.get("logged_in", False):

    st.warning("Please log in to access Phishing Detection.")

    if st.button("Go to Login", type="primary"):
        st.switch_page("pages/Login.py")

    st.stop()
if not st.session_state.get("logged_in", False):

    st.warning("Please log in to access Phishing Detection.")

    if st.button("Go to Login", type="primary"):
        st.switch_page("pages/Login.py")

    st.stop()
analyst_navigation(
    active_page="threat"
)

# ============================================================
# GET LOGGED-IN USER
# ============================================================

user_id = st.session_state.get("user_id")

# ============================================================
# GET LOGGED-IN USER
# ============================================================

user_id = st.session_state.get("user_id")
user_name = st.session_state.get("fullname", "User")
username = st.session_state.get("username")
role = st.session_state.get("role")


# Make sure user ID exists
if not user_id:

    st.error(
        "Unable to identify the logged-in user."
    )

    st.stop()


# ============================================================
# LOAD MODEL
# ============================================================

MODEL_PATH = (
    r"D:\Semester5\NLP\CyberLens"
    r"\static\model\phishing_model.pkl"
)


@st.cache_resource
def load_pipeline():

    with open(MODEL_PATH, "rb") as file:
        return pickle.load(file)


try:

    pipeline = load_pipeline()

except FileNotFoundError:

    st.error(
        f"Phishing model file not found at:\n{MODEL_PATH}"
    )

    st.info(
        "Please run train_phishing_model.py first."
    )

    st.stop()

except Exception as e:

    st.error(
        f"Unable to load phishing model: {e}"
    )

    st.stop()


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(url):

    url = url.strip()

    if not url:
        return ""

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        url
    ):
        url = "https://" + url

    return url


# ============================================================
# URL HEURISTIC ANALYSIS
#
# IMPORTANT:
# These are NOT used for ML prediction.
# They are only supporting observations.
# ============================================================

def analyze_url_heuristics(url):

    parsed = urlparse(url)

    domain = (
        parsed.netloc
        if parsed.netloc
        else parsed.path.split('/')[0]
    )

    netloc = (
        parsed.netloc
        if parsed.netloc
        else parsed.path.split('/')[0]
    )

    domain_without_port = (
        netloc.split(':')[0].lower()
    )

    path = parsed.path
    query = parsed.query

    risks = []
    positives = []

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if parsed.scheme.lower() == "https":

        positives.append(
            "HTTPS security protocol enabled."
        )

    else:

        risks.append(
            "HTTPS is not enabled."
        )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    if re.match(
        r"^(?:\d{1,3}\.){3}\d{1,3}$",
        domain_without_port
    ):

        risks.append(
            "Domain uses an IP address directly "
            "instead of a hostname."
        )

    else:

        positives.append(
            "Uses a standard domain name."
        )

    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if "@" in url:

        risks.append(
            "URL contains '@' which may obscure "
            "the actual destination."
        )

    # --------------------------------------------------------
    # URL LENGTH
    # --------------------------------------------------------

    if len(url) > 75:

        risks.append(
            f"Unusually long URL ({len(url)} characters)."
        )

    else:

        positives.append(
            f"Standard URL length ({len(url)} characters)."
        )

    # --------------------------------------------------------
    # SUSPICIOUS TLD
    # --------------------------------------------------------

    suspicious_tlds = {
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".xyz",
        ".top",
        ".work",
        ".click",
        ".fit",
        ".zip",
        ".mov"
    }

    tld = (
        "." + domain_without_port.split(".")[-1]
        if "." in domain_without_port
        else ""
    )

    if tld in suspicious_tlds:

        risks.append(
            f"Domain uses a commonly abused TLD ({tld})."
        )

    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    domain_parts = [
        part
        for part in domain_without_port.split('.')
        if part
    ]

    subdomain_count = max(
        len(domain_parts) - 2,
        0
    )

    if subdomain_count >= 3:

        risks.append(
            f"Excessive subdomain nesting "
            f"detected ({subdomain_count})."
        )

    # --------------------------------------------------------
    # HYPHENATED DOMAIN
    # --------------------------------------------------------

    if (
        domain_parts
        and len(domain_parts) >= 2
        and "-" in domain_parts[-2]
    ):

        risks.append(
            "Domain contains hyphens that may "
            "be associated with typosquatting."
        )

    # --------------------------------------------------------
    # NON-STANDARD PORT
    # --------------------------------------------------------

    if ":" in netloc:

        try:

            port = int(netloc.rsplit(":", 1)[1])

            if port not in (80, 443):

                risks.append(
                    f"Non-standard network port detected ({port})."
                )

        except ValueError:
            pass

    # --------------------------------------------------------
    # URL ENCODING / OBFUSCATION
    # --------------------------------------------------------

    obfuscated_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )

    if obfuscated_count > 0:

        risks.append(
            "Percent-encoded characters detected "
            f"({obfuscated_count} instances)."
        )

    # --------------------------------------------------------
    # PHISHING-RELATED KEYWORDS
    # --------------------------------------------------------

    phishing_keywords = [
        "login",
        "signin",
        "verify",
        "account",
        "banking",
        "secure",
        "update",
        "wallet",
        "confirm",
        "admin"
    ]

    found_keywords = [
        keyword
        for keyword in phishing_keywords
        if keyword in url.lower()
    ]

    if len(found_keywords) >= 2:

        risks.append(
            "Multiple security/login-related "
            "keywords detected: "
            + ", ".join(found_keywords)
        )

    # --------------------------------------------------------
    # PATH DEPTH
    # --------------------------------------------------------

    path_depth = len([
        segment
        for segment in path.split('/')
        if segment
    ])

    if path_depth >= 4:

        risks.append(
            f"Deep URL path detected "
            f"({path_depth} levels)."
        )

    # --------------------------------------------------------
    # QUERY PARAMETERS
    # --------------------------------------------------------

    if query:

        query_params = len(
            query.split('&')
        )

        if query_params >= 3:

            risks.append(
                f"Multiple URL parameters detected "
                f"({query_params})."
            )

    return {

        "url_length": len(url),

        "domain": domain,

        "domain_length": len(domain),

        "subdomains": subdomain_count,

        "is_https": (
            parsed.scheme.lower() == "https"
        ),

        "risks": risks,

        "positives": positives
    }


# ============================================================
# CREATE INTERPRETATION FOR MODULE 7
#
# This is stored in PostgreSQL.
# It does NOT replace the ML model.
# ============================================================

def create_interpretation(
    prediction,
    phishing_probability,
    confidence,
    heuristics
):

    if prediction == "bad":

        classification = "Phishing"

        interpretation = (
            f"CyberLens classified the URL as phishing "
            f"with a model confidence of "
            f"{confidence * 100:.2f}%. "
            f"The classification was produced by the "
            f"trained NLP URL model using TF-IDF word and "
            f"character features with Logistic Regression."
        )

    else:

        classification = "Legitimate"

        interpretation = (
            f"CyberLens classified the URL as legitimate "
            f"with a model confidence of "
            f"{confidence * 100:.2f}%. "
            f"The classification was produced by the "
            f"trained NLP URL model using TF-IDF word and "
            f"character features with Logistic Regression."
        )

    if heuristics["risks"]:

        interpretation += (
            " Supporting URL observations included: "
            + " ".join(heuristics["risks"])
            + "."
        )

    else:

        interpretation += (
            " No rule-based URL risk indicators were "
            "observed during the supporting structural analysis."
        )

    if heuristics["positives"]:

        interpretation += (
            " Positive URL observations included: "
            + " ".join(heuristics["positives"])
            + "."
        )

    return {
        "classification": classification,
        "text": interpretation
    }


# ============================================================
# SAVE ANALYSIS TO POSTGRESQL
# ============================================================

def save_analysis(
    user_id,
    url,
    heuristics,
    prediction,
    phishing_probability,
    confidence,
    interpretation
):

    with engine.begin() as connection:

        connection.execute(
            text(
                """
                INSERT INTO phishing_analysis
                (
                    user_id,
                    url,
                    domain,
                    prediction,
                    phishing_probability,
                    model_confidence,
                    url_length,
                    domain_length,
                    subdomain_count,
                    is_https,
                    risk_indicators,
                    positive_indicators,
                    interpretation
                )
                VALUES
                (
                    :user_id,
                    :url,
                    :domain,
                    :prediction,
                    :phishing_probability,
                    :model_confidence,
                    :url_length,
                    :domain_length,
                    :subdomain_count,
                    :is_https,
                    :risk_indicators,
                    :positive_indicators,
                    :interpretation
                )
                """
            ),
            {
                "user_id": user_id,
                "url": url,
                "domain": heuristics["domain"],
                "prediction": prediction,
                "phishing_probability": phishing_probability,
                "model_confidence": confidence,
                "url_length": heuristics["url_length"],
                "domain_length": heuristics["domain_length"],
                "subdomain_count": heuristics["subdomains"],
                "is_https": heuristics["is_https"],
                "risk_indicators": "\n".join(
                    heuristics["risks"]
                ),
                "positive_indicators": "\n".join(
                    heuristics["positives"]
                ),
                "interpretation": interpretation
            }
        )


# ============================================================
# PAGE HEADER
# ============================================================

st.title("🛡️ Phishing URL Detection")

st.write(
    "Analyze a URL using the CyberLens NLP-based "
    "phishing detection model."
)

st.divider()


# ============================================================
# URL INPUT
# ============================================================

url_input = st.text_input(
    "Enter URL",
    placeholder="https://example.com",
    help="Enter the URL you want CyberLens to analyze."
)


# ============================================================
# ANALYZE BUTTON
# ============================================================

if st.button(
    "🔍 Analyze Target URL",
    type="primary",
    use_container_width=True
):

    if not url_input.strip():

        st.warning(
            "Please enter a URL."
        )

        st.stop()

    # --------------------------------------------------------
    # NORMALIZE
    # --------------------------------------------------------

    url = normalize_url(url_input)

    parsed = urlparse(url)

    if not parsed.netloc and not parsed.path:

        st.error(
            "Invalid URL format."
        )

        st.stop()

    # --------------------------------------------------------
    # MODEL PREDICTION
    #
    # THIS IS THE ONLY ML CLASSIFICATION.
    # --------------------------------------------------------

    prediction = pipeline.predict([url])[0]

    probabilities = pipeline.predict_proba([url])[0]

    classes = list(
        pipeline.classes_
    )

    if "bad" in classes:

        bad_index = classes.index("bad")

    else:

        bad_index = 0

    phishing_probability = (
        probabilities[bad_index]
    )

    # --------------------------------------------------------
    # MODEL CONFIDENCE
    # --------------------------------------------------------

    if prediction == "bad":

        confidence = phishing_probability

    else:

        confidence = 1 - phishing_probability

    # --------------------------------------------------------
    # SUPPORTING URL ANALYSIS
    # --------------------------------------------------------

    heuristics = analyze_url_heuristics(url)

    # --------------------------------------------------------
    # INTERPRETATION FOR MODULE 7
    # --------------------------------------------------------

    interpretation = create_interpretation(
        prediction,
        phishing_probability,
        confidence,
        heuristics
    )

    # --------------------------------------------------------
    # SAVE TO POSTGRESQL
    # --------------------------------------------------------

    try:

        save_analysis(
            user_id=user_id,
            url=url,
            heuristics=heuristics,
            prediction=prediction,
            phishing_probability=phishing_probability,
            confidence=confidence,
            interpretation=interpretation["text"]
        )

        analysis_saved = True

    except Exception as e:

        analysis_saved = False

        st.error(
            f"Unable to save analysis: {e}"
        )

    # ========================================================
    # DETECTION RESULT
    # ========================================================

    st.divider()

    st.subheader("Detection Result")

    if prediction == "bad":

        st.error(
            "🚨 PHISHING URL DETECTED"
        )

        st.metric(
            "Model Confidence",
            f"{confidence * 100:.2f}%"
        )

    else:

        st.success(
            "✅ LEGITIMATE URL"
        )

        st.metric(
            "Model Confidence",
            f"{confidence * 100:.2f}%"
        )

    st.caption(
        f"Phishing Probability: "
        f"**{phishing_probability * 100:.2f}%**"
    )

    # ========================================================
    # URL OVERVIEW
    # ========================================================

    st.divider()

    st.subheader("URL Analysis")

    m1, m2, m3, m4 = st.columns(4)

    m1.metric(
        "URL Length",
        heuristics["url_length"]
    )

    m2.metric(
        "Domain Length",
        heuristics["domain_length"]
    )

    m3.metric(
        "Subdomains",
        heuristics["subdomains"]
    )

    m4.metric(
        "HTTPS",
        "Yes"
        if heuristics["is_https"]
        else "No"
    )

    # ========================================================
    # SUPPORTING INDICATORS
    # ========================================================

    st.divider()

    col1, col2 = st.columns(2)

    with col1:

        st.subheader(
            "⚠️ Observed URL Indicators"
        )

        if heuristics["risks"]:

            for risk in heuristics["risks"]:

                st.write(
                    f"🔴 {risk}"
                )

        else:

            st.write(
                "No rule-based URL risk indicators observed."
            )

    with col2:

        st.subheader(
            "✓ Positive URL Indicators"
        )

        if heuristics["positives"]:

            for positive in heuristics["positives"]:

                st.write(
                    f"🟢 {positive}"
                )

        else:

            st.write(
                "No additional positive indicators recorded."
            )

    # ========================================================
    # SAVE STATUS
    # ========================================================

    if analysis_saved:

        st.caption(
            "Analysis recorded for the logged-in user."
        )