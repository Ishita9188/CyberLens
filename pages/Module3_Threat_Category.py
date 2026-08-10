import streamlit as st
import pickle
import os
import re
import json
from collections import Counter

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberLens - Threat Category",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = r"D:\Semester5\NLP\CyberLens\static\model\threat_category\threat_category_model.pkl"

# ============================================================
# LOGIN CHECK
# ============================================================

if not st.session_state.get("logged_in", False):
    st.error("Please login to access Threat Category Analysis.")
    st.stop()

user_id = st.session_state.get("user_id")
fullname = st.session_state.get("fullname", "User")

if user_id is None:
    st.error("User ID not found in the current session.")
    st.stop()

# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_model_package():

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(MODEL_PATH)

    with open(MODEL_PATH, "rb") as file:
        package = pickle.load(file)

    return package


try:

    model_package = load_model_package()

except FileNotFoundError:

    st.error("Threat category model file not found.")

    st.info(
        "Copy threat_category_model.pkl into:\n\n"
        "static/model/"
    )

    st.stop()

except Exception as e:

    st.error(f"Unable to load threat category model: {e}")
    st.stop()

# ============================================================
# EXTRACT MODEL FROM PACKAGE
# ============================================================

if isinstance(model_package, dict):

    if "model" not in model_package:

        st.error(
            "Invalid model package. "
            "The 'model' key was not found."
        )

        st.stop()

    model = model_package["model"]

    categories = model_package.get(
        "categories",
        []
    )

    model_type = model_package.get(
        "model_type",
        "NLP Threat Category Classifier"
    )

    training_samples = model_package.get(
        "training_samples",
        None
    )

    testing_samples = model_package.get(
        "testing_samples",
        None
    )

    model_accuracy = model_package.get(
        "accuracy",
        None
    )

    model_precision = model_package.get(
        "precision",
        None
    )

    model_recall = model_package.get(
        "recall",
        None
    )

    model_f1 = model_package.get(
        "f1",
        None
    )

else:

    # Fallback in case a pipeline itself was saved
    model = model_package

    categories = []
    model_type = "NLP Threat Category Classifier"

    training_samples = None
    testing_samples = None
    model_accuracy = None
    model_precision = None
    model_recall = None
    model_f1 = None


# ============================================================
# KEYWORD EXTRACTION
# ============================================================

CYBER_KEYWORDS = [

    "malware",
    "ransomware",
    "phishing",
    "trojan",
    "spyware",
    "botnet",
    "virus",
    "worm",
    "exploit",
    "exploitation",
    "vulnerability",
    "attack",
    "attacker",
    "threat",
    "threat actor",
    "credential",
    "credentials",
    "password",
    "authentication",
    "login",
    "email",
    "spearphishing",
    "spear-phishing",
    "payload",
    "backdoor",
    "rootkit",
    "keylogger",
    "ddos",
    "denial of service",
    "c2",
    "command and control",
    "command-control",
    "data breach",
    "data exfiltration",
    "exfiltration",
    "rce",
    "remote code execution",
    "sql injection",
    "xss",
    "zero-day",
    "zeroday",
    "ip address",
    "domain",
    "url",
    "hash",
    "ioc",
    "indicator",
    "malicious",
    "unauthorized",
    "breach",
    "compromise",
    "compromised",
    "intrusion",
    "network",
    "server",
    "firewall",
    "vpn",
    "ddos attack",
    "distributed denial"
]


def extract_keywords(text):

    text_lower = text.lower()

    found = []

    for keyword in CYBER_KEYWORDS:

        if keyword in text_lower:

            found.append(keyword)

    return list(dict.fromkeys(found))


# ============================================================
# TEXT STATISTICS
# ============================================================

def analyze_text(text):

    words = re.findall(
        r"\b[a-zA-Z0-9_-]+\b",
        text
    )

    sentences = re.split(
        r"[.!?]+",
        text
    )

    sentences = [
        s.strip()
        for s in sentences
        if s.strip()
    ]

    return {
        "characters": len(text),
        "words": len(words),
        "sentences": len(sentences),
        "lines": len(text.splitlines())
    }


# ============================================================
# DATABASE LOGGING
# ============================================================

def log_threat_category_analysis(
    user_id,
    threat_text,
    predicted_category,
    confidence,
    probabilities,
    model_type
):

    try:

        from database import get_connection

        conn = get_connection()

        # ----------------------------------------------------
        # CASE 1: SQLAlchemy Engine / Connection
        # ----------------------------------------------------

        if hasattr(conn, "execute"):

            from sqlalchemy import text

            insert_query = text(
                """
                INSERT INTO threat_category_analysis
                (
                    user_id,
                    threat_text,
                    predicted_category,
                    confidence,
                    probabilities,
                    model_type
                )
                VALUES
                (
                    :user_id,
                    :threat_text,
                    :predicted_category,
                    :confidence,
                    :probabilities,
                    :model_type
                )
                """
            )

            # SQLAlchemy Engine
            if hasattr(conn, "begin"):

                try:

                    with conn.begin() as transaction:

                        transaction.execute(
                            insert_query,
                            {
                                "user_id": user_id,
                                "threat_text": threat_text,
                                "predicted_category": predicted_category,
                                "confidence": confidence,
                                "probabilities": probabilities,
                                "model_type": model_type
                            }
                        )

                except Exception:

                    # SQLAlchemy Connection
                    conn.execute(
                        insert_query,
                        {
                            "user_id": user_id,
                            "threat_text": threat_text,
                            "predicted_category": predicted_category,
                            "confidence": confidence,
                            "probabilities": probabilities,
                            "model_type": model_type
                        }
                    )

                    if hasattr(conn, "commit"):
                        conn.commit()

            else:

                conn.execute(
                    insert_query,
                    {
                        "user_id": user_id,
                        "threat_text": threat_text,
                        "predicted_category": predicted_category,
                        "confidence": confidence,
                        "probabilities": probabilities,
                        "model_type": model_type
                    }
                )

                if hasattr(conn, "commit"):
                    conn.commit()

        # ----------------------------------------------------
        # CASE 2: RAW PSYCOPG CONNECTION
        # ----------------------------------------------------

        elif hasattr(conn, "cursor"):

            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO threat_category_analysis
                (
                    user_id,
                    threat_text,
                    predicted_category,
                    confidence,
                    probabilities,
                    model_type
                )
                VALUES
                (%s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id,
                    threat_text,
                    predicted_category,
                    confidence,
                    probabilities,
                    model_type
                )
            )

            conn.commit()

            cursor.close()

        else:

            raise TypeError(
                "Unsupported database connection object."
            )

        if hasattr(conn, "close"):
            conn.close()

        return True, None

    except Exception as e:

        return False, str(e)


# ============================================================
# PAGE HEADER
# ============================================================

st.title("🛡️ CyberLens - Threat Category Classification")

st.write(
    "Analyze cybersecurity threat descriptions using "
    "NLP-based threat category classification."
)

st.caption(
    f"Logged in as: **{fullname}**"
)

st.divider()

# ============================================================
# MODEL INFORMATION
# ============================================================

with st.expander("Model Information"):

    col1, col2, col3 = st.columns(3)

    col1.write(
        f"**Model Type:** {model_type}"
    )

    if categories:
        col2.write(
            f"**Categories:** {len(categories)}"
        )

    if training_samples is not None:
        col3.write(
            f"**Training Samples:** {training_samples:,}"
        )

    if testing_samples is not None:

        st.write(
            f"**Testing Samples:** {testing_samples:,}"
        )

    if model_accuracy is not None:

        st.write(
            f"**Accuracy:** "
            f"{model_accuracy * 100:.2f}%"
        )

    if model_precision is not None:

        st.write(
            f"**Precision:** "
            f"{model_precision * 100:.2f}%"
        )

    if model_recall is not None:

        st.write(
            f"**Recall:** "
            f"{model_recall * 100:.2f}%"
        )

    if model_f1 is not None:

        st.write(
            f"**F1 Score:** "
            f"{model_f1 * 100:.2f}%"
        )


# ============================================================
# INPUT
# ============================================================

st.subheader("Enter Threat Description")

threat_text = st.text_area(
    "Threat Description",
    height=250,
    placeholder=(
        "Paste a cybersecurity threat report, incident "
        "description, advisory, or threat intelligence text here..."
    ),
    help=(
        "Enter the text you want CyberLens to classify."
    )
)

# ============================================================
# ANALYZE BUTTON
# ============================================================

if st.button(
    "🔍 Analyze Threat",
    type="primary",
    use_container_width=True
):

    if not threat_text.strip():

        st.warning(
            "Please enter a threat description."
        )

        st.stop()

    # --------------------------------------------------------
    # CLEAN INPUT
    # --------------------------------------------------------

    threat_text = threat_text.strip()

    # --------------------------------------------------------
    # TEXT ANALYSIS
    # --------------------------------------------------------

    text_stats = analyze_text(
        threat_text
    )

    detected_keywords = extract_keywords(
        threat_text
    )

    # --------------------------------------------------------
    # MODEL PREDICTION
    # --------------------------------------------------------

    try:

        prediction = model.predict(
            [threat_text]
        )[0]

        prediction = str(prediction)

    except Exception as e:

        st.error(
            f"Threat category prediction failed: {e}"
        )

        st.stop()

    # --------------------------------------------------------
    # PROBABILITY
    # --------------------------------------------------------

    confidence = None
    probability_dict = {}

    if hasattr(
        model,
        "predict_proba"
    ):

        try:

            probabilities_array = model.predict_proba(
                [threat_text]
            )[0]

            if hasattr(
                model,
                "classes_"
            ):

                classes = model.classes_

            else:

                classes = categories

            if len(classes) == len(
                probabilities_array
            ):

                probability_dict = {

                    str(classes[i]):
                    float(probabilities_array[i])

                    for i in range(
                        len(probabilities_array)
                    )
                }

                confidence = max(
                    probability_dict.values()
                )

        except Exception as e:

            st.warning(
                f"Probability calculation unavailable: {e}"
            )

    # --------------------------------------------------------
    # SERIALIZE PROBABILITIES
    # --------------------------------------------------------

    if probability_dict:

        probabilities_text = json.dumps(
            probability_dict
        )

    else:

        probabilities_text = None

    # ========================================================
    # RESULT
    # ========================================================

    st.divider()

    st.subheader("Detection Result")

    result_col1, result_col2 = st.columns(2)

    with result_col1:

        st.success(
            f"### {prediction}"
        )

    with result_col2:

        if confidence is not None:

            st.metric(
                "Model Confidence",
                f"{confidence * 100:.2f}%"
            )

        


    # ========================================================
    # TEXT ANALYSIS
    # ========================================================

    st.divider()

    st.subheader("Threat Text Analysis")

    stat1, stat2, stat3, stat4 = st.columns(4)

    stat1.metric(
        "Characters",
        f"{text_stats['characters']:,}"
    )

    stat2.metric(
        "Words",
        f"{text_stats['words']:,}"
    )

    stat3.metric(
        "Sentences",
        f"{text_stats['sentences']:,}"
    )

    stat4.metric(
        "Detected Keywords",
        len(detected_keywords)
    )

    # ========================================================
    # CYBERSECURITY KEYWORDS
    # ========================================================

    st.divider()

    st.subheader(
        "Cybersecurity Keyword Analysis"
    )

    if detected_keywords:

        st.write(
            "The following cybersecurity-related "
            "terms were detected in the submitted text:"
        )

        keyword_columns = st.columns(3)

        for index, keyword in enumerate(
            detected_keywords
        ):

            with keyword_columns[
                index % 3
            ]:

                st.write(
                    f"🔹 **{keyword}**"
                )

    else:

        st.info(
            "No predefined cybersecurity keywords "
            "were detected."
        )

    # ========================================================
    # THREAT TEXT
    # ========================================================

    st.divider()

    st.subheader(
        "Analyzed Threat Description"
    )

    with st.expander(
        "View submitted threat text"
    ):

        st.write(
            threat_text
        )

    # ========================================================
    # DATABASE LOGGING
    # ========================================================

    success, logging_error = (
        log_threat_category_analysis(
            user_id=user_id,
            threat_text=threat_text,
            predicted_category=prediction,
            confidence=confidence,
            probabilities=probabilities_text,
            model_type=model_type
        )
    )

    if success:

        st.success(
            "✅ Analysis completed and stored "
            "successfully in PostgreSQL."
        )

    else:

        st.warning(
            "Analysis completed, but PostgreSQL "
            f"logging failed: {logging_error}"
        )

    # ========================================================
    # CYBERLENS ASSESSMENT
    # ========================================================

    st.divider()

    st.subheader(
        "CyberLens Assessment"
    )

    if confidence is not None:

        st.write(
            f"CyberLens classified the submitted "
            f"threat description as **{prediction}** "
            f"with a model confidence of "
            f"**{confidence * 100:.2f}%**."
        )

    else:

        st.write(
            f"CyberLens classified the submitted "
            f"threat description as **{prediction}**."
        )

    st.caption(
        "This classification is generated by the trained "
        "CyberLens NLP model and should be interpreted as "
        "an ML-based threat categorization rather than a "
        "definitive security determination."
    )