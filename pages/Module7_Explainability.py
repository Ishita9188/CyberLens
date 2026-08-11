import streamlit as st
import pandas as pd
import numpy as np
import re
import ast
from datetime import datetime
from utils.navigation import analyst_navigation
# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberLens | Explainable Decision Support",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# DATABASE
# ============================================================

try:
    from database import get_connection
except Exception:
    get_connection = None


# ============================================================
# SESSION USER
# ============================================================

user_id = st.session_state.get("user_id")

if not user_id:
    st.warning("User session not found. Please log in again.")
    st.stop()

analyst_navigation(
    active_page="threat"
)
# ============================================================
# DATABASE HELPER
# Supports SQLAlchemy connections and psycopg connections
# ============================================================

def execute_query(query, params=None):
    """
    Executes SELECT queries using the existing database.py
    connection implementation.

    Supports:
    - SQLAlchemy Connection
    - psycopg Connection
    - psycopg cursor-style connection
    """

    if get_connection is None:
        return None, "database.py could not be imported."

    connection = None

    try:
        connection = get_connection()

        # ----------------------------------------------------
        # SQLAlchemy connection
        # ----------------------------------------------------
        if hasattr(connection, "execute") and not hasattr(connection, "cursor"):

            from sqlalchemy import text

            result = connection.execute(
                text(query),
                params or {}
            )

            rows = result.fetchall()

            columns = list(result.keys())

            return pd.DataFrame(rows, columns=columns), None

        # ----------------------------------------------------
        # psycopg connection
        # ----------------------------------------------------
        if hasattr(connection, "cursor"):

            cursor = connection.cursor()

            cursor.execute(
                query,
                params or {}
            )

            if cursor.description:

                rows = cursor.fetchall()

                columns = [
                    column.name
                    if hasattr(column, "name")
                    else column[0]
                    for column in cursor.description
                ]

                cursor.close()

                return pd.DataFrame(
                    rows,
                    columns=columns
                ), None

            cursor.close()

            return pd.DataFrame(), None

        return None, "Unsupported database connection type."

    except Exception as e:

        return None, str(e)

    finally:

        try:
            if connection is not None:
                connection.close()
        except Exception:
            pass


# ============================================================
# SAFE TEXT
# ============================================================

def safe_text(value):

    if value is None:
        return ""

    if isinstance(value, float) and np.isnan(value):
        return ""

    return str(value)


# ============================================================
# FETCH LATEST ANALYSES
# ============================================================

def load_phishing_analysis():

    query = """
        SELECT *
        FROM phishing_analysis
        WHERE user_id = :user_id
        ORDER BY analyzed_at DESC
        LIMIT 20
    """

    return execute_query(
        query,
        {"user_id": user_id}
    )


def load_threat_category():

    query = """
        SELECT *
        FROM threat_category_analysis
        WHERE user_id = :user_id
        ORDER BY analyzed_at DESC
        LIMIT 20
    """

    return execute_query(
        query,
        {"user_id": user_id}
    )


def load_attack_analysis():

    query = """
        SELECT *
        FROM attack_analysis
        WHERE user_id = :user_id
        ORDER BY analyzed_at DESC
        LIMIT 20
    """

    return execute_query(
        query,
        {"user_id": user_id}
    )


def load_summary_analysis():

    query = """
        SELECT *
        FROM summary_analysis
        WHERE user_id = :user_id
        ORDER BY analyzed_at DESC
        LIMIT 20
    """

    return execute_query(
        query,
        {"user_id": user_id}
    )


# ============================================================
# LOAD DATA
# ============================================================

phishing_df, phishing_error = load_phishing_analysis()

category_df, category_error = load_threat_category()

attack_df, attack_error = load_attack_analysis()

summary_df, summary_error = load_summary_analysis()


# ============================================================
# LATEST RECORD
# ============================================================

def latest_record(df):

    if df is None:
        return None

    if df.empty:
        return None

    return df.iloc[0]


phishing_record = latest_record(phishing_df)

category_record = latest_record(category_df)

attack_record = latest_record(attack_df)

summary_record = latest_record(summary_df)


# ============================================================
# TITLE
# ============================================================

st.title("CyberLens")
st.subheader("Explainable Decision Support")

st.caption(
    "Integrated threat reasoning and actionable security recommendations"
)


# ============================================================
# DATA AVAILABILITY
# ============================================================

available_modules = 0

if phishing_record is not None:
    available_modules += 1

if category_record is not None:
    available_modules += 1

if attack_record is not None:
    available_modules += 1

if summary_record is not None:
    available_modules += 1


if available_modules == 0:

    st.info(
        "No completed analyses are available for this user. "
        "Run Modules 3–6 before using Explainable Decision Support."
    )

    st.stop()


# ============================================================
# EXTRACT PHISHING RESULT
# ============================================================

phishing_label = ""
phishing_confidence = 0.0

if phishing_record is not None:

    phishing_columns = list(phishing_record.index)

    possible_label_columns = [
        "prediction",
        "predicted_label",
        "predicted_class",
        "label",
        "result",
        "classification"
    ]

    for column in possible_label_columns:

        if column in phishing_columns:

            phishing_label = safe_text(
                phishing_record[column]
            )

            break

    possible_confidence_columns = [
        "confidence",
        "probability",
        "score"
    ]

    for column in possible_confidence_columns:

        if column in phishing_columns:

            try:
                phishing_confidence = float(
                    phishing_record[column]
                )
            except Exception:
                phishing_confidence = 0.0

            break


# ============================================================
# PHISHING RISK
# ============================================================

def calculate_phishing_risk(label, confidence):

    label_lower = label.lower()

    if (
        "phish" in label_lower
        or "malicious" in label_lower
        or "suspicious" in label_lower
    ):

        if confidence > 1:
            confidence = confidence / 100

        return max(
            70,
            min(
                100,
                confidence * 100
            )
        )

    return max(
        0,
        min(
            35,
            (1 - confidence) * 30
        )
    )


phishing_risk = calculate_phishing_risk(
    phishing_label,
    phishing_confidence
)


# ============================================================
# THREAT CATEGORY RISK
# ============================================================

category_risk = 0

category_name = ""

if category_record is not None:

    columns = list(category_record.index)

    for column in [
        "predicted_category",
        "category",
        "threat_category",
        "predicted_categ"
    ]:

        if column in columns:

            category_name = safe_text(
                category_record[column]
            )

            break


    category_lower = category_name.lower()

    high_risk_categories = [
        "ransomware",
        "credential",
        "phishing",
        "exploit",
        "malware",
        "apt",
        "data breach",
        "account compromise",
        "remote code execution",
        "rce"
    ]

    medium_risk_categories = [
        "email",
        "social engineering",
        "vulnerability",
        "network",
        "authentication",
        "web"
    ]

    if any(
        item in category_lower
        for item in high_risk_categories
    ):

        category_risk = 80

    elif any(
        item in category_lower
        for item in medium_risk_categories
    ):

        category_risk = 60

    elif category_name:

        category_risk = 40


# ============================================================
# ATT&CK RISK
# ============================================================

attack_risk = 0

techniques_text = ""

if attack_record is not None:

    columns = list(attack_record.index)

    for column in [
        "detected_techniques",
        "techniques_found",
        "techniques"
    ]:

        if column in columns:

            techniques_text = safe_text(
                attack_record[column]
            )

            break

    technique_count = len(
        re.findall(
            r"T\d{4}(?:\.\d{3})?",
            techniques_text
        )
    )

    if technique_count >= 8:
        attack_risk = 90

    elif technique_count >= 5:
        attack_risk = 75

    elif technique_count >= 3:
        attack_risk = 60

    elif technique_count >= 1:
        attack_risk = 45


# ============================================================
# SUMMARY RISK
# ============================================================

summary_risk = 0

summary_text = ""

if summary_record is not None:

    columns = list(summary_record.index)

    if "summary" in columns:

        summary_text = safe_text(
            summary_record["summary"]
        )

    elif "threat_summary" in columns:

        summary_text = safe_text(
            summary_record["threat_summary"]
        )


summary_lower = summary_text.lower()

critical_words = [
    "ransomware",
    "data breach",
    "credential theft",
    "remote code execution",
    "privilege escalation",
    "exfiltration",
    "account compromise"
]

high_words = [
    "phishing",
    "malware",
    "spoofing",
    "credential",
    "vulnerability",
    "attack",
    "exploit",
    "threat actor"
]

critical_count = sum(
    1
    for word in critical_words
    if word in summary_lower
)

high_count = sum(
    1
    for word in high_words
    if word in summary_lower
)

summary_risk = min(
    100,
    critical_count * 15 + high_count * 7
)


# ============================================================
# OVERALL RISK
# ============================================================

risk_components = []

if phishing_record is not None:
    risk_components.append(phishing_risk)

if category_record is not None:
    risk_components.append(category_risk)

if attack_record is not None:
    risk_components.append(attack_risk)

if summary_record is not None:
    risk_components.append(summary_risk)


if risk_components:

    overall_risk = round(
        sum(risk_components) /
        len(risk_components),
        1
    )

else:

    overall_risk = 0


# ============================================================
# DECISION
# ============================================================

if overall_risk >= 80:

    decision = "CRITICAL"
    decision_text = (
        "Immediate containment and incident-response "
        "actions are recommended."
    )

elif overall_risk >= 60:

    decision = "HIGH"
    decision_text = (
        "Priority remediation and security-control "
        "review are recommended."
    )

elif overall_risk >= 40:

    decision = "MEDIUM"
    decision_text = (
        "Investigation and preventive controls "
        "should be reviewed."
    )

else:

    decision = "LOW"
    decision_text = (
        "Continue monitoring and maintain current controls."
    )


# ============================================================
# EXECUTIVE DECISION PANEL
# ============================================================

st.divider()

st.header("Security Decision")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Overall Risk",
        f"{overall_risk:.0f}/100"
    )

with col2:
    st.metric(
        "Decision",
        decision
    )

with col3:
    st.metric(
        "Modules Correlated",
        f"{available_modules}/4"
    )

with col4:

    technique_count = len(
        re.findall(
            r"T\d{4}(?:\.\d{3})?",
            techniques_text
        )
    )

    st.metric(
        "ATT&CK Techniques",
        technique_count
    )


st.info(decision_text)


# ============================================================
# RISK CONTRIBUTION CHART
# ============================================================

st.subheader("Risk Contribution")

risk_data = pd.DataFrame(
    {
        "Analysis": [
            "Phishing",
            "Threat Category",
            "ATT&CK",
            "Threat Summary"
        ],
        "Risk": [
            round(phishing_risk, 1),
            round(category_risk, 1),
            round(attack_risk, 1),
            round(summary_risk, 1)
        ]
    }
)

risk_data = risk_data[
    risk_data["Risk"] > 0
]

if not risk_data.empty:

    st.bar_chart(
        risk_data.set_index("Analysis")
    )


# ============================================================
# EXPLAINABLE EVIDENCE
# ============================================================

st.divider()

st.header("Decision Evidence")

evidence = []


if phishing_record is not None:

    evidence.append(
        {
            "Source": "Phishing Analysis",
            "Evidence": (
                phishing_label
                if phishing_label
                else "Phishing analysis available"
            ),
            "Risk Contribution": f"{phishing_risk:.0f}/100"
        }
    )


if category_record is not None:

    evidence.append(
        {
            "Source": "Threat Category",
            "Evidence": (
                category_name
                if category_name
                else "Threat category identified"
            ),
            "Risk Contribution": f"{category_risk:.0f}/100"
        }
    )


if attack_record is not None:

    evidence.append(
        {
            "Source": "MITRE ATT&CK",
            "Evidence": (
                f"{technique_count} ATT&CK techniques detected"
            ),
            "Risk Contribution": f"{attack_risk:.0f}/100"
        }
    )


if summary_record is not None:

    evidence.append(
        {
            "Source": "Threat Summary",
            "Evidence": (
                f"{critical_count} critical indicators and "
                f"{high_count} high-risk indicators identified"
            ),
            "Risk Contribution": f"{summary_risk:.0f}/100"
        }
    )


if evidence:

    evidence_df = pd.DataFrame(evidence)

    st.dataframe(
        evidence_df,
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# KEY THREAT INDICATORS
# ============================================================

st.divider()

st.header("Key Threat Indicators")

indicator_text = " ".join(
    [
        safe_text(
            phishing_record.get(
                "detected_keywords", ""
            )
        )
        if phishing_record is not None
        else "",

        safe_text(
            category_record.get(
                "detected_keywords", ""
            )
        )
        if category_record is not None
        else "",

        safe_text(
            attack_record.get(
                "detected_keywords", ""
            )
        )
        if attack_record is not None
        else "",

        summary_text
    ]
).lower()


cyber_terms = [
    "phishing",
    "credential",
    "malware",
    "ransomware",
    "spoofing",
    "spoofed",
    "vulnerability",
    "exploit",
    "attack",
    "threat actor",
    "password",
    "authentication",
    "mfa",
    "2fa",
    "credential theft",
    "data breach",
    "exfiltration",
    "rce",
    "remote code execution",
    "privilege escalation",
    "persistence",
    "command and control",
    "c2",
    "botnet",
    "trojan",
    "backdoor",
    "payload",
    "malicious",
    "ioc",
    "ip address",
    "domain"
]


detected_terms = []

for term in cyber_terms:

    if term in indicator_text:

        detected_terms.append(term)


if detected_terms:

    terms_df = pd.DataFrame(
        {
            "Indicator": detected_terms,
            "Detected": ["Yes"] * len(detected_terms)
        }
    )

    st.dataframe(
        terms_df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No additional cybersecurity indicators were identified."
    )


# ============================================================
# ACTIONABLE RECOMMENDATIONS
# ============================================================

st.divider()

st.header("Recommended Actions")

recommendations = []


if phishing_risk >= 60:

    recommendations.append(
        {
            "Priority": "Critical",
            "Action": "Block or quarantine suspicious URLs and messages",
            "Reason": "Phishing indicators were identified."
        }
    )

    recommendations.append(
        {
            "Priority": "High",
            "Action": "Review SPF, DKIM and DMARC configuration",
            "Reason": "Email spoofing or phishing indicators were detected."
        }
    )

    recommendations.append(
        {
            "Priority": "High",
            "Action": "Enable phishing-resistant MFA where applicable",
            "Reason": "Credential-focused attack indicators were identified."
        }
    )


if category_risk >= 60:

    recommendations.append(
        {
            "Priority": "High",
            "Action": "Prioritize remediation for the detected threat category",
            "Reason": (
                f"Threat category identified as "
                f"{category_name or 'high-risk activity'}."
            )
        }
    )


if attack_risk >= 60:

    recommendations.append(
        {
            "Priority": "High",
            "Action": "Map detected ATT&CK techniques to defensive controls",
            "Reason": (
                f"{technique_count} ATT&CK techniques "
                "were detected."
            )
        }
    )

    recommendations.append(
        {
            "Priority": "High",
            "Action": "Review detection and threat-hunting coverage",
            "Reason": (
                "Multiple adversary behaviours were identified."
            )
        }
    )


if (
    "vulnerability" in indicator_text
    or "exploit" in indicator_text
):

    recommendations.append(
        {
            "Priority": "Critical",
            "Action": "Assess affected systems and prioritize patching",
            "Reason": (
                "Vulnerability or exploitation indicators were detected."
            )
        }
    )


if (
    "credential" in indicator_text
    or "password" in indicator_text
):

    recommendations.append(
        {
            "Priority": "High",
            "Action": "Review affected credentials and access privileges",
            "Reason": (
                "Credential-related indicators were detected."
            )
        }
    )


if (
    "data breach" in indicator_text
    or "exfiltration" in indicator_text
):

    recommendations.append(
        {
            "Priority": "Critical",
            "Action": "Activate incident-response and data-breach procedures",
            "Reason": (
                "Potential data compromise or exfiltration was identified."
            )
        }
    )


if not recommendations:

    recommendations.append(
        {
            "Priority": "Medium",
            "Action": "Continue monitoring and review security controls",
            "Reason": (
                "No immediate high-risk indicator was identified."
            )
        }
    )


recommendation_df = pd.DataFrame(
    recommendations
)

st.dataframe(
    recommendation_df,
    use_container_width=True,
    hide_index=True
)


# ============================================================
# EXPLAINABILITY SUMMARY
# ============================================================

st.divider()

st.header("Explainability Summary")

explanation_points = []


if phishing_record is not None:

    explanation_points.append(
        f"Phishing analysis contributed a risk score "
        f"of {phishing_risk:.0f}/100."
    )


if category_record is not None:

    explanation_points.append(
        f"The detected threat category was "
        f"{category_name or 'not specified'}, "
        f"with a category risk contribution of "
        f"{category_risk:.0f}/100."
    )


if attack_record is not None:

    explanation_points.append(
        f"{technique_count} MITRE ATT&CK techniques "
        f"were detected, contributing "
        f"{attack_risk:.0f}/100 to the risk assessment."
    )


if summary_record is not None:

    explanation_points.append(
        f"The threat summary contained "
        f"{critical_count} critical indicators and "
        f"{high_count} high-risk indicators."
    )


for point in explanation_points:

    st.write("• " + point)


# ============================================================
# MODEL-AGNOSTIC SHAP / FEATURE EXPLANATION
# ============================================================

st.divider()

st.header("Model Explainability")

st.caption(
    "This section explains model-driven phishing decisions "
    "when a compatible trained model is available."
)


def find_model_path():

    import os

    possible_paths = [
        "static/model/phishing_model.pkl",
        "static/models/phishing_model.pkl",
        "models/phishing_model.pkl",
        "static/model/phishing_model.joblib",
        "static/models/phishing_model.joblib"
    ]

    for path in possible_paths:

        if os.path.exists(path):

            return path

    return None


def load_phishing_model():

    model_path = find_model_path()

    if not model_path:

        return None, None

    try:

        import joblib

        package = joblib.load(model_path)

        if isinstance(package, dict):

            model = package.get("model")

        else:

            model = package

        return model, model_path

    except Exception:

        return None, model_path


def explain_model_features():

    model, model_path = load_phishing_model()

    if model is None:

        return None

    try:

        if hasattr(model, "named_steps"):

            steps = model.named_steps

            vectorizer = None
            classifier = None

            for name, step in steps.items():

                if hasattr(
                    step,
                    "get_feature_names_out"
                ):

                    vectorizer = step

                if hasattr(
                    step,
                    "coef_"
                ):

                    classifier = step


            if (
                vectorizer is not None
                and classifier is not None
            ):

                features = vectorizer.get_feature_names_out()

                coefficients = classifier.coef_

                if coefficients.ndim > 1:

                    coefficients = coefficients[0]

                importance = np.abs(
                    coefficients
                )

                result = pd.DataFrame(
                    {
                        "Feature": features,
                        "Importance": importance
                    }
                )

                result = result.sort_values(
                    "Importance",
                    ascending=False
                )

                return result.head(15)

    except Exception:

        return None

    return None


feature_df = explain_model_features()


if feature_df is not None and not feature_df.empty:

    st.subheader(
        "Top Model Features"
    )

    st.bar_chart(
        feature_df.set_index("Feature")
    )

    st.caption(
        "Feature importance is derived from the existing trained "
        "model. Retraining is not performed."
    )

else:

    st.info(
        "A compatible phishing model with directly accessible "
        "feature importance was not found. Decision evidence "
        "above remains available."
    )


# ============================================================
# CROSS-MODULE CORRELATION
# ============================================================

st.divider()

st.header("Cross-Module Correlation")

correlation_rows = []


if phishing_record is not None:

    correlation_rows.append(
        {
            "Module": "Module 3",
            "Finding": "Phishing Detection",
            "Status": "Available",
            "Decision Impact": (
                "Phishing risk evaluated"
            )
        }
    )


if category_record is not None:

    correlation_rows.append(
        {
            "Module": "Module 3",
            "Finding": "Threat Category",
            "Status": "Available",
            "Decision Impact": (
                "Threat category evaluated"
            )
        }
    )


if attack_record is not None:

    correlation_rows.append(
        {
            "Module": "Module 4",
            "Finding": "ATT&CK Mapping",
            "Status": "Available",
            "Decision Impact": (
                "Adversary behaviour evaluated"
            )
        }
    )


if summary_record is not None:

    correlation_rows.append(
        {
            "Module": "Module 5",
            "Finding": "Threat Summary",
            "Status": "Available",
            "Decision Impact": (
                "Threat context evaluated"
            )
        }
    )


if correlation_rows:

    st.dataframe(
        pd.DataFrame(correlation_rows),
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# COMPLIANCE DECISION
# ============================================================

st.divider()

st.header("Compliance Decision")

compliance_keywords = [
    "phishing",
    "credential",
    "authentication",
    "password",
    "data breach",
    "personal data",
    "vulnerability",
    "attack",
    "incident"
]


compliance_hits = [
    term
    for term in compliance_keywords
    if term in indicator_text
]


if compliance_hits:

    st.warning(
        "Compliance review recommended because the "
        "integrated analysis contains indicators associated "
        "with cybersecurity or incident-response obligations."
    )

    st.write(
        "Detected compliance-relevant indicators:"
    )

    st.write(
        ", ".join(
            sorted(
                set(compliance_hits)
            )
        )
    )

else:

    st.success(
        "No immediate compliance-relevant indicator "
        "was identified by the decision-support layer."
    )


# ============================================================
# FINAL DECISION
# ============================================================

st.divider()

st.header("Final Analyst Decision")

if decision == "CRITICAL":

    st.error(
        "CRITICAL RISK — Immediate investigation, "
        "containment and response are recommended."
    )

elif decision == "HIGH":

    st.error(
        "HIGH RISK — Priority remediation and "
        "security-control review are recommended."
    )

elif decision == "MEDIUM":

    st.warning(
        "MEDIUM RISK — Investigation and preventive "
        "security measures are recommended."
    )

else:

    st.success(
        "LOW RISK — Continue monitoring and maintain "
        "current controls."
    )


# ============================================================
# LOG MODULE 7 DECISION
# ============================================================

def log_decision():

    connection = None

    try:

        if get_connection is None:
            return False, "database.py unavailable."

        connection = get_connection()

        now = datetime.now()

        detected_evidence = "; ".join(
            detected_terms
        )

        recommendation_text = "; ".join(
            item["Action"]
            for item in recommendations
        )

        insert_query = """
            INSERT INTO explainability_analysis
            (
                user_id,
                overall_risk,
                decision,
                phishing_risk,
                category_risk,
                attack_risk,
                summary_risk,
                detected_indicators,
                recommendations,
                analyzed_at
            )
            VALUES
            (
                :user_id,
                :overall_risk,
                :decision,
                :phishing_risk,
                :category_risk,
                :attack_risk,
                :summary_risk,
                :detected_indicators,
                :recommendations,
                :analyzed_at
            )
        """

        # ----------------------------------------------------
        # SQLAlchemy
        # ----------------------------------------------------

        if hasattr(connection, "execute") and not hasattr(
            connection,
            "cursor"
        ):

            from sqlalchemy import text

            connection.execute(
                text(insert_query),
                {
                    "user_id": user_id,
                    "overall_risk": overall_risk,
                    "decision": decision,
                    "phishing_risk": phishing_risk,
                    "category_risk": category_risk,
                    "attack_risk": attack_risk,
                    "summary_risk": summary_risk,
                    "detected_indicators": detected_evidence,
                    "recommendations": recommendation_text,
                    "analyzed_at": now
                }
            )

            if hasattr(connection, "commit"):
                connection.commit()

            return True, None


        # ----------------------------------------------------
        # psycopg
        # ----------------------------------------------------

        if hasattr(connection, "cursor"):

            cursor = connection.cursor()

            psycopg_query = """
                INSERT INTO explainability_analysis
                (
                    user_id,
                    overall_risk,
                    decision,
                    phishing_risk,
                    category_risk,
                    attack_risk,
                    summary_risk,
                    detected_indicators,
                    recommendations,
                    analyzed_at
                )
                VALUES
                (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
            """

            cursor.execute(
                psycopg_query,
                (
                    user_id,
                    overall_risk,
                    decision,
                    phishing_risk,
                    category_risk,
                    attack_risk,
                    summary_risk,
                    detected_evidence,
                    recommendation_text,
                    now
                )
            )

            connection.commit()

            cursor.close()

            return True, None


        return False, "Unsupported database connection."

    except Exception as e:

        try:

            if connection is not None:
                connection.rollback()

        except Exception:
            pass

        return False, str(e)

    finally:

        try:

            if connection is not None:
                connection.close()

        except Exception:
            pass


# ============================================================
# SAVE DECISION
# ============================================================

if st.button(
    "Save Decision Support Analysis",
    type="primary",
    use_container_width=True
):

    success, error = log_decision()

    if success:

        st.success(
            "Explainable decision-support analysis saved successfully."
        )

    else:

        st.warning(
            f"Decision generated successfully, "
            f"but PostgreSQL logging failed: {error}"
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "CyberLens Explainable Decision Support | "
    "Integrated analysis across phishing, threat category, "
    "ATT&CK mapping and threat summarization"
)