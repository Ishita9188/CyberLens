import streamlit as st
import pandas as pd

from sqlalchemy import text

from database import engine
from utils.navigation import analyst_navigation
from utils.dashboard_data import (
    get_user_organization,
    get_organization_statistics
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberLens - Organization Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# SESSION CHECK
# ============================================================

if not st.session_state.get("logged_in", False):

    st.warning(
        "Please log in to access Organization Intelligence."
    )

    if st.button(
        "Go to Login →",
        type="primary"
    ):
        st.switch_page("pages/Login.py")

    st.stop()


# ============================================================
# CURRENT USER
# ============================================================

user_id = st.session_state.get("user_id")

fullname = st.session_state.get(
    "fullname",
    "User"
)

role = st.session_state.get(
    "role",
    "User"
)


# ============================================================
# GET ORGANIZATION
# ============================================================

organization_id, organization_name = (
    get_user_organization(user_id)
)


if not organization_id:

    st.warning(
        "Your account is not linked to an organization yet."
    )

    st.info(
        "Please contact the organization administrator."
    )

    st.stop()




# ============================================================
# ORGANIZATION DATA
# ============================================================

stats = get_organization_statistics(
    organization_id
)


# ============================================================
# HEADER
# ============================================================

st.caption(
    "CYBERLENS  /  ORGANIZATION INTELLIGENCE"
)

st.title(
    organization_name
)

st.write(
    "Organization-wide cybersecurity intelligence and analyst activity."
)

st.caption(
    f"Accessed by {fullname}  •  {role}"
)

st.divider()


# ============================================================
# ORGANIZATION METRICS
# ============================================================

st.caption(
    "ORGANIZATION OVERVIEW"
)

st.header(
    "Security Operations Overview"
)

st.write("")

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "Total Analyses",
        stats["analyses"]
    )

with col2:

    st.metric(
        "Threat Findings",
        stats["threats"]
    )

with col3:

    st.metric(
        "Reports Analyzed",
        stats["reports"]
    )

with col4:

    st.metric(
        "High Risk",
        stats["high_risk"]
    )


st.write("")
st.divider()


# ============================================================
# ANALYST ACTIVITY
# ============================================================

st.caption(
    "ANALYST ACTIVITY"
)

st.header(
    "Security Analyst Activity"
)


with engine.connect() as connection:

    result = connection.execute(
        text("""
            SELECT
                u.id,
                u.fullname,
                u.username,
                COUNT(a.id) AS analyses
            FROM users u
            LEFT JOIN (
                SELECT user_id, id
                FROM phishing_analysis

                UNION ALL

                SELECT user_id, id
                FROM ner_analysis

                UNION ALL

                SELECT user_id, id
                FROM threat_category_analysis

                UNION ALL

                SELECT user_id, id
                FROM attack_analysis

                UNION ALL

                SELECT user_id, id
                FROM summary_analysis

                UNION ALL

                SELECT user_id, id
                FROM compliance_analysis

                UNION ALL

                SELECT user_id, id
                FROM explainability_analysis
            ) a
                ON a.user_id = u.id
            WHERE u.organization_id = :organization_id
            GROUP BY
                u.id,
                u.fullname,
                u.username
            ORDER BY analyses DESC
        """),
        {
            "organization_id": organization_id
        }
    )

    rows = result.mappings().all()


if rows:

    analyst_df = pd.DataFrame(rows)

    analyst_df = analyst_df.rename(
        columns={
            "fullname": "Analyst",
            "username": "Username",
            "analyses": "Analyses"
        }
    )

    st.dataframe(
        analyst_df[
            [
                "Analyst",
                "Username",
                "Analyses"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No analyst activity is available yet."
    )


st.write("")
st.divider()


# ============================================================
# ORGANIZATION ANALYSIS BREAKDOWN
# ============================================================

st.caption(
    "INTELLIGENCE COVERAGE"
)

st.header(
    "Analysis Distribution"
)


analysis_counts = {}


tables = {
    "Phishing Intel": "phishing_analysis",
    "Entity Intel": "ner_analysis",
    "Threat Classification": "threat_category_analysis",
    "MITRE ATT&CK": "attack_analysis",
    "Threat Summary": "summary_analysis",
    "Compliance Intel": "compliance_analysis",
    "Risk & Explainability": "explainability_analysis"
}


with engine.connect() as connection:

    for label, table in tables.items():

        try:

            result = connection.execute(
                text(f"""
                    SELECT COUNT(*)
                    FROM {table} a
                    INNER JOIN users u
                        ON a.user_id = u.id
                    WHERE u.organization_id = :organization_id
                """),
                {
                    "organization_id": organization_id
                }
            )

            analysis_counts[label] = (
                result.scalar() or 0
            )

        except Exception:

            analysis_counts[label] = 0


chart_df = pd.DataFrame(
    {
        "Module": list(
            analysis_counts.keys()
        ),
        "Analyses": list(
            analysis_counts.values()
        )
    }
)


st.bar_chart(
    chart_df.set_index("Module"),
    use_container_width=True
)


# ============================================================
# HIGH-RISK DISTRIBUTION
# ============================================================

st.write("")
st.divider()

st.caption(
    "RISK MONITORING"
)

st.header(
    "High-Risk Findings"
)


with engine.connect() as connection:

    result = connection.execute(
        text("""
            SELECT
                COUNT(*) FILTER (
                    WHERE overall_risk < 40
                ) AS low,

                COUNT(*) FILTER (
                    WHERE overall_risk >= 40
                    AND overall_risk < 70
                ) AS medium,

                COUNT(*) FILTER (
                    WHERE overall_risk >= 70
                ) AS high

            FROM explainability_analysis a

            INNER JOIN users u
                ON a.user_id = u.id

            WHERE u.organization_id = :organization_id
        """),
        {
            "organization_id": organization_id
        }
    )

    risk = result.mappings().first()


risk_df = pd.DataFrame(
    {
        "Risk Level": [
            "Low",
            "Medium",
            "High"
        ],
        "Findings": [
            risk["low"] or 0,
            risk["medium"] or 0,
            risk["high"] or 0
        ]
    }
)


st.bar_chart(
    risk_df.set_index("Risk Level"),
    use_container_width=True
)


# ============================================================
# ORGANIZATION USERS
# ============================================================

st.write("")
st.divider()

st.caption(
    "ORGANIZATION MEMBERS"
)

st.header(
    "Security Personnel"
)


with engine.connect() as connection:

    result = connection.execute(
        text("""
            SELECT
                fullname,
                username,
                role
            FROM users
            WHERE organization_id = :organization_id
            ORDER BY fullname
        """),
        {
            "organization_id": organization_id
        }
    )

    users = result.mappings().all()


if users:

    users_df = pd.DataFrame(users)

    users_df = users_df.rename(
        columns={
            "fullname": "Name",
            "username": "Username",
            "role": "Role"
        }
    )

    st.dataframe(
        users_df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No users are currently linked to this organization."
    )

# ============================================================
# MODULE OUTPUT INTELLIGENCE
# ============================================================

st.write("")
st.divider()

st.caption("MODULE OUTPUT INTELLIGENCE")

st.header("Security Intelligence Overview")

st.write(
    "Aggregated intelligence generated by CyberLens analysts "
    "within this organization."
)

# ============================================================
# 1. PHISHING INTELLIGENCE
# ============================================================

st.write("")
st.subheader("Phishing Detection Outcomes")

with engine.connect() as connection:

    result = connection.execute(
        text("""
            SELECT
                p.prediction,
                COUNT(*) AS count
            FROM phishing_analysis p
            INNER JOIN users u
                ON p.user_id = u.id
            WHERE u.organization_id = :organization_id
            GROUP BY p.prediction
            ORDER BY count DESC
        """),
        {
            "organization_id": organization_id
        }
    )

    rows = result.mappings().all()

if rows:

    phishing_df = pd.DataFrame(rows)

    phishing_df = phishing_df.rename(
        columns={
            "prediction": "Prediction",
            "count": "Analyses"
        }
    )

    st.bar_chart(
        phishing_df.set_index("Prediction"),
        use_container_width=True
    )

else:

    st.info(
        "No phishing detection results are available."
    )


# ============================================================
# 2. THREAT CATEGORY DISTRIBUTION
# ============================================================

st.write("")
st.subheader("Threat Category Distribution")

with engine.connect() as connection:

    result = connection.execute(
        text("""
            SELECT
                predicted_category,
                COUNT(*) AS count
            FROM threat_category_analysis t
            INNER JOIN users u
                ON t.user_id = u.id
            WHERE u.organization_id = :organization_id
            GROUP BY predicted_category
            ORDER BY count DESC
        """),
        {
            "organization_id": organization_id
        }
    )

    rows = result.mappings().all()

if rows:

    category_df = pd.DataFrame(rows)

    category_df = category_df.rename(
        columns={
            "predicted_category": "Threat Category",
            "count": "Findings"
        }
    )

    st.bar_chart(
        category_df.set_index("Threat Category"),
        use_container_width=True
    )

else:

    st.info(
        "No threat classification results are available."
    )


# ============================================================
# 3. NER ENTITY EXTRACTION
# ============================================================

st.write("")
st.subheader("Threat Entity Extraction")

with engine.connect() as connection:

    result = connection.execute(
        text("""
            SELECT
                COALESCE(SUM(entity_count), 0) AS total_entities,
                COALESCE(AVG(entity_count), 0) AS average_entities,
                COUNT(*) AS reports
            FROM ner_analysis n
            INNER JOIN users u
                ON n.user_id = u.id
            WHERE u.organization_id = :organization_id
        """),
        {
            "organization_id": organization_id
        }
    )

    ner_stats = result.mappings().first()

if ner_stats:

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Entities Extracted",
            int(ner_stats["total_entities"] or 0)
        )

    with col2:

        st.metric(
            "Average Entities / Report",
            round(
                float(
                    ner_stats["average_entities"] or 0
                ),
                1
            )
        )

    with col3:

        st.metric(
            "Reports Processed",
            int(ner_stats["reports"] or 0)
        )


# ============================================================
# 4. MITRE ATT&CK INTELLIGENCE
# ============================================================

st.write("")
st.subheader("MITRE ATT&CK Technique Coverage")

with engine.connect() as connection:

    result = connection.execute(
        text("""
            SELECT
                detected_techniques,
                detected_keywords
            FROM attack_analysis a
            INNER JOIN users u
                ON a.user_id = u.id
            WHERE u.organization_id = :organization_id
        """),
        {
            "organization_id": organization_id
        }
    )

    attack_rows = result.mappings().all()


if attack_rows:

    technique_counts = {}

    for row in attack_rows:

        techniques = row["detected_techniques"]

        if not techniques:
            continue

        if isinstance(techniques, str):

            parts = [
                x.strip()
                for x in techniques.split(",")
                if x.strip()
            ]

            for technique in parts:

                technique_counts[technique] = (
                    technique_counts.get(
                        technique,
                        0
                    ) + 1
                )


    if technique_counts:

        attack_df = pd.DataFrame(
            {
                "Technique": list(
                    technique_counts.keys()
                ),
                "Occurrences": list(
                    technique_counts.values()
                )
            }
        )

        attack_df = attack_df.sort_values(
            "Occurrences",
            ascending=False
        )

        st.bar_chart(
            attack_df.set_index("Technique"),
            use_container_width=True
        )

    else:

        st.info(
            "No ATT&CK techniques have been identified yet."
        )

else:

    st.info(
        "No ATT&CK analysis results are available."
    )


# ============================================================
# 5. THREAT SUMMARY PERFORMANCE
# ============================================================

st.write("")
st.subheader("Threat Report Summarization")

with engine.connect() as connection:

    result = connection.execute(
        text("""
            SELECT
                COUNT(*) AS reports,
                COALESCE(
                    AVG(original_word_count),
                    0
                ) AS avg_original_words,
                COALESCE(
                    AVG(summary_word_count),
                    0
                ) AS avg_summary_words,
                COALESCE(
                    AVG(compression_ratio),
                    0
                ) AS avg_compression
            FROM threat_summary_analysis s
            INNER JOIN users u
                ON s.user_id = u.id
            WHERE u.organization_id = :organization_id
        """),
        {
            "organization_id": organization_id
        }
    )

    summary_stats = result.mappings().first()

if summary_stats:

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Reports Summarized",
            int(
                summary_stats["reports"] or 0
            )
        )

    with col2:

        st.metric(
            "Avg. Original Words",
            round(
                float(
                    summary_stats[
                        "avg_original_words"
                    ] or 0
                )
            )
        )

    with col3:

        st.metric(
            "Avg. Summary Words",
            round(
                float(
                    summary_stats[
                        "avg_summary_words"
                    ] or 0
                )
            )
        )

    with col4:

        st.metric(
            "Avg. Compression",
            f"{float(summary_stats['avg_compression'] or 0):.1f}%"
        )


# ============================================================
# 6. COMPLIANCE FRAMEWORK COVERAGE
# ============================================================

st.write("")
st.subheader("Compliance Framework Coverage")

with engine.connect() as connection:

    result = connection.execute(
        text("""
            SELECT
                matched_frameworks,
                severity
            FROM compliance_analysis c
            INNER JOIN users u
                ON c.user_id = u.id
            WHERE u.organization_id = :organization_id
        """),
        {
            "organization_id": organization_id
        }
    )

    compliance_rows = result.mappings().all()


if compliance_rows:

    framework_counts = {}

    for row in compliance_rows:

        frameworks = row["matched_frameworks"]

        if not frameworks:
            continue

        if isinstance(frameworks, str):

            parts = [
                x.strip()
                for x in frameworks.split(",")
                if x.strip()
            ]

            for framework in parts:

                framework_counts[framework] = (
                    framework_counts.get(
                        framework,
                        0
                    ) + 1
                )


    if framework_counts:

        compliance_df = pd.DataFrame(
            {
                "Framework": list(
                    framework_counts.keys()
                ),
                "Findings": list(
                    framework_counts.values()
                )
            }
        )

        compliance_df = compliance_df.sort_values(
            "Findings",
            ascending=False
        )

        st.bar_chart(
            compliance_df.set_index("Framework"),
            use_container_width=True
        )

    else:

        st.info(
            "No compliance frameworks have been matched yet."
        )

else:

    st.info(
        "No compliance analysis results are available."
    )


# ============================================================
# 7. EXPLAINABILITY RISK PROFILE
# ============================================================

st.write("")
st.subheader("Organization Risk Profile")

with engine.connect() as connection:

    result = connection.execute(
        text("""
            SELECT
                COUNT(*) FILTER (
                    WHERE overall_risk < 40
                ) AS low,

                COUNT(*) FILTER (
                    WHERE overall_risk >= 40
                    AND overall_risk < 70
                ) AS medium,

                COUNT(*) FILTER (
                    WHERE overall_risk >= 70
                ) AS high,

                COALESCE(
                    AVG(overall_risk),
                    0
                ) AS average_risk

            FROM explainability_analysis e

            INNER JOIN users u
                ON e.user_id = u.id

            WHERE u.organization_id = :organization_id
        """),
        {
            "organization_id": organization_id
        }
    )

    risk_stats = result.mappings().first()


if risk_stats:

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Low Risk",
            int(risk_stats["low"] or 0)
        )

    with col2:

        st.metric(
            "Medium Risk",
            int(risk_stats["medium"] or 0)
        )

    with col3:

        st.metric(
            "High Risk",
            int(risk_stats["high"] or 0)
        )

    with col4:

        st.metric(
            "Average Risk",
            f"{float(risk_stats['average_risk'] or 0):.1f}"
        )


# ============================================================
# 8. RISK COMPONENT ANALYSIS
# ============================================================

st.write("")
st.subheader("Risk Component Analysis")

with engine.connect() as connection:

    result = connection.execute(
        text("""
            SELECT
                COALESCE(
                    AVG(phishing_risk),
                    0
                ) AS phishing,

                COALESCE(
                    AVG(category_risk),
                    0
                ) AS category,

                COALESCE(
                    AVG(attack_risk),
                    0
                ) AS attack,

                COALESCE(
                    AVG(summary_risk),
                    0
                ) AS summary

            FROM explainability_analysis e

            INNER JOIN users u
                ON e.user_id = u.id

            WHERE u.organization_id = :organization_id
        """),
        {
            "organization_id": organization_id
        }
    )

    component = result.mappings().first()


risk_component_df = pd.DataFrame(
    {
        "Risk Component": [
            "Phishing",
            "Threat Category",
            "ATT&CK",
            "Summary"
        ],
        "Average Risk": [
            float(component["phishing"] or 0),
            float(component["category"] or 0),
            float(component["attack"] or 0),
            float(component["summary"] or 0)
        ]
    }
)

st.bar_chart(
    risk_component_df.set_index(
        "Risk Component"
    ),
    use_container_width=True
)
# ============================================================
# FOOTER
# ============================================================

st.write("")
st.divider()

st.caption(
    "CYBERLENS  •  ORGANIZATION SECURITY INTELLIGENCE"
)