import streamlit as st
from pathlib import Path

from sqlalchemy import text

from database import get_connection


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberLens - Analyst Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# DASHBOARD CSS
# ============================================================

css_path = (
    Path(__file__).parent.parent
    / "assets"
    / "analyst_dashboard.css"
)




# ============================================================
# SESSION CHECK
# ============================================================

if not st.session_state.get("logged_in", False):

    st.warning(
        "Please sign in to access the analyst dashboard."
    )

    if st.button(
        "Go to Login →",
        type="primary"
    ):
        st.switch_page("pages/Login.py")

    st.stop()


# ============================================================
# NAVIGATION
# ============================================================

try:

    from utils.navigation import analyst_navigation

    analyst_navigation(
        active_page="command"
    )

except Exception:
    pass


# ============================================================
# USER INFORMATION
# ============================================================

fullname = st.session_state.get(
    "fullname",
    "User"
)

username = st.session_state.get(
    "username",
    ""
)

role = st.session_state.get(
    "role",
    "Cybersecurity Analyst"
)


# ============================================================
# DATABASE HELPERS
# ============================================================

def get_table_count(conn, table_name):
    """
    Return total number of rows in a PostgreSQL table.

    Uses SQLAlchemy connection.execute().
    Does NOT use cursor().
    """

    try:

        query = text(
            f"""
            SELECT COUNT(*)
            FROM "{table_name}"
            """
        )

        result = conn.execute(query)

        value = result.scalar()

        return int(value or 0)

    except Exception:
        return 0


def table_exists(conn, table_name):
    """
    Check whether a table exists in PostgreSQL.
    """

    try:

        query = text(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = :table_name
            )
            """
        )

        result = conn.execute(
            query,
            {
                "table_name": table_name
            }
        )

        return bool(result.scalar())

    except Exception:
        return False


def get_column_names(conn, table_name):
    """
    Get column names from a PostgreSQL table.
    """

    try:

        query = text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
            AND table_name = :table_name
            ORDER BY ordinal_position
            """
        )

        result = conn.execute(
            query,
            {
                "table_name": table_name
            }
        )

        return [
            row[0]
            for row in result.fetchall()
        ]

    except Exception:
        return []


def get_high_risk_count(conn):
    """
    Calculate high-risk findings from explainability_analysis.

    Primary source:
        overall_risk >= 70

    If the table or column does not exist,
    returns 0 rather than crashing the dashboard.
    """

    try:

        if not table_exists(
            conn,
            "explainability_analysis"
        ):
            return 0

        columns = get_column_names(
            conn,
            "explainability_analysis"
        )

        if "overall_risk" not in columns:
            return 0

        query = text(
            """
            SELECT COUNT(*)
            FROM explainability_analysis
            WHERE overall_risk >= 70
            """
        )

        result = conn.execute(query)

        return int(result.scalar() or 0)

    except Exception:
        return 0


def get_recent_activity(conn, limit=10):
    """
    Retrieve recent analysis activity from the
    available module tables.

    This combines the module histories into one
    dashboard history.
    """

    activities = []

    module_tables = [
        (
            "phishing_analysis",
            "Phishing Detection",
            "phishing"
        ),
        (
            "ner_analysis",
            "Threat Entity Extraction",
            "ner"
        ),
        (
            "threat_category_analysis",
            "Threat Classification",
            "category"
        ),
        (
            "attack_analysis",
            "MITRE ATT&CK Intelligence",
            "attack"
        ),
        (
            "summary_analysis",
            "Threat Summary",
            "summary"
        ),
        (
            "explainability_analysis",
            "Risk & Explainability",
            "explainability"
        )
    ]

    for table_name, module_name, module_key in module_tables:

        try:

            if not table_exists(
                conn,
                table_name
            ):
                continue

            columns = get_column_names(
                conn,
                table_name
            )

            if not columns:
                continue

            # ------------------------------------------------
            # Find a useful timestamp column
            # ------------------------------------------------

            timestamp_column = None

            for candidate in [
                "analyzed_at",
                "created_at",
                "updated_at",
                "timestamp"
            ]:

                if candidate in columns:
                    timestamp_column = candidate
                    break

            # ------------------------------------------------
            # Find user column
            # ------------------------------------------------

            user_column = None

            for candidate in [
                "user_id",
                "userid",
                "user"
            ]:

                if candidate in columns:
                    user_column = candidate
                    break

            # ------------------------------------------------
            # Build query
            # ------------------------------------------------

            if timestamp_column:

                query = text(
                    f"""
                    SELECT
                        {timestamp_column} AS analyzed_at
                    FROM "{table_name}"
                    ORDER BY {timestamp_column} DESC
                    LIMIT :limit
                    """
                )

                result = conn.execute(
                    query,
                    {
                        "limit": limit
                    }
                )

                rows = result.fetchall()

                for row in rows:

                    activities.append(
                        {
                            "Module": module_name,
                            "Type": module_key,
                            "Analyzed At": row[0]
                        }
                    )

            else:

                query = text(
                    f"""
                    SELECT COUNT(*)
                    FROM "{table_name}"
                    """
                )

                result = conn.execute(query)

                count = int(
                    result.scalar() or 0
                )

                if count > 0:

                    activities.append(
                        {
                            "Module": module_name,
                            "Type": module_key,
                            "Analyzed At": "Historical"
                        }
                    )

        except Exception:
            continue

    # Newest first where timestamps are available

    try:

        activities.sort(
            key=lambda x: (
                x["Analyzed At"]
                if x["Analyzed At"] != "Historical"
                else ""
            ),
            reverse=True
        )

    except Exception:
        pass

    return activities[:limit]


# ============================================================
# LOAD DASHBOARD DATA
# ============================================================

@st.cache_data(ttl=15)
def load_dashboard_data():

    try:

        with get_connection() as conn:

            # ------------------------------------------------
            # EXISTING ANALYSIS TABLES
            # ------------------------------------------------

            tables = [
                "phishing_analysis",
                "ner_analysis",
                "threat_category_analysis",
                "attack_analysis",
                "summary_analysis",
                "compliance_analysis",
                "explainability_analysis"
            ]

            table_counts = {}

            for table in tables:

                table_counts[table] = (
                    get_table_count(
                        conn,
                        table
                    )
                )

            # ------------------------------------------------
            # TOTAL MODULE ANALYSES
            # ------------------------------------------------

            total_analyses = sum(
                table_counts.values()
            )

            # ------------------------------------------------
            # REPORTS ANALYZED
            #
            # Summary reports are the main report-level
            # analysis source.
            # ------------------------------------------------

            reports_analyzed = (
                table_counts.get(
                    "summary_analysis",
                    0
                )
            )

            # ------------------------------------------------
            # THREAT DETECTIONS
            #
            # Phishing analyses represent explicit
            # detection events.
            #
            # We also include explainability decisions
            # because those are final risk assessments.
            # ------------------------------------------------

            threats_detected = (
                table_counts.get(
                    "phishing_analysis",
                    0
                )
                +
                table_counts.get(
                    "explainability_analysis",
                    0
                )
            )

            # ------------------------------------------------
            # HIGH-RISK FINDINGS
            # ------------------------------------------------

            high_risk = get_high_risk_count(
                conn
            )

            # ------------------------------------------------
            # RECENT HISTORY
            # ------------------------------------------------

            recent_activity = get_recent_activity(
                conn,
                limit=15
            )

            return {
                "total_analyses": total_analyses,
                "threats_detected": threats_detected,
                "reports_analyzed": reports_analyzed,
                "high_risk": high_risk,
                "table_counts": table_counts,
                "recent_activity": recent_activity
            }

    except Exception as e:

        return {
            "error": str(e),
            "total_analyses": 0,
            "threats_detected": 0,
            "reports_analyzed": 0,
            "high_risk": 0,
            "table_counts": {},
            "recent_activity": []
        }


# ============================================================
# LOAD DATA
# ============================================================

dashboard_data = load_dashboard_data()


# ============================================================
# DATABASE ERROR
# ============================================================

if "error" in dashboard_data:

    st.error(
        "Unable to load dashboard data."
    )

    st.caption(
        f"Database details: "
        f"{dashboard_data['error']}"
    )


# ============================================================
# HEADER
# ============================================================

st.caption(
    "CYBERLENS  /  ANALYST OPERATIONS"
)

col1, col2 = st.columns(
    [5, 1]
)

with col1:

    st.title(
        "Analyst Dashboard"
    )

    st.write(
        f"Welcome back, **{fullname}**."
    )

    st.caption(
        f"Signed in as {role}  •  @{username}"
    )


with col2:

    st.write("")

    if st.button(
        "Sign Out",
        use_container_width=True
    ):

        st.session_state[
            "logged_in"
        ] = False

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

        st.switch_page(
            "app.py"
        )


st.divider()


# ============================================================
# OPERATIONS OVERVIEW
# ============================================================

st.caption(
    "OPERATIONS OVERVIEW"
)

st.header(
    "Cyber Intelligence Workspace"
)

st.write(
    "Monitor historical CyberLens activity across "
    "phishing detection, threat intelligence, "
    "classification, ATT&CK analysis, summarization, "
    "compliance and explainability."
)

st.write("")


# ============================================================
# QUICK STATISTICS
# ============================================================

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Total Analyses",
        f"{dashboard_data['total_analyses']:,}",
        help=(
            "Total analysis records stored across "
            "CyberLens module tables."
        )
    )


with col2:

    st.metric(
        "Threat Findings",
        f"{dashboard_data['threats_detected']:,}",
        help=(
            "Stored phishing detection and "
            "risk-assessment findings."
        )
    )


with col3:

    st.metric(
        "Reports Analyzed",
        f"{dashboard_data['reports_analyzed']:,}",
        help=(
            "Threat reports processed by "
            "the summarization module."
        )
    )


with col4:

    st.metric(
        "High Risk",
        f"{dashboard_data['high_risk']:,}",
        help=(
            "Explainability assessments with "
            "an overall risk score of 70 or higher."
        )
    )


st.write("")
st.divider()


# ============================================================
# HISTORICAL MODULE COUNTS
# ============================================================

st.caption(
    "PLATFORM ACTIVITY"
)

st.header(
    "Analysis History"
)

st.write(
    "Total stored activity across the CyberLens "
    "analysis pipeline."
)

st.write("")


counts = dashboard_data.get(
    "table_counts",
    {}
)


# ------------------------------------------------------------
# Display module counts
# ------------------------------------------------------------

col1, col2, col3 = st.columns(3)

with col1:

    st.metric(
        "Phishing Intel",
        f"{counts.get('phishing_analysis', 0):,}"
    )

with col2:

    st.metric(
        "Entity Intel",
        f"{counts.get('ner_analysis', 0):,}"
    )

with col3:

    st.metric(
        "Threat Classification",
        f"{counts.get('threat_category_analysis', 0):,}"
    )


st.write("")


col1, col2, col3 = st.columns(3)

with col1:

    st.metric(
        "MITRE ATT&CK",
        f"{counts.get('attack_analysis', 0):,}"
    )

with col2:

    st.metric(
        "Threat Summary",
        f"{counts.get('summary_analysis', 0):,}"
    )

with col3:

    st.metric(
        "Compliance Intel",
        f"{counts.get('compliance_analysis', 0):,}"
    )


st.write("")


col1, col2, col3 = st.columns(3)

with col2:

    st.metric(
        "Risk & Explainability",
        f"{counts.get('explainability_analysis', 0):,}"
    )


st.write("")
st.divider()


# ============================================================
# ANALYSIS MODULES
# ============================================================

st.caption(
    "ANALYSIS MODULES"
)

st.header(
    "Cyber Intelligence Modules"
)

st.write(
    "Select a module to begin an analysis."
)

st.write("")


# ============================================================
# ROW 1
# ============================================================

col1, col2, col3 = st.columns(
    3,
    gap="large"
)


with col1:

    with st.container(
        border=True
    ):

        st.caption(
            "MODULE 01"
        )

        st.markdown(
            "### 🔎 Phishing Detection"
        )

        st.write(
            "Analyze URLs and identify potentially "
            "phishing or malicious websites."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="dashboard_phishing",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module1_Phishing.py"
            )


with col2:

    with st.container(
        border=True
    ):

        st.caption(
            "MODULE 02"
        )

        st.markdown(
            "### 🧠 Threat Entity Extraction"
        )

        st.write(
            "Extract cybersecurity entities such as "
            "threat actors, malware, vulnerabilities "
            "and organizations."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="dashboard_ner",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module2_NER.py"
            )


with col3:

    with st.container(
        border=True
    ):

        st.caption(
            "MODULE 03"
        )

        st.markdown(
            "### 🏷️ Threat Classification"
        )

        st.write(
            "Classify cybersecurity information into "
            "relevant threat categories."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="dashboard_category",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module3_Threat_Category.py"
            )


# ============================================================
# ROW 2
# ============================================================

st.write("")

col1, col2, col3 = st.columns(
    3,
    gap="large"
)


with col1:

    with st.container(
        border=True
    ):

        st.caption(
            "MODULE 04"
        )

        st.markdown(
            "### 🎯 MITRE ATT&CK"
        )

        st.write(
            "Map extracted threat intelligence to "
            "MITRE ATT&CK tactics and techniques."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="dashboard_attack",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module4_ATTACK.py"
            )


with col2:

    with st.container(
        border=True
    ):

        st.caption(
            "MODULE 05"
        )

        st.markdown(
            "### 📝 Threat Summary"
        )

        st.write(
            "Generate concise summaries from "
            "lengthy cybersecurity reports."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="dashboard_summary",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module5_Summary.py"
            )


with col3:

    with st.container(
        border=True
    ):

        st.caption(
            "MODULE 06"
        )

        st.markdown(
            "### ⚖️ Compliance Support"
        )

        st.write(
            "Identify relevant regulatory requirements "
            "and compliance-oriented actions."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="dashboard_compliance",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module6_Compliance.py"
            )


# ============================================================
# ROW 3
# ============================================================

st.write("")

col1, col2, col3 = st.columns(
    [1, 2, 1]
)

with col2:

    with st.container(
        border=True
    ):

        st.caption(
            "MODULE 07"
        )

        st.markdown(
            "### 🔍 Explainability"
        )

        st.write(
            "Understand the reasoning behind "
            "machine-learning based threat predictions "
            "using explainable AI."
        )

        st.write("")

        if st.button(
            "Open Module →",
            key="dashboard_explainability",
            use_container_width=True
        ):

            st.switch_page(
                "pages/Module7_Explainability.py"
            )


# ============================================================
# ANALYST WORKFLOW
# ============================================================

st.write("")
st.divider()

st.caption(
    "ANALYST WORKFLOW"
)

st.header(
    "From Threat Data to Intelligence"
)

st.write("")


col1, col2, col3, col4 = st.columns(4)


with col1:

    st.markdown("### 01")

    st.markdown(
        "**DETECT**"
    )

    st.caption(
        "Identify suspicious URLs and threats."
    )


with col2:

    st.markdown("### 02")

    st.markdown(
        "**EXTRACT**"
    )

    st.caption(
        "Extract entities, TTPs and intelligence."
    )


with col3:

    st.markdown("### 03")

    st.markdown(
        "**UNDERSTAND**"
    )

    st.caption(
        "Summarize, classify and map threats."
    )


with col4:

    st.markdown("### 04")

    st.markdown(
        "**EXPLAIN**"
    )

    st.caption(
        "Provide interpretable security insights."
    )


# ============================================================
# RECENT ACTIVITY
# ============================================================

st.write("")
st.divider()

st.caption(
    "RECENT ACTIVITY"
)

st.header(
    "Analysis History"
)


recent_activity = dashboard_data.get(
    "recent_activity",
    []
)


if recent_activity:

    for activity in recent_activity:

        module_name = activity.get(
            "Module",
            "Analysis"
        )

        analyzed_at = activity.get(
            "Analyzed At",
            ""
        )

        col1, col2 = st.columns(
            [4, 2]
        )

        with col1:

            st.write(
                f"**{module_name}**"
            )

        with col2:

            if analyzed_at:
                st.caption(
                    str(analyzed_at)
                )

else:

    st.info(
        "No analysis activity has been recorded yet."
    )


# ============================================================
# FOOTER
# ============================================================

st.write("")
st.divider()

st.caption(
    "CYBERLENS  •  ANALYST OPERATIONS"
)

st.caption(
    "NLP-based cyber intelligence and explainable "
    "threat analysis."
)