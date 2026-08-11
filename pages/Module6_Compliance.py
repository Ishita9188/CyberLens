# ============================================================
# CYBERLENS - MODULE 6
# COMPLIANCE ANALYSIS & RECOMMENDATION
# ============================================================

import streamlit as st
import pandas as pd
import re
import ast
import json
from pathlib import Path
from datetime import datetime
from sqlalchemy import text
from utils.navigation import analyst_navigation

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberLens - Compliance Analysis",
    page_icon="⚖️",
    layout="wide"
)


# ============================================================
# DATABASE
# ============================================================

try:
    from database import get_connection
except Exception as e:
    st.error(f"Unable to import database connection: {e}")
    st.stop()


# ============================================================
# SESSION / USER
# ============================================================

user_id = st.session_state.get("user_id")

if not user_id:
    st.warning(
        "User session not found. Please log in again to access Module 6."
    )
    st.stop()

analyst_navigation(
    active_page="threat"
)
# ============================================================
# KNOWLEDGE BASE PATH
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

KNOWLEDGE_BASE_PATH = (
    BASE_DIR
    / "datasets"
    / "compliance"
    / "compliance_knowledge_base.csv"
)


# ============================================================
# TITLE
# ============================================================

st.title("⚖️ CyberLens - Compliance Analysis")

st.markdown(
    """
    This module retrieves previously analysed threat intelligence from
    **Phishing Detection, NER, Threat Category, ATT&CK and Threat Summary**
    modules and maps identified cybersecurity issues against the
    CyberLens Compliance Knowledge Base.
    """
)


# ============================================================
# LOAD COMPLIANCE KNOWLEDGE BASE
# ============================================================

@st.cache_data
def load_knowledge_base():

    if not KNOWLEDGE_BASE_PATH.exists():
        return None

    try:

        df = pd.read_csv(
            KNOWLEDGE_BASE_PATH,
            encoding="utf-8"
        )

        df = df.fillna("")

        return df

    except Exception as e:

        st.error(
            f"Unable to load compliance knowledge base: {e}"
        )

        return None


knowledge_base = load_knowledge_base()


if knowledge_base is None:

    st.error(
        f"""
        Compliance knowledge base not found.

        Expected location:

        `{KNOWLEDGE_BASE_PATH}`
        """
    )

    st.stop()


# ============================================================
# KNOWLEDGE BASE INFORMATION
# ============================================================

with st.expander("📚 Compliance Knowledge Base", expanded=False):

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Total Rules",
            len(knowledge_base)
        )

    with col2:
        st.metric(
            "Frameworks",
            knowledge_base["framework"].nunique()
            if "framework" in knowledge_base.columns
            else 0
        )

    with col3:
        st.metric(
            "High/Critical Rules",
            len(
                knowledge_base[
                    knowledge_base["severity"]
                    .astype(str)
                    .str.lower()
                    .isin(["high", "critical"])
                ]
            )
            if "severity" in knowledge_base.columns
            else 0
        )

    if "framework" in knowledge_base.columns:

        st.write("### Frameworks included")

        frameworks = (
            knowledge_base["framework"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        st.write(", ".join(frameworks))


# ============================================================
# DATABASE HELPERS
# ============================================================

def get_connection_safe():

    """
    get_connection() in this project returns a SQLAlchemy Connection.

    Therefore:
        connection.execute(text(...))

    is used instead of:
        connection.cursor()
    """

    return get_connection()


# ============================================================
# CHECK TABLE EXISTS
# ============================================================

def table_exists(connection, table_name):

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

    result = connection.execute(
        query,
        {"table_name": table_name}
    )

    return bool(result.scalar())


# ============================================================
# GET TABLE COLUMNS
# ============================================================

def get_table_columns(connection, table_name):

    query = text(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
        AND table_name = :table_name
        ORDER BY ordinal_position
        """
    )

    result = connection.execute(
        query,
        {"table_name": table_name}
    )

    return [
        row[0]
        for row in result.fetchall()
    ]


# ============================================================
# FIND BEST TEXT COLUMN
# ============================================================

def find_text_column(columns):

    preferred_columns = [

        "threat_text",
        "threat_description",
        "threat",
        "description",
        "text",
        "report_text",
        "input_text",
        "url",
        "threat_url",
        "summary"

    ]

    lower_map = {
        c.lower(): c
        for c in columns
    }

    for preferred in preferred_columns:

        if preferred in lower_map:

            return lower_map[preferred]

    # fallback

    text_candidates = [

        c for c in columns

        if any(
            word in c.lower()
            for word in [
                "text",
                "description",
                "report",
                "content",
                "summary",
                "url"
            ]
        )

    ]

    if text_candidates:

        return text_candidates[0]

    return None


# ============================================================
# RETRIEVE ANALYSES
# ============================================================

def retrieve_user_analyses(user_id):

    """
    Retrieves all available analysis records belonging to
    the currently logged-in user.

    Tables:

        phishing_analysis
        ner_analysis
        threat_category_analysis
        attack_analysis
        summary_analysis
    """

    tables = [

        ("phishing_analysis", "Phishing Detection"),
        ("ner_analysis", "NER"),
        ("threat_category_analysis", "Threat Category"),
        ("attack_analysis", "MITRE ATT&CK"),
        ("summary_analysis", "Threat Summary")

    ]

    records = []

    connection = None

    try:

        connection = get_connection_safe()

        for table_name, module_name in tables:

            try:

                if not table_exists(
                    connection,
                    table_name
                ):

                    continue

                columns = get_table_columns(
                    connection,
                    table_name
                )

                if not columns:
                    continue

                text_column = find_text_column(
                    columns
                )

                if not text_column:
                    continue

                # Determine whether user_id exists

                has_user_id = (
                    "user_id" in columns
                )

                # Determine ID column

                id_column = (
                    "id"
                    if "id" in columns
                    else None
                )

                # Determine timestamp column

                timestamp_column = None

                for candidate in [
                    "analyzed_at",
                    "created_at",
                    "timestamp"
                ]:

                    if candidate in columns:

                        timestamp_column = candidate
                        break

                select_columns = []

                if id_column:

                    select_columns.append(
                        f'"{id_column}"'
                    )

                if has_user_id:

                    select_columns.append(
                        '"user_id"'
                    )

                select_columns.append(
                    f'"{text_column}"'
                )

                if timestamp_column:

                    select_columns.append(
                        f'"{timestamp_column}"'
                    )

                query_string = f"""
                    SELECT
                        {", ".join(select_columns)}
                    FROM "{table_name}"
                """

                params = {}

                if has_user_id:

                    query_string += """
                        WHERE user_id = :user_id
                    """

                    params["user_id"] = user_id

                query_string += " ORDER BY 1 DESC"

                query = text(query_string)

                result = connection.execute(
                    query,
                    params
                )

                rows = result.fetchall()

                for row in rows:

                    row_data = dict(
                        row._mapping
                    )

                    threat_text = row_data.get(
                        text_column
                    )

                    if threat_text is None:

                        continue

                    threat_text = str(
                        threat_text
                    ).strip()

                    if not threat_text:

                        continue

                    records.append({

                        "module": module_name,

                        "table": table_name,

                        "analysis_id":
                            row_data.get(
                                id_column
                            )
                            if id_column
                            else None,

                        "threat_text":
                            threat_text,

                        "analyzed_at":
                            row_data.get(
                                timestamp_column
                            )
                            if timestamp_column
                            else None

                    })

            except Exception as e:

                # One missing/problematic table should not
                # stop the other four modules.

                st.warning(
                    f"Could not retrieve {table_name}: {e}"
                )

        return records

    except Exception as e:

        st.error(
            f"Unable to retrieve analyses from PostgreSQL: {e}"
        )

        return []

    finally:

        # SQLAlchemy Connection may or may not need explicit close
        # depending on database.py implementation.

        try:

            if connection is not None:
                connection.close()

        except Exception:
            pass


# ============================================================
# CYBERSECURITY KEYWORDS
# ============================================================

CYBERSECURITY_TERMS = [

    # General
    "cybersecurity",
    "cyber attack",
    "cyber threat",
    "threat intelligence",
    "threat actor",
    "attack vector",
    "malicious",
    "compromise",
    "security incident",
    "security breach",
    "incident response",

    # Phishing
    "phishing",
    "spear phishing",
    "spearphishing",
    "credential phishing",
    "email phishing",
    "spoofing",
    "spoofed",
    "social engineering",
    "phishing link",
    "malicious link",
    "malicious attachment",
    "qr code",

    # Malware
    "malware",
    "ransomware",
    "trojan",
    "virus",
    "worm",
    "spyware",
    "rootkit",
    "backdoor",
    "botnet",
    "payload",
    "loader",
    "dropper",

    # Credentials
    "credential",
    "credentials",
    "credential theft",
    "password",
    "password theft",
    "account compromise",
    "account takeover",
    "authentication",
    "authorization",
    "mfa",
    "multi-factor authentication",
    "2fa",
    "token",
    "session",
    "access token",
    "privilege",
    "privilege escalation",

    # Vulnerabilities
    "vulnerability",
    "vulnerabilities",
    "exploit",
    "exploitation",
    "zero-day",
    "zero day",
    "cve",
    "unpatched",
    "patch",
    "security flaw",
    "remote code execution",
    "rce",

    # Network
    "ip address",
    "ip",
    "domain",
    "dns",
    "mx record",
    "smtp",
    "http",
    "https",
    "firewall",
    "proxy",
    "vpn",
    "network",
    "port",
    "traffic",
    "packet",
    "command and control",
    "c2",
    "beacon",

    # Email
    "email",
    "email address",
    "mailbox",
    "email header",
    "spf",
    "dkim",
    "dmarc",
    "smtp",
    "mail exchanger",

    # Data
    "data breach",
    "data leak",
    "data loss",
    "data theft",
    "data exfiltration",
    "exfiltration",
    "personal data",
    "sensitive data",
    "confidential information",
    "customer data",
    "user data",

    # Attack techniques
    "lateral movement",
    "persistence",
    "discovery",
    "reconnaissance",
    "command execution",
    "code execution",
    "execution",
    "initial access",
    "defense evasion",
    "credential access",
    "collection",
    "impact",

    # Security controls
    "encryption",
    "access control",
    "least privilege",
    "security monitoring",
    "logging",
    "audit log",
    "siem",
    "endpoint detection",
    "edr",
    "ids",
    "ips",
    "backup",
    "security policy",

    # Compliance
    "privacy",
    "compliance",
    "regulation",
    "dpdp",
    "gdpr",
    "cert-in",
    "incident reporting",
    "data protection",

]


# ============================================================
# NORMALIZE TEXT
# ============================================================

def normalize_text(text_value):

    if not text_value:

        return ""

    text_value = str(
        text_value
    ).lower()

    text_value = re.sub(
        r"\s+",
        " ",
        text_value
    )

    return text_value.strip()


# ============================================================
# EXTRACT CYBERSECURITY TERMS
# ============================================================

def extract_cybersecurity_terms(text_value):

    normalized = normalize_text(
        text_value
    )

    found = []

    for term in CYBERSECURITY_TERMS:

        if term.lower() in normalized:

            found.append(term)

    return sorted(
        set(found)
    )


# ============================================================
# MATCH KNOWLEDGE BASE
# ============================================================

def match_compliance_rules(
    threat_text,
    knowledge_base
):

    normalized_text = normalize_text(
        threat_text
    )

    matches = []

    for _, rule in knowledge_base.iterrows():

        keywords_raw = str(
            rule.get(
                "evidence_keywords",
                ""
            )
        )

        if not keywords_raw:

            continue

        keywords = [

            k.strip().lower()

            for k in re.split(
                r"[;,|]",
                keywords_raw
            )

            if k.strip()

        ]

        matched_keywords = []

        for keyword in keywords:

            if keyword in normalized_text:

                matched_keywords.append(
                    keyword
                )

        if matched_keywords:

            score = len(
                matched_keywords
            )

            matches.append({

                "framework":
                    str(
                        rule.get(
                            "framework",
                            ""
                        )
                    ),

                "source_type":
                    str(
                        rule.get(
                            "source_type",
                            ""
                        )
                    ),

                "rule_reference":
                    str(
                        rule.get(
                            "rule_reference",
                            ""
                        )
                    ),

                "requirement":
                    str(
                        rule.get(
                            "requirement",
                            ""
                        )
                    ),

                "required_procedure":
                    str(
                        rule.get(
                            "required_procedure",
                            ""
                        )
                    ),

                "recommendation":
                    str(
                        rule.get(
                            "recommendation",
                            ""
                        )
                    ),

                "severity":
                    str(
                        rule.get(
                            "severity",
                            ""
                        )
                    ),

                "source_url":
                    str(
                        rule.get(
                            "source_url",
                            ""
                        )
                    ),

                "matched_keywords":
                    matched_keywords,

                "score":
                    score

            })

    # Sort strongest matches first

    matches.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    # Avoid displaying excessive duplicate rules

    unique_matches = []

    seen = set()

    for match in matches:

        key = (
            match["framework"],
            match["rule_reference"]
        )

        if key not in seen:

            seen.add(key)

            unique_matches.append(
                match
            )

    return unique_matches


# ============================================================
# CALCULATE OVERALL SEVERITY
# ============================================================

def calculate_severity(matches):

    if not matches:

        return "Low"

    severities = [

        str(
            m.get(
                "severity",
                ""
            )
        ).lower()

        for m in matches

    ]

    if "critical" in severities:

        return "Critical"

    if "high" in severities:

        return "High"

    if "medium" in severities:

        return "Medium"

    return "Low"


# ============================================================
# LOG COMPLIANCE ANALYSIS
# ============================================================

def log_compliance_analysis(
    user_id,
    source_module,
    source_analysis_id,
    threat_text,
    identified_issues,
    matches,
    overall_severity
):

    connection = None

    try:

        connection = get_connection_safe()

        # Convert rule information to JSON

        applicable_rules = json.dumps(
            [
                {
                    "framework":
                        m["framework"],

                    "rule_reference":
                        m["rule_reference"],

                    "matched_keywords":
                        m["matched_keywords"]

                }

                for m in matches
            ],
            ensure_ascii=False
        )

        legal_requirements = "\n\n".join(

            [

                (
                    f"{m['framework']} - "
                    f"{m['rule_reference']}:\n"
                    f"{m['requirement']}"
                )

                for m in matches

            ]

        )

        procedures = "\n\n".join(

            [

                (
                    f"{m['framework']}:\n"
                    f"{m['required_procedure']}"
                )

                for m in matches

            ]

        )

        recommendations = "\n\n".join(

            [

                (
                    f"{m['framework']}:\n"
                    f"{m['recommendation']}"
                )

                for m in matches

            ]

        )

        frameworks = ", ".join(

            sorted(
                set(
                    m["framework"]
                    for m in matches
                )
            )

        )

        references = "\n".join(

            sorted(
                set(
                    m["source_url"]
                    for m in matches
                    if m["source_url"]
                )
            )

        )

        insert_query = text(
            """
            INSERT INTO compliance_analysis
            (
                user_id,
                source_module,
                source_analysis_id,
                threat_text,
                identified_issues,
                applicable_rules,
                legal_requirements,
                recommended_procedures,
                recommendations,
                matched_frameworks,
                severity,
                source_references,
                analyzed_at
            )
            VALUES
            (
                :user_id,
                :source_module,
                :source_analysis_id,
                :threat_text,
                :identified_issues,
                :applicable_rules,
                :legal_requirements,
                :recommended_procedures,
                :recommendations,
                :matched_frameworks,
                :severity,
                :source_references,
                :analyzed_at
            )
            """
        )

        connection.execute(
            insert_query,
            {
                "user_id":
                    user_id,

                "source_module":
                    source_module,

                "source_analysis_id":
                    source_analysis_id,

                "threat_text":
                    threat_text,

                "identified_issues":
                    ", ".join(
                        identified_issues
                    ),

                "applicable_rules":
                    applicable_rules,

                "legal_requirements":
                    legal_requirements,

                "recommended_procedures":
                    procedures,

                "recommendations":
                    recommendations,

                "matched_frameworks":
                    frameworks,

                "severity":
                    overall_severity,

                "source_references":
                    references,

                "analyzed_at":
                    datetime.now()

            }
        )

        # SQLAlchemy Connection does not always expose commit().
        # In that case transaction context is managed by database.py.
        #
        # If commit exists, use it.

        if hasattr(
            connection,
            "commit"
        ):

            connection.commit()

        return True, None

    except Exception as e:

        try:

            if connection is not None:

                if hasattr(
                    connection,
                    "rollback"
                ):

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
# RETRIEVE REPORTS
# ============================================================

if "compliance_reports" not in st.session_state:

    st.session_state[
        "compliance_reports"
    ] = retrieve_user_analyses(
        user_id
    )


reports = st.session_state[
    "compliance_reports"
]


# ============================================================
# REPORT SUMMARY
# ============================================================

st.subheader("📊 Previously Analysed Reports")

if not reports:

    st.info(
        """
        No analysed reports were found for the logged-in user.

        Run at least one analysis in:

        • Module 1 - Phishing Detection  
        • Module 2 - NER  
        • Module 3 - Threat Category  
        • Module 4 - MITRE ATT&CK  
        • Module 5 - Threat Summary
        """
    )

else:

    report_df = pd.DataFrame(
        reports
    )

    c1, c2, c3 = st.columns(3)

    with c1:

        st.metric(
            "Total Reports",
            len(reports)
        )

    with c2:

        st.metric(
            "Modules",
            report_df[
                "module"
            ].nunique()
        )

    with c3:

        st.metric(
            "Logged-in User",
            str(user_id)
        )

    st.dataframe(
        report_df[
            [
                "module",
                "table",
                "analysis_id",
                "analyzed_at"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# REFRESH BUTTON
# ============================================================

if st.button(
    "🔄 Refresh Analysed Reports"
):

    st.session_state[
        "compliance_reports"
    ] = retrieve_user_analyses(
        user_id
    )

    st.rerun()


# ============================================================
# SELECT REPORT
# ============================================================

if reports:

    st.divider()

    st.subheader(
        "🔎 Select Report for Compliance Analysis"
    )

    report_options = []

    for index, report in enumerate(
        reports
    ):

        preview = (
            report["threat_text"]
            .replace("\n", " ")
            [:100]
        )

        label = (
            f"{index + 1}. "
            f"{report['module']} | "
            f"{preview}..."
        )

        report_options.append(
            label
        )

    selected_index = st.selectbox(
        "Choose an analysed report",
        range(len(report_options)),
        format_func=lambda x:
            report_options[x]
    )

    selected_report = reports[
        selected_index
    ]

    # ========================================================
    # DISPLAY SOURCE REPORT
    # ========================================================

    with st.expander(
        "📄 View Original Analysed Report",
        expanded=False
    ):

        st.write(
            selected_report[
                "threat_text"
            ]
        )

    # ========================================================
    # RUN COMPLIANCE ANALYSIS
    # ========================================================

    if st.button(
        "⚖️ Analyse Compliance",
        type="primary"
    ):

        threat_text = selected_report[
            "threat_text"
        ]

        with st.spinner(
            "Analysing cybersecurity compliance..."
        ):

            # ------------------------------------------------
            # Extract cybersecurity terms
            # ------------------------------------------------

            cybersecurity_terms = (
                extract_cybersecurity_terms(
                    threat_text
                )
            )

            # ------------------------------------------------
            # Match compliance rules
            # ------------------------------------------------

            matches = match_compliance_rules(
                threat_text,
                knowledge_base
            )

            # ------------------------------------------------
            # Severity
            # ------------------------------------------------

            overall_severity = (
                calculate_severity(
                    matches
                )
            )

            # ------------------------------------------------
            # Identified issues
            # ------------------------------------------------

            identified_issues = []

            for match in matches:

                if (
                    match["rule_reference"]
                    and
                    match["rule_reference"]
                    not in identified_issues
                ):

                    identified_issues.append(
                        match[
                            "rule_reference"
                        ]
                    )

            # ------------------------------------------------
            # Store result in session
            # ------------------------------------------------

            compliance_result = {

                "threat_text":
                    threat_text,

                "cybersecurity_terms":
                    cybersecurity_terms,

                "matches":
                    matches,

                "severity":
                    overall_severity,

                "identified_issues":
                    identified_issues

            }

            st.session_state[
                "last_compliance_result"
            ] = compliance_result

            # ------------------------------------------------
            # PostgreSQL logging
            # ------------------------------------------------

            if matches:

                success, error = (
                    log_compliance_analysis(

                        user_id=user_id,

                        source_module=
                            selected_report[
                                "module"
                            ],

                        source_analysis_id=
                            selected_report[
                                "analysis_id"
                            ],

                        threat_text=
                            threat_text,

                        identified_issues=
                            identified_issues,

                        matches=
                            matches,

                        overall_severity=
                            overall_severity

                    )
                )

                if success:

                    st.success(
                        "Compliance analysis logged successfully."
                    )

                else:

                    st.warning(
                        "Compliance analysis completed, "
                        f"but PostgreSQL logging failed: {error}"
                    )

            st.success(
                "Compliance analysis completed."
            )


# ============================================================
# DISPLAY LAST RESULT
# ============================================================

if (
    "last_compliance_result"
    in st.session_state
):

    result = st.session_state[
        "last_compliance_result"
    ]

    st.divider()

    st.header(
        "⚖️ Compliance Assessment"
    )

    # ========================================================
    # OVERVIEW
    # ========================================================

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Overall Severity",
            result["severity"]
        )

    with col2:

        st.metric(
            "Matched Rules",
            len(
                result["matches"]
            )
        )

    with col3:

        st.metric(
            "Cybersecurity Terms",
            len(
                result[
                    "cybersecurity_terms"
                ]
            )
        )

    # ========================================================
    # CYBERSECURITY TERMS
    # ========================================================

    st.subheader(
        "🔐 Identified Cybersecurity Terms"
    )

    if result[
        "cybersecurity_terms"
    ]:

        st.write(
            ", ".join(
                result[
                    "cybersecurity_terms"
                ]
            )
        )

    else:

        st.info(
            "No predefined cybersecurity terms were detected."
        )

    # ========================================================
    # MATCHED COMPLIANCE RULES
    # ========================================================

    st.subheader(
        "📜 Applicable Rules / Laws / Frameworks"
    )

    if not result["matches"]:

        st.warning(
            """
            No matching compliance rule was found
            in the current knowledge base.

            This does NOT mean the report is compliant.
            It means that the current knowledge base did
            not contain a sufficiently matching rule.
            """
        )

    else:

        for number, match in enumerate(
            result["matches"],
            start=1
        ):

            severity = match[
                "severity"
            ]

            with st.container(
                border=True
            ):

                st.markdown(
                    f"### {number}. "
                    f"{match['framework']}"
                )

                c1, c2, c3 = st.columns(3)

                with c1:

                    st.write(
                        "**Source Type**"
                    )

                    st.write(
                        match[
                            "source_type"
                        ]
                    )

                with c2:

                    st.write(
                        "**Rule / Issue**"
                    )

                    st.write(
                        match[
                            "rule_reference"
                        ]
                    )

                with c3:

                    st.write(
                        "**Severity**"
                    )

                    st.write(
                        severity
                    )

                st.write(
                    "**Matched Evidence:**"
                )

                st.write(
                    ", ".join(
                        match[
                            "matched_keywords"
                        ]
                    )
                )

                st.write(
                    "**Requirement:**"
                )

                st.write(
                    match[
                        "requirement"
                    ]
                )

                st.write(
                    "**Required Procedure:**"
                )

                st.write(
                    match[
                        "required_procedure"
                    ]
                )

                st.write(
                    "**Recommended Solution:**"
                )

                st.success(
                    match[
                        "recommendation"
                    ]
                )

                if match[
                    "source_url"
                ]:

                    st.markdown(
                        "**Official / Reference Source:**"
                    )

                    st.markdown(
                        match[
                            "source_url"
                        ]
                    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    """
    CyberLens Module 6 maps detected cybersecurity issues
    against the configured compliance knowledge base.
    The results are intended for compliance-support and
    decision-support purposes and should not be treated
    as legal advice.
    """
)