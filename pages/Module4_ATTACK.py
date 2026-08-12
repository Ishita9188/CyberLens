import streamlit as st
import json
import re
from pathlib import Path
from datetime import datetime
from database import get_connection
from utils.theme import load_theme
from utils.navigation import analyst_navigation
load_theme()

st.set_page_config(
    page_title="CyberLens - MITRE ATT&CK Mapping",
    page_icon="🧩",
    layout="wide",
    initial_sidebar_state="collapsed"
)
if not st.session_state.get("logged_in", False):
    st.error("Please login to access CyberLens.")
    st.stop()
analyst_navigation(
    active_page="threat"
)
USER_ID = st.session_state.get("user_id")
BASE_DIR = Path(__file__).resolve().parent.parent

ATTACK_PATH = (
    BASE_DIR
    / "datasets"
    / "attack"
    / "enterprise-attack.json"
)
@st.cache_resource
def load_attack_data():

    if not ATTACK_PATH.exists():
        return None

    with open(
        ATTACK_PATH,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


try:

    attack_data = load_attack_data()

    if attack_data is None:

        st.error(
            "MITRE ATT&CK dataset was not found."
        )

        st.info(
            f"Expected file:\n{ATTACK_PATH}"
        )

        st.stop()

except Exception as e:

    st.error(
        f"Unable to load MITRE ATT&CK dataset: {e}"
    )

    st.stop()
attack_objects = attack_data.get("objects", [])

techniques = []
tactics = []
groups = []
software = []

for obj in attack_objects:

    obj_type = obj.get("type")

    if obj_type == "attack-pattern":

        if obj.get("revoked", False):
            continue

        if obj.get("x_mitre_deprecated", False):
            continue

        techniques.append(obj)

    elif obj_type == "x-mitre-tactic":

        if obj.get("revoked", False):
            continue

        if obj.get("x_mitre_deprecated", False):
            continue

        tactics.append(obj)

    elif obj_type == "intrusion-set":

        groups.append(obj)

    elif obj_type == "malware":

        software.append(obj)
technique_index = {}

for technique in techniques:

    name = technique.get(
        "name",
        ""
    ).lower()

    technique_index[name] = technique
def get_attack_id(technique):

    external_refs = technique.get(
        "external_references",
        []
    )

    for ref in external_refs:

        if ref.get("source_name") == "mitre-attack":

            external_id = ref.get(
                "external_id"
            )

            if external_id:
                return external_id

    return "N/A"


def get_technique_description(technique):

    description = technique.get(
        "description",
        ""
    )

    # Remove basic STIX formatting
    description = re.sub(
        r"<[^>]+>",
        "",
        description
    )

    return description.strip()


def get_tactics(technique):

    kill_chain_phases = technique.get(
        "kill_chain_phases",
        []
    )

    result = []

    for phase in kill_chain_phases:

        if phase.get("kill_chain_name") == "mitre-attack":

            phase_name = phase.get(
                "phase_name",
                ""
            )

            if phase_name:

                result.append(
                    phase_name.replace("-", " ").title()
                )

    return result


def normalize_text(text):

    text = text.lower()

    text = re.sub(
        r"[^a-z0-9\s\-]",
        " ",
        text
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()
CYBER_KEYWORDS = {

    "powershell",
    "cmd",
    "command shell",
    "scripting",
    "phishing",
    "spearphishing",
    "attachment",
    "link",
    "credential",
    "credentials",
    "password",
    "malware",
    "ransomware",
    "trojan",
    "backdoor",
    "remote desktop",
    "rdp",
    "ssh",
    "vpn",
    "exploit",
    "vulnerability",
    "privilege escalation",
    "lateral movement",
    "data exfiltration",
    "exfiltration",
    "download",
    "execute",
    "execution",
    "obfuscated",
    "encoded",
    "scheduled task",
    "service",
    "registry",
    "wmi",
    "mac address",
    "dns",
    "web shell",
    "email",
    "spearphishing",
    "brute force",
    "valid accounts",
    "api",
    "browser",
    "process",
    "shell",
    "remote access"
}


def extract_keywords(text):

    normalized = normalize_text(text)

    found = []

    for keyword in CYBER_KEYWORDS:

        if keyword in normalized:

            found.append(keyword)

    return sorted(
        found,
        key=len,
        reverse=True
    )
def calculate_match_score(
    technique,
    text,
    keywords
):

    normalized_text = normalize_text(text)

    technique_name = normalize_text(
        technique.get("name", "")
    )

    description = normalize_text(
        get_technique_description(technique)
    )

    score = 0
    evidence = []
    if technique_name and technique_name in normalized_text:

        score += 60

        evidence.append(
            f"Technique name '{technique.get('name')}' appears in the report."
        )
    technique_words = [
        word
        for word in technique_name.split()
        if len(word) >= 4
    ]

    matched_words = []

    for word in technique_words:

        if word in normalized_text:

            matched_words.append(word)

    if matched_words:

        score += min(
            len(matched_words) * 10,
            30
        )

        evidence.append(
            "Technique-related terms found: "
            + ", ".join(matched_words)
        )
    technique_description_words = set(
        description.split()
    )

    keyword_matches = []

    for keyword in keywords:

        keyword_parts = keyword.split()

        if any(
            part in technique_description_words
            for part in keyword_parts
        ):

            keyword_matches.append(
                keyword
            )

    if keyword_matches:

        score += min(
            len(keyword_matches) * 5,
            25
        )

        evidence.append(
            "Related cybersecurity indicators: "
            + ", ".join(
                keyword_matches[:5]
            )
        )
    score = min(
        score,
        100
    )

    return score, evidence
def find_matching_techniques(
    text,
    max_results=8
):

    keywords = extract_keywords(
        text
    )

    candidates = []

    for technique in techniques:

        score, evidence = calculate_match_score(
            technique,
            text,
            keywords
        )

        if score > 0:

            candidates.append(
                {
                    "technique": technique,
                    "score": score,
                    "evidence": evidence
                }
            )

    candidates.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return candidates[:max_results], keywords


# ============================================================
# POSTGRESQL LOGGING
# ============================================================

def log_attack_analysis(
    user_id,
    threat_text,
    techniques_found,
    keywords
):
    connection = None

    try:
        from database import get_connection
        from sqlalchemy import text
        from datetime import datetime

        if not user_id:
            return False, "User session not found."

        # Convert ATT&CK results to text
        technique_names = []

        for item in techniques_found:
            technique = item["technique"]

            attack_id = get_attack_id(technique)
            technique_name = technique.get("name", "Unknown")

            technique_names.append(
                f"{attack_id}: {technique_name}"
            )

        detected_techniques_text = ", ".join(technique_names)

        detected_keywords_text = ", ".join(keywords)

        # SQLAlchemy connection
        connection = get_connection()

        query = text("""
            INSERT INTO attack_analysis
            (
                user_id,
                threat_text,
                detected_techniques,
                detected_keywords,
                analyzed_at
            )
            VALUES
            (
                :user_id,
                :threat_text,
                :detected_techniques,
                :detected_keywords,
                :analyzed_at
            )
        """)

        connection.execute(
            query,
            {
                "user_id": user_id,
                "threat_text": threat_text,
                "detected_techniques": detected_techniques_text,
                "detected_keywords": detected_keywords_text,
                "analyzed_at": datetime.now()
            }
        )

        # Commit if supported
        if hasattr(connection, "commit"):
            connection.commit()

        return True, None

    except Exception as e:

        if connection is not None:
            try:
                if hasattr(connection, "rollback"):
                    connection.rollback()
            except Exception:
                pass

        return False, str(e)

    finally:

        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

# ============================================================
# HEADER
# ============================================================

st.title(
    "🧩 MITRE ATT&CK Mapping"
)

st.write(
    "Analyze a cybersecurity threat report and map "
    "observed behaviors to MITRE ATT&CK techniques."
)

st.divider()


# ============================================================
# DATASET INFORMATION
# ============================================================

with st.expander(
    "MITRE ATT&CK Dataset Information"
):

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "ATT&CK Techniques",
        len(techniques)
    )

    c2.metric(
        "ATT&CK Tactics",
        len(tactics)
    )

    c3.metric(
        "Software / Malware",
        len(software)
    )

    st.caption(
        "Source: MITRE ATT&CK Enterprise STIX dataset."
    )


# ============================================================
# THREAT REPORT INPUT
# ============================================================

st.subheader(
    "Threat Report"
)

threat_text = st.text_area(
    "Enter or paste a cybersecurity threat report:",
    height=300,
    placeholder=(
        "Example: The threat actor used PowerShell to "
        "download malicious files and subsequently moved "
        "laterally through the network using stolen credentials."
    )
)


# ============================================================
# ANALYZE BUTTON
# ============================================================

if st.button(
    "🧩 Analyze & Map to ATT&CK",
    type="primary",
    use_container_width=True
):

    if not threat_text.strip():

        st.warning(
            "Please enter a threat report."
        )

        st.stop()

    # --------------------------------------------------------
    # Find techniques
    # --------------------------------------------------------

    matches, keywords = find_matching_techniques(
        threat_text
    )

    st.divider()

    # ========================================================
    # EXTRACTED SECURITY KEYWORDS
    # ========================================================

    st.subheader(
        "🔎 Detected Cybersecurity Indicators"
    )

    if keywords:

        st.write(
            ", ".join(
                keywords
            )
        )

    else:

        st.info(
            "No predefined cybersecurity indicators were detected."
        )


    # ========================================================
    # ATT&CK RESULTS
    # ========================================================

    st.subheader(
        "🎯 MITRE ATT&CK Technique Mapping"
    )

    if not matches:

        st.warning(
            "No strong ATT&CK technique matches were found "
            "from the supplied threat description."
        )

    else:

        for index, item in enumerate(
            matches,
            start=1
        ):

            technique = item[
                "technique"
            ]

            score = item[
                "score"
            ]

            evidence = item[
                "evidence"
            ]

            attack_id = get_attack_id(
                technique
            )

            technique_name = technique.get(
                "name",
                "Unknown"
            )

            tactic_list = get_tactics(
                technique
            )

            description = get_technique_description(
                technique
            )

            st.markdown(
                f"### {index}. {technique_name}"
            )

            c1, c2, c3 = st.columns(3)

            c1.metric(
                "ATT&CK ID",
                attack_id
            )

            c2.metric(
                "Match Score",
                f"{score}%"
            )

            c3.write(
                "**Tactic(s)**"
            )

            if tactic_list:

                c3.write(
                    ", ".join(
                        tactic_list
                    )
                )

            else:

                c3.write(
                    "Not specified"
                )

            st.write(
                "**Technique Description**"
            )

            st.write(
                description
            )

            if evidence:

                st.write(
                    "**Why this technique was matched:**"
                )

                for evidence_item in evidence:

                    st.write(
                        f"- {evidence_item}"
                    )

            st.divider()


    # ========================================================
    # LOGGING
    # ========================================================

    success, error = log_attack_analysis(
        USER_ID,
        threat_text,
        matches,
        keywords
    )

    if success:

        st.success(
            "ATT&CK analysis completed and stored successfully."
        )

    else:

        st.warning(
            f"Analysis completed, but PostgreSQL logging failed: {error}"
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "CyberLens uses the MITRE ATT&CK Enterprise knowledge base "
    "to support cybersecurity technique identification. "
    "Technique matching is an analytical aid and should be "
    "reviewed by a security analyst."
)