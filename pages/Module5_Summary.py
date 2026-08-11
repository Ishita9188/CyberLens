import streamlit as st
import re
from collections import Counter
from datetime import datetime
from utils.navigation import analyst_navigation
import torch

# ============================================================
# CYBERLENS - MODULE 5
# THREAT INTELLIGENCE SUMMARIZATION
# ============================================================

st.set_page_config(
    page_title="CyberLens - Threat Summarization",
    page_icon="🛡️",
    layout="wide"
)
user_id = st.session_state.get("user_id")

if not user_id:
    st.warning("User session not found. Please log in again.")
    st.stop()
analyst_navigation(
    active_page="threat"
)
st.title("🛡️ Threat Intelligence Summarization")
st.caption(
    "Generate a concise threat summary and identify cybersecurity-specific "
    "terms, indicators, actors and attack-related concepts."
)


# ============================================================
# CYBERSECURITY VOCABULARY
# ============================================================

CYBERSECURITY_TERMS = {
    # --------------------------------------------------------
    # Threats / Attacks
    # --------------------------------------------------------
    "malware",
    "ransomware",
    "spyware",
    "adware",
    "trojan",
    "rootkit",
    "worm",
    "botnet",
    "backdoor",
    "keylogger",
    "cryptojacking",

    "phishing",
    "spear-phishing",
    "spear phishing",
    "whaling",
    "smishing",
    "vishing",
    "spoofing",
    "email spoofing",
    "credential phishing",
    "social engineering",

    "brute force",
    "password spraying",
    "credential stuffing",
    "denial of service",
    "distributed denial of service",
    "ddos",
    "dos",
    "cyberattack",
    "cyber attack",
    "data breach",
    "account takeover",
    "insider threat",

    # --------------------------------------------------------
    # Vulnerabilities / Exploitation
    # --------------------------------------------------------
    "vulnerability",
    "vulnerabilities",
    "exploit",
    "exploitation",
    "zero-day",
    "zero day",
    "security flaw",
    "remote code execution",
    "rce",
    "privilege escalation",
    "buffer overflow",
    "command injection",
    "sql injection",
    "xss",
    "cross-site scripting",
    "path traversal",
    "authentication bypass",

    # --------------------------------------------------------
    # Credentials / Authentication
    # --------------------------------------------------------
    "credential",
    "credentials",
    "credential theft",
    "password",
    "password theft",
    "authentication",
    "authorization",
    "mfa",
    "multi-factor authentication",
    "2fa",
    "two-factor authentication",
    "token",
    "session",
    "access key",
    "api key",
    "secret",
    "identity",
    "identity theft",

    # --------------------------------------------------------
    # Network
    # --------------------------------------------------------
    "network",
    "firewall",
    "proxy",
    "vpn",
    "dns",
    "http",
    "https",
    "smtp",
    "ip address",
    "domain",
    "port",
    "packet",
    "traffic",
    "network traffic",
    "c2",
    "c2 server",
    "command and control",
    "c&c",
    "beacon",

    # --------------------------------------------------------
    # Malware Behaviour
    # --------------------------------------------------------
    "payload",
    "dropper",
    "loader",
    "implant",
    "persistence",
    "execution",
    "discovery",
    "lateral movement",
    "privilege escalation",
    "command execution",
    "process injection",
    "dll injection",
    "code injection",
    "scheduled task",
    "registry",
    "powershell",
    "powershell script",
    "wmi",
    "windows management instrumentation",

    # --------------------------------------------------------
    # Data / Objectives
    # --------------------------------------------------------
    "data theft",
    "data exfiltration",
    "exfiltration",
    "sensitive data",
    "personal information",
    "customer data",
    "payment card data",
    "information theft",
    "surveillance",
    "espionage",

    # --------------------------------------------------------
    # Email / Phishing
    # --------------------------------------------------------
    "malicious email",
    "phishing email",
    "malicious link",
    "malicious attachment",
    "attachment",
    "qr code",
    "phishing page",
    "landing page",
    "email spoofing",
    "spf",
    "dkim",
    "dmarc",
    "mx record",

    # --------------------------------------------------------
    # Security Infrastructure
    # --------------------------------------------------------
    "endpoint",
    "server",
    "workstation",
    "host",
    "cloud",
    "cloud service",
    "security solution",
    "security control",
    "antivirus",
    "edr",
    "xdr",
    "siem",
    "soc",
    "threat intelligence",
    "incident response",
    "forensics",
    "security monitoring",

    # --------------------------------------------------------
    # Indicators of Compromise
    # --------------------------------------------------------
    "ioc",
    "indicator of compromise",
    "indicators of compromise",
    "ip",
    "domain",
    "url",
    "hash",
    "md5",
    "sha1",
    "sha256",
    "file hash",
    "malicious domain",
    "malicious url",
    "email address",
    "filename",

    # --------------------------------------------------------
    # Threat Actors / Groups
    # --------------------------------------------------------
    "apt",
    "apt28",
    "apt29",
    "apt39",
    "fin6",
    "fin7",
    "lazarus group",
    "anonymous",
    "gamaredon",
    "bronze butler",
    "threat actor",
    "attack group",

    # --------------------------------------------------------
    # CTI / ATT&CK
    # --------------------------------------------------------
    "tactic",
    "technique",
    "procedure",
    "ttp",
    "mitre att&ck",
    "attack technique",
    "attack vector",
    "campaign",
    "operation",
    "threat campaign",

    # --------------------------------------------------------
    # General Cybersecurity Language
    # --------------------------------------------------------
    "compromised",
    "infected",
    "malicious",
    "suspicious",
    "attack surface",
    "risk",
    "severity",
    "mitigation",
    "defense",
    "detection",
    "prevention",
    "quarantine",
    "patch",
    "security update",
    "security patch"
}


# ============================================================
# THREAT ACTOR VOCABULARY
# ============================================================

THREAT_ACTOR_TERMS = {
    "apt28",
    "apt29",
    "apt39",
    "fin6",
    "fin7",
    "lazarus group",
    "gamaredon",
    "bronze butler",
    "anonymous",
    "threat actor",
    "threat actors"
}


# ============================================================
# ATTACK / TECHNIQUE TERMS
# ============================================================

ATTACK_TERMS = {
    "phishing",
    "spear-phishing",
    "spear phishing",
    "whaling",
    "smishing",
    "vishing",
    "spoofing",
    "credential phishing",
    "social engineering",
    "brute force",
    "password spraying",
    "credential stuffing",
    "ransomware",
    "malware",
    "ddos",
    "dos",
    "denial of service",
    "distributed denial of service",
    "remote code execution",
    "rce",
    "privilege escalation",
    "command injection",
    "sql injection",
    "cross-site scripting",
    "process injection",
    "dll injection",
    "lateral movement",
    "data exfiltration",
    "credential theft",
    "command and control",
    "c2",
    "persistence",
    "discovery",
    "powershell",
    "scheduled task"
}


# ============================================================
# IOC EXTRACTION
# ============================================================

def extract_iocs(text):

    iocs = {
        "IP Addresses": [],
        "Domains": [],
        "URLs": [],
        "Hashes": [],
        "Email Addresses": []
    }

    # IPv4
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    # URLs
    url_pattern = r"https?://[^\s<>\"]+"

    # Domains
    domain_pattern = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|net|org|gov|edu|io|co|info|biz|xyz|online|site)\b"
    )

    # Hashes
    hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"

    # Emails
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    iocs["IP Addresses"] = list(
        dict.fromkeys(re.findall(ip_pattern, text))
    )

    iocs["URLs"] = list(
        dict.fromkeys(re.findall(url_pattern, text))
    )

    iocs["Domains"] = list(
        dict.fromkeys(re.findall(domain_pattern, text))
    )

    iocs["Hashes"] = list(
        dict.fromkeys(re.findall(hash_pattern, text))
    )

    iocs["Email Addresses"] = list(
        dict.fromkeys(re.findall(email_pattern, text))
    )

    return iocs


# ============================================================
# CYBERSECURITY TERM EXTRACTION
# ============================================================

def extract_cybersecurity_terms(text):

    text_lower = text.lower()

    found = []

    # Longest phrases first.
    # This prevents "credential" from being preferred
    # over "credential theft", for example.
    sorted_terms = sorted(
        CYBERSECURITY_TERMS,
        key=len,
        reverse=True
    )

    for term in sorted_terms:

        pattern = r"(?<!\w)" + re.escape(term) + r"(?!\w)"

        if re.search(pattern, text_lower):
            found.append(term)

    return found


# ============================================================
# THREAT ACTOR EXTRACTION
# ============================================================

def extract_threat_actors(text):

    text_lower = text.lower()

    found = []

    for actor in sorted(
        THREAT_ACTOR_TERMS,
        key=len,
        reverse=True
    ):

        pattern = r"(?<!\w)" + re.escape(actor) + r"(?!\w)"

        if re.search(pattern, text_lower):
            found.append(actor)

    return found


# ============================================================
# ATTACK TECHNIQUE EXTRACTION
# ============================================================

def extract_attack_terms(text):

    text_lower = text.lower()

    found = []

    for term in sorted(
        ATTACK_TERMS,
        key=len,
        reverse=True
    ):

        pattern = r"(?<!\w)" + re.escape(term) + r"(?!\w)"

        if re.search(pattern, text_lower):
            found.append(term)

    return found


# ============================================================
# KEYWORD FREQUENCY
# ============================================================

def get_keyword_frequency(text):

    text_lower = text.lower()

    counts = Counter()

    for term in CYBERSECURITY_TERMS:

        pattern = r"(?<!\w)" + re.escape(term) + r"(?!\w)"

        matches = re.findall(pattern, text_lower)

        if matches:
            counts[term] = len(matches)

    return counts.most_common(15)


# ============================================================
# SUMMARIZATION MODEL
# ============================================================

# ============================================================
# SUMMARIZATION MODEL
# ============================================================

@st.cache_resource
def load_summarization_model():

    try:

        import torch
        from transformers import (
            AutoTokenizer,
            AutoModelForSeq2SeqLM
        )

        model_name = "sshleifer/distilbart-cnn-12-6"

        # Load tokenizer
        tokenizer = AutoTokenizer.from_pretrained(
            model_name
        )

        # Load pretrained model
        # NO RETRAINING REQUIRED
        model = AutoModelForSeq2SeqLM.from_pretrained(
            model_name
        )

        # Use GPU if available
        device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )

        model.to(device)
        model.eval()

        return tokenizer, model, device

    except Exception as e:

        st.error(
            f"Unable to load summarization model: {e}"
        )

        return None, None, None


# ============================================================
# CYBERSECURITY KEYWORD EXTRACTION
# ============================================================

def extract_cybersecurity_keywords(text):

    cybersecurity_terms = [

        # General security
        "cybersecurity",
        "cyber attack",
        "cyber threat",
        "threat actor",
        "attack",
        "attacker",
        "adversary",
        "campaign",
        "incident",
        "compromise",
        "breach",
        "exploit",
        "exploitation",
        "vulnerability",
        "zero-day",
        "zero day",

        # Malware
        "malware",
        "ransomware",
        "trojan",
        "backdoor",
        "rootkit",
        "spyware",
        "keylogger",
        "botnet",
        "worm",
        "loader",
        "dropper",
        "infostealer",
        "stealer",

        # Phishing
        "phishing",
        "spear phishing",
        "whaling",
        "credential phishing",
        "spoofing",
        "email spoofing",
        "business email compromise",
        "BEC",
        "phishing-as-a-service",
        "PhaaS",
        "malicious email",
        "malicious link",
        "malicious attachment",

        # Credentials / identity
        "credential",
        "credentials",
        "credential theft",
        "password",
        "password theft",
        "authentication",
        "authorization",
        "MFA",
        "multi-factor authentication",
        "multifactor authentication",
        "2FA",
        "account takeover",
        "identity theft",
        "session hijacking",
        "token theft",

        # Network
        "network",
        "network attack",
        "DDoS",
        "denial of service",
        "distributed denial of service",
        "DNS",
        "DNS attack",
        "IP address",
        "proxy",
        "VPN",
        "firewall",
        "router",
        "server",
        "endpoint",

        # Web
        "web attack",
        "web shell",
        "SQL injection",
        "command injection",
        "cross-site scripting",
        "XSS",
        "CSRF",
        "malicious URL",
        "URL",
        "domain",
        "redirect",
        "payload",

        # Email security
        "DMARC",
        "SPF",
        "DKIM",
        "MX record",
        "email header",
        "mail flow",
        "email security",

        # Exploitation
        "remote code execution",
        "RCE",
        "privilege escalation",
        "lateral movement",
        "persistence",
        "execution",
        "command and control",
        "C2",
        "C&C",
        "exfiltration",
        "data theft",
        "data exfiltration",

        # Attack techniques
        "social engineering",
        "brute force",
        "password spraying",
        "credential stuffing",
        "man-in-the-middle",
        "adversary-in-the-middle",
        "AiTM",
        "reconnaissance",
        "initial access",
        "defense evasion",
        "discovery",
        "collection",

        # Security technologies
        "EDR",
        "XDR",
        "SIEM",
        "IDS",
        "IPS",
        "antivirus",
        "endpoint protection",
        "threat intelligence",
        "threat detection",
        "incident response",

        # Cyber threat intelligence
        "IOC",
        "IOCs",
        "indicator of compromise",
        "indicators of compromise",
        "TTP",
        "TTPs",
        "MITRE ATT&CK",
        "attack technique",
        "threat intelligence report",
        "CTI",

        # Common artifacts
        "hash",
        "SHA256",
        "SHA-256",
        "MD5",
        "file hash",
        "malicious file",
        "executable",
        "attachment",
        "script",
        "PowerShell",
        "command shell",

        # Cloud / infrastructure
        "cloud security",
        "Microsoft 365",
        "Office 365",
        "Azure",
        "AWS",
        "cloud account",
        "tenant",
        "API key",
        "access key"
    ]

    text_lower = text.lower()

    found = []

    for term in cybersecurity_terms:

        if term.lower() in text_lower:

            found.append(term)

    # Remove duplicates while preserving order
    found = list(dict.fromkeys(found))

    return found


# ============================================================
# SUMMARIZE THREAT REPORT
# ============================================================

# ============================================================
# CYBERLENS - IMPROVED THREAT SUMMARIZATION
# ============================================================

def summarize_threat(text, tokenizer, model, device):

    if tokenizer is None or model is None:
        return None

    if not text or not text.strip():
        return None

    try:

        import re
        import torch

        # ====================================================
        # CYBERSECURITY TERMS
        # ====================================================

        cybersecurity_terms = [

            # Threats
            "phishing",
            "spear phishing",
            "credential phishing",
            "spoofing",
            "email spoofing",
            "malware",
            "ransomware",
            "trojan",
            "backdoor",
            "botnet",
            "DDoS",
            "denial of service",

            # Credentials / identity
            "credential",
            "credentials",
            "password",
            "authentication",
            "MFA",
            "2FA",
            "multi-factor authentication",
            "account takeover",
            "credential theft",

            # Attack techniques
            "exploit",
            "exploitation",
            "vulnerability",
            "zero-day",
            "privilege escalation",
            "lateral movement",
            "persistence",
            "command and control",
            "C2",
            "data exfiltration",
            "social engineering",
            "brute force",
            "password spraying",
            "credential stuffing",
            "adversary-in-the-middle",
            "AiTM",

            # Email security
            "DMARC",
            "SPF",
            "DKIM",
            "MX record",
            "email header",
            "mail flow",
            "third-party connector",

            # Cybersecurity platforms / technologies
            "Microsoft 365",
            "Office 365",
            "Microsoft Defender",
            "Tycoon2FA",
            "PhaaS",
            "MITRE ATT&CK",
            "IOC",
            "IOCs",
            "indicator of compromise",
            "threat actor",
            "threat intelligence",

            # Web / network
            "malicious URL",
            "malicious link",
            "malicious attachment",
            "QR code",
            "payload",
            "IP address",
            "domain",
            "DNS",
            "firewall",
            "endpoint",
            "EDR",
            "SIEM"
        ]

        # ====================================================
        # SENTENCE SPLITTING
        # ====================================================

        # Normalize whitespace
        clean_text = re.sub(
            r"\s+",
            " ",
            text
        ).strip()

        # Split report into sentences
        sentences = re.split(
            r"(?<=[.!?])\s+",
            clean_text
        )

        sentences = [
            s.strip()
            for s in sentences
            if len(s.strip()) > 30
        ]

        # ====================================================
        # IDENTIFY IMPORTANT CYBERSECURITY SENTENCES
        # ====================================================

        important_sentences = []

        for sentence in sentences:

            sentence_lower = sentence.lower()

            matched_terms = []

            for term in cybersecurity_terms:

                if term.lower() in sentence_lower:

                    matched_terms.append(term)

            # Score sentence based on cybersecurity relevance
            score = len(
                set(matched_terms)
            )

            # Give extra importance to attack/mitigation
            # related sentences

            high_priority_terms = [
                "attack",
                "phishing",
                "spoofing",
                "exploit",
                "vulnerability",
                "credential",
                "malware",
                "ransomware",
                "mitigation",
                "prevent",
                "blocked",
                "bypass",
                "compromise",
                "malicious"
            ]

            for term in high_priority_terms:

                if term.lower() in sentence_lower:

                    score += 2

            if score > 0:

                important_sentences.append(
                    (score, sentence)
                )

        # ====================================================
        # SORT BY CYBERSECURITY RELEVANCE
        # ====================================================

        important_sentences.sort(
            key=lambda x: x[0],
            reverse=True
        )

        # Keep the strongest technical sentences
        selected_sentences = []

        for score, sentence in important_sentences:

            if sentence not in selected_sentences:

                selected_sentences.append(
                    sentence
                )

            if len(selected_sentences) >= 6:
                break

        # ====================================================
        # GENERATE BART SUMMARY
        # ====================================================

        words = clean_text.split()

        # DistilBART input limitation
        max_words = 650

        chunks = []

        for i in range(
            0,
            len(words),
            max_words
        ):

            chunk = " ".join(
                words[i:i + max_words]
            )

            if chunk.strip():

                chunks.append(chunk)

        bart_summaries = []

        for chunk in chunks:

            try:

                inputs = tokenizer(
                    chunk,
                    return_tensors="pt",
                    max_length=1024,
                    truncation=True
                )

                inputs = {
                    key: value.to(device)
                    for key, value in inputs.items()
                }

                with torch.no_grad():

                    summary_ids = model.generate(

                        **inputs,

                        max_length=180,

                        min_length=50,

                        num_beams=4,

                        length_penalty=2.0,

                        no_repeat_ngram_size=3,

                        early_stopping=True
                    )

                summary = tokenizer.decode(
                    summary_ids[0],
                    skip_special_tokens=True
                )

                if summary.strip():

                    bart_summaries.append(
                        summary.strip()
                    )

            except Exception as e:

                st.warning(
                    f"Could not summarize one section: {e}"
                )

        # ====================================================
        # CHECK BART RESULT
        # ====================================================

        if not bart_summaries:

            bart_summary = ""

        else:

            bart_summary = " ".join(
                bart_summaries
            )

        # ====================================================
        # EXTRACT CYBERSECURITY TERMS PRESENT
        # ====================================================

        detected_keywords = []

        text_lower = clean_text.lower()

        for term in cybersecurity_terms:

            if term.lower() in text_lower:

                detected_keywords.append(term)

        # Remove duplicates
        detected_keywords = list(
            dict.fromkeys(
                detected_keywords
            )
        )

        # ====================================================
        # BUILD TECHNICAL CONTEXT
        # ====================================================

        technical_context = ""

        if selected_sentences:

            technical_context = " ".join(
                selected_sentences[:5]
            )

        # ====================================================
        # REMOVE SENTENCE DUPLICATES
        # ====================================================

        final_parts = []

        if bart_summary:

            final_parts.append(
                bart_summary
            )

        # Add technically important information
        # that BART may have missed

        if technical_context:

            final_parts.append(
                technical_context
            )

        # ====================================================
        # COMBINE SUMMARY
        # ====================================================

        combined_summary = " ".join(
            final_parts
        )

        # Normalize spaces
        combined_summary = re.sub(
            r"\s+",
            " ",
            combined_summary
        ).strip()

        # ====================================================
        # REMOVE EXACT DUPLICATE SENTENCES
        # ====================================================

        final_sentences = re.split(
            r"(?<=[.!?])\s+",
            combined_summary
        )

        unique_sentences = []

        seen = set()

        for sentence in final_sentences:

            normalized = sentence.lower().strip()

            if (
                normalized
                and normalized not in seen
            ):

                unique_sentences.append(
                    sentence.strip()
                )

                seen.add(normalized)

        combined_summary = " ".join(
            unique_sentences
        )

        # ====================================================
        # RETURN RESULTS
        # ====================================================

        return {

            "summary": combined_summary,

            "keywords": detected_keywords,

            "technical_sentences":
                selected_sentences

        }

    except Exception as e:

        st.error(
            f"Summary generation failed: {e}"
        )

        return None


# ============================================================
# DATABASE LOGGING
# ============================================================

def log_summary_analysis(
    threat_text,
    summary,
    cyber_terms,
    threat_actors,
    attack_terms,
    iocs
):

    try:

        from database import get_connection

        user_id = st.session_state.get("user_id")

        if not user_id:

            return False, "User session not found."

        connection = get_connection()

        # Your project may use SQLAlchemy.
        # Therefore support both SQLAlchemy and
        # raw DB-API connections.

        try:

            from sqlalchemy import text as sql_text

            if hasattr(connection, "execute"):

                query = sql_text("""
                    INSERT INTO summary_analysis
                    (
                        user_id,
                        threat_text,
                        summary,
                        cybersecurity_terms,
                        threat_actors,
                        attack_terms,
                        iocs,
                        word_count,
                        analyzed_at
                    )
                    VALUES
                    (
                        :user_id,
                        :threat_text,
                        :summary,
                        :cybersecurity_terms,
                        :threat_actors,
                        :attack_terms,
                        :iocs,
                        :word_count,
                        :analyzed_at
                    )
                """)

                connection.execute(
                    query,
                    {
                        "user_id": user_id,
                        "threat_text": threat_text,
                        "summary": summary,
                        "cybersecurity_terms": ", ".join(cyber_terms),
                        "threat_actors": ", ".join(threat_actors),
                        "attack_terms": ", ".join(attack_terms),
                        "iocs": str(iocs),
                        "word_count": len(threat_text.split()),
                        "analyzed_at": datetime.now()
                    }
                )

                connection.commit()

            else:

                cursor = connection.cursor()

                cursor.execute(
                    """
                    INSERT INTO summary_analysis
                    (
                        user_id,
                        threat_text,
                        summary,
                        cybersecurity_terms,
                        threat_actors,
                        attack_terms,
                        iocs,
                        word_count,
                        analyzed_at
                    )
                    VALUES
                    (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        user_id,
                        threat_text,
                        summary,
                        ", ".join(cyber_terms),
                        ", ".join(threat_actors),
                        ", ".join(attack_terms),
                        str(iocs),
                        len(threat_text.split()),
                        datetime.now()
                    )
                )

                connection.commit()
                cursor.close()

        except Exception:

            try:
                connection.rollback()
            except Exception:
                pass

            raise

        finally:

            try:
                connection.close()
            except Exception:
                pass

        return True, None

    except Exception as e:

        return False, str(e)


# ============================================================
# INPUT
# ============================================================

st.subheader("📄 Threat Report")

uploaded_file = st.file_uploader(
    "Upload a cybersecurity threat report",
    type=["txt", "text"]
)


# ============================================================
# TEXT INPUT
# ============================================================

report_text = ""

if uploaded_file:

    try:

        report_text = uploaded_file.read().decode(
            "utf-8",
            errors="ignore"
        )

        st.success(
            f"Loaded report: {uploaded_file.name}"
        )

    except Exception as e:

        st.error(
            f"Unable to read file: {e}"
        )

else:

    report_text = st.text_area(
        "Or paste a threat report here",
        height=350,
        placeholder=(
            "Paste a cybersecurity threat intelligence report..."
        )
    )


# ============================================================
# ANALYZE
# ============================================================

if st.button(
    "🔍 Analyze Threat Report",
    type="primary",
    use_container_width=True
):

    if not report_text.strip():

        st.warning(
            "Please upload or paste a threat report."
        )

        st.stop()

    with st.spinner(
        "Analyzing threat report..."
    ):

        # ----------------------------------------------------
        # Load existing pretrained model
        # ----------------------------------------------------

        tokenizer, model, device = load_summarization_model()

        # ----------------------------------------------------
        # Generate summary
        # ----------------------------------------------------

        result = summarize_threat(
            report_text,
            tokenizer,
            model,
            device
        )

        if result:
            summary = result["summary"]
            cybersecurity_keywords = result["keywords"]
            technical_sentences = result[
        "technical_sentences" ]

        else:
            summary = None
            cybersecurity_keywords = []
            technical_sentences = []

        # ----------------------------------------------------
        # Cybersecurity analysis
        # ----------------------------------------------------

        cyber_terms = extract_cybersecurity_terms(
            report_text
        )

        threat_actors = extract_threat_actors(
            report_text
        )

        attack_terms = extract_attack_terms(
            report_text
        )

        iocs = extract_iocs(
            report_text
        )

        keyword_frequency = get_keyword_frequency(
            report_text
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    st.subheader("📝 Threat Summary")

    if summary:

        st.success(summary)

    else:

        st.warning(
            "Summary could not be generated."
        )


    # ========================================================
    # BASIC STATISTICS
    # ========================================================

    word_count = len(
        report_text.split()
    )

    sentence_count = len(
        re.findall(
            r"[.!?]+",
            report_text
        )
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Word Count",
            word_count
        )

    with col2:

        st.metric(
            "Sentences",
            sentence_count
        )

    with col3:

        st.metric(
            "Cybersecurity Terms",
            len(cyber_terms)
        )


    # ========================================================
    # CYBERSECURITY TERMS
    # ========================================================

    st.subheader(
        "🔐 Cybersecurity Terms Identified"
    )

    if cyber_terms:

        st.write(
            ", ".join(
                cyber_terms
            )
        )

    else:

        st.info(
            "No predefined cybersecurity terms detected."
        )


    # ========================================================
    # KEYWORD FREQUENCY
    # ========================================================

    st.subheader(
        "🔑 Important Cybersecurity Keywords"
    )

    if keyword_frequency:

        keyword_table = []

        for keyword, frequency in keyword_frequency:

            keyword_table.append(
                {
                    "Keyword": keyword,
                    "Occurrences": frequency
                }
            )

        st.dataframe(
            keyword_table,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No cybersecurity keywords detected."
        )


    # ========================================================
    # THREAT ACTORS
    # ========================================================

    st.subheader(
        "👤 Threat Actors / Groups"
    )

    if threat_actors:

        for actor in threat_actors:

            st.write(
                f"• {actor}"
            )

    else:

        st.info(
            "No predefined threat actors detected."
        )


    # ========================================================
    # ATTACK TECHNIQUES
    # ========================================================

    st.subheader(
        "⚔️ Attack Techniques / Behaviours"
    )

    if attack_terms:

        for attack in attack_terms:

            st.write(
                f"• {attack}"
            )

    else:

        st.info(
            "No predefined attack techniques detected."
        )


    # ========================================================
    # IOCs
    # ========================================================

    st.subheader(
        "🚨 Indicators of Compromise"
    )

    total_iocs = sum(
        len(values)
        for values in iocs.values()
    )

    if total_iocs > 0:

        for category, values in iocs.items():

            if values:

                st.markdown(
                    f"**{category}**"
                )

                for value in values:

                    st.code(
                        value
                    )

    else:

        st.info(
            "No obvious IOCs detected."
        )


    # ========================================================
    # DATABASE LOGGING
    # ========================================================

    if summary:

        success, error = log_summary_analysis(
            report_text,
            summary,
            cyber_terms,
            threat_actors,
            attack_terms,
            iocs
        )

        if success:

            st.success(
                "✅ Summary analysis logged successfully."
            )

        else:

            st.warning(
                "Analysis completed, but PostgreSQL "
                f"logging failed: {error}"
            )


    # ========================================================
    # DOWNLOAD SUMMARY
    # ========================================================

    output = f"""
CYBERLENS - THREAT INTELLIGENCE ANALYSIS
=========================================

THREAT SUMMARY
--------------
{summary if summary else "Not generated"}

CYBERSECURITY TERMS
-------------------
{", ".join(cyber_terms)}

THREAT ACTORS
-------------
{", ".join(threat_actors)}

ATTACK TECHNIQUES
-----------------
{", ".join(attack_terms)}

KEYWORD FREQUENCY
-----------------
"""

    for keyword, frequency in keyword_frequency:

        output += (
            f"{keyword}: {frequency}\n"
        )

    output += """

INDICATORS OF COMPROMISE
------------------------
"""

    for category, values in iocs.items():

        if values:

            output += (
                f"\n{category}:\n"
            )

            for value in values:

                output += (
                    f"- {value}\n"
                )


    st.download_button(
        label="⬇️ Download Analysis",
        data=output,
        file_name="cyberlens_threat_analysis.txt",
        mime="text/plain",
        use_container_width=True
    )