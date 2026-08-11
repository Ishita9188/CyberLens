from sqlalchemy import text
from database import engine


# ============================================================
# GET USER ORGANIZATION
# ============================================================

def get_user_organization(user_id):

    query = text("""
        SELECT
            u.organization_id,
            o.organization_name
        FROM users u
        LEFT JOIN organizations o
            ON u.organization_id = o.organization_id
        WHERE u.id = :user_id
    """)

    with engine.connect() as connection:

        row = connection.execute(
            query,
            {"user_id": user_id}
        ).mappings().first()

    if not row:
        return None, None

    return (
        row["organization_id"],
        row["organization_name"]
    )


# ============================================================
# ANALYST STATISTICS
# ============================================================

def get_analyst_statistics(user_id):

    stats = {
        "analyses": 0,
        "threats": 0,
        "reports": 0,
        "high_risk": 0
    }

    with engine.connect() as connection:

        # ----------------------------------------------------
        # PHISHING
        # ----------------------------------------------------

        try:

            result = connection.execute(
                text("""
                    SELECT COUNT(*)
                    FROM phishing_analysis
                    WHERE user_id = :user_id
                """),
                {"user_id": user_id}
            )

            phishing_count = result.scalar() or 0

        except Exception:
            phishing_count = 0

        # ----------------------------------------------------
        # NER
        # ----------------------------------------------------

        try:

            result = connection.execute(
                text("""
                    SELECT COUNT(*)
                    FROM ner_analysis
                    WHERE user_id = :user_id
                """),
                {"user_id": user_id}
            )

            ner_count = result.scalar() or 0

        except Exception:
            ner_count = 0

        # ----------------------------------------------------
        # THREAT CATEGORY
        # ----------------------------------------------------

        try:

            result = connection.execute(
                text("""
                    SELECT COUNT(*)
                    FROM threat_category_analysis
                    WHERE user_id = :user_id
                """),
                {"user_id": user_id}
            )

            category_count = result.scalar() or 0

        except Exception:
            category_count = 0

        # ----------------------------------------------------
        # ATT&CK
        # ----------------------------------------------------

        try:

            result = connection.execute(
                text("""
                    SELECT COUNT(*)
                    FROM attack_analysis
                    WHERE user_id = :user_id
                """),
                {"user_id": user_id}
            )

            attack_count = result.scalar() or 0

        except Exception:
            attack_count = 0

        # ----------------------------------------------------
        # SUMMARY
        # ----------------------------------------------------

        try:

            result = connection.execute(
                text("""
                    SELECT COUNT(*)
                    FROM summary_analysis
                    WHERE user_id = :user_id
                """),
                {"user_id": user_id}
            )

            summary_count = result.scalar() or 0

        except Exception:
            summary_count = 0

        # ----------------------------------------------------
        # COMPLIANCE
        # ----------------------------------------------------

        try:

            result = connection.execute(
                text("""
                    SELECT COUNT(*)
                    FROM compliance_analysis
                    WHERE user_id = :user_id
                """),
                {"user_id": user_id}
            )

            compliance_count = result.scalar() or 0

        except Exception:
            compliance_count = 0

        # ----------------------------------------------------
        # EXPLAINABILITY
        # ----------------------------------------------------

        try:

            result = connection.execute(
                text("""
                    SELECT COUNT(*)
                    FROM explainability_analysis
                    WHERE user_id = :user_id
                """),
                {"user_id": user_id}
            )

            explainability_count = result.scalar() or 0

        except Exception:
            explainability_count = 0

        # ----------------------------------------------------
        # TOTAL ANALYSES
        # ----------------------------------------------------

        stats["analyses"] = (
            phishing_count
            + ner_count
            + category_count
            + attack_count
            + summary_count
            + compliance_count
            + explainability_count
        )

        # Reports are based on CTI report processing.
        stats["reports"] = max(
            ner_count,
            attack_count,
            summary_count,
            compliance_count
        )

        # ----------------------------------------------------
        # HIGH-RISK EXPLAINABILITY RESULTS
        # ----------------------------------------------------

        try:

            result = connection.execute(
                text("""
                    SELECT COUNT(*)
                    FROM explainability_analysis
                    WHERE user_id = :user_id
                    AND (
                        UPPER(CAST(decision AS TEXT)) = 'HIGH'
                        OR overall_risk >= 70
                    )
                """),
                {"user_id": user_id}
            )

            stats["high_risk"] = result.scalar() or 0

        except Exception:
            stats["high_risk"] = 0

        # ----------------------------------------------------
        # THREATS DETECTED
        # ----------------------------------------------------

        stats["threats"] = (
            category_count
            + attack_count
            + explainability_count
        )

    return stats


# ============================================================
# ORGANIZATION STATISTICS
# ============================================================

def get_organization_statistics(organization_id):

    stats = {
        "analyses": 0,
        "threats": 0,
        "reports": 0,
        "high_risk": 0,
        "analysts": 0
    }

    with engine.connect() as connection:

        # ----------------------------------------------------
        # NUMBER OF USERS
        # ----------------------------------------------------

        result = connection.execute(
            text("""
                SELECT COUNT(*)
                FROM users
                WHERE organization_id = :organization_id
            """),
            {
                "organization_id": organization_id
            }
        )

        stats["analysts"] = result.scalar() or 0

        # ----------------------------------------------------
        # TOTAL ANALYSES
        # ----------------------------------------------------

        tables = [
            "phishing_analysis",
            "ner_analysis",
            "threat_category_analysis",
            "attack_analysis",
            "summary_analysis",
            "compliance_analysis",
            "explainability_analysis"
        ]

        for table in tables:

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

                stats["analyses"] += result.scalar() or 0

            except Exception:
                pass

        # ----------------------------------------------------
        # REPORTS
        # ----------------------------------------------------

        report_tables = [
            "ner_analysis",
            "attack_analysis",
            "summary_analysis",
            "compliance_analysis"
        ]

        for table in report_tables:

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

                stats["reports"] += result.scalar() or 0

            except Exception:
                pass

        # ----------------------------------------------------
        # THREATS
        # ----------------------------------------------------

        threat_tables = [
            "threat_category_analysis",
            "attack_analysis",
            "explainability_analysis"
        ]

        for table in threat_tables:

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

                stats["threats"] += result.scalar() or 0

            except Exception:
                pass

        # ----------------------------------------------------
        # HIGH RISK
        # ----------------------------------------------------

        try:

            result = connection.execute(
                text("""
                    SELECT COUNT(*)
                    FROM explainability_analysis a
                    INNER JOIN users u
                        ON a.user_id = u.id
                    WHERE u.organization_id = :organization_id
                    AND (
                        UPPER(CAST(a.decision AS TEXT)) = 'HIGH'
                        OR a.overall_risk >= 70
                    )
                """),
                {
                    "organization_id": organization_id
                }
            )

            stats["high_risk"] = result.scalar() or 0

        except Exception:
            stats["high_risk"] = 0

    return stats