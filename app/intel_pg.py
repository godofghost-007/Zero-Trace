import json
from collections.abc import Iterable
from typing import Any, Callable
from uuid import uuid4

from .intel import ServiceFinding, UncertainMatch, VulnerabilityFact


class PostgresIntelRepository:
    """Parameterized persistence for normalized facts and explainable findings."""

    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        self.connection_factory = connection_factory

    def list_findings(
        self, owner_id: str, *, page: int, page_size: int
    ) -> dict[str, object]:
        if page < 1 or not 1 <= page_size <= 100:
            raise ValueError("pagination values are invalid")
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT COUNT(*)
                    FROM intel_findings AS f
                    JOIN recon_scopes AS s ON s.scope_id = f.scope_id
                    WHERE s.owner_id = %s
                    """,
                    (owner_id,),
                )
                total_items = int(cursor.fetchone()[0])
                cursor.execute(
                    """
                    SELECT f.finding_id, f.scope_id, f.asset_id, f.service_id,
                           f.cve_id, f.match_method, f.confidence, f.evidence,
                           f.freshness, f.priority_score, f.priority_inputs,
                           f.formula_version, f.source_revision
                    FROM intel_findings AS f
                    JOIN recon_scopes AS s ON s.scope_id = f.scope_id
                    WHERE s.owner_id = %s
                    ORDER BY f.finding_id
                    LIMIT %s OFFSET %s
                    """,
                    (owner_id, page_size, (page - 1) * page_size),
                )
                rows = cursor.fetchall()
        items = [
            {
                "findingId": str(row[0]),
                "scopeId": str(row[1]),
                "assetId": str(row[2]),
                "serviceId": str(row[3]),
                "cveId": row[4],
                "matchMethod": row[5],
                "confidence": row[6],
                "evidence": row[7],
                "freshness": row[8],
                "priorityScore": row[9],
                "priorityInputs": row[10],
                "formulaVersion": row[11],
                "sourceRevision": row[12],
            }
            for row in rows
        ]
        return {
            "items": items,
            "pagination": {
                "page": page,
                "pageSize": page_size,
                "totalItems": total_items,
                "totalPages": (total_items + page_size - 1) // page_size,
            },
        }

    def get_finding(self, owner_id: str, finding_id: str) -> dict[str, object] | None:
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT f.finding_id, f.scope_id, f.asset_id, f.service_id,
                           f.cve_id, f.match_method, f.confidence, f.evidence,
                           f.freshness, f.priority_score, f.priority_inputs,
                           f.formula_version, f.source_revision
                    FROM intel_findings AS f
                    JOIN recon_scopes AS s ON s.scope_id = f.scope_id
                    WHERE s.owner_id = %s AND f.finding_id = %s
                    """,
                    (owner_id, finding_id),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        return {
            "findingId": str(row[0]),
            "scopeId": str(row[1]),
            "assetId": str(row[2]),
            "serviceId": str(row[3]),
            "cveId": row[4],
            "matchMethod": row[5],
            "confidence": row[6],
            "evidence": row[7],
            "freshness": row[8],
            "priorityScore": row[9],
            "priorityInputs": row[10],
            "formulaVersion": row[11],
            "sourceRevision": row[12],
        }

    def save_fact(self, fact: VulnerabilityFact) -> str:
        fact_id = str(uuid4())
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO intel_vulnerability_facts
                        (fact_id, cve_id, source, source_record_id, source_revision,
                         summary, cpe_names, cvss_score, epss_score, kev,
                         published_at, modified_at, retrieved_at, schema_version,
                         payload_digest)
                    VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s,
                            %s, %s, %s, %s, %s)
                    ON CONFLICT (source, source_record_id, source_revision)
                    DO NOTHING
                    """,
                    (
                        fact_id, fact.cve_id, fact.source, fact.source_record_id,
                        fact.source_revision, fact.summary, json.dumps(fact.cpe_names),
                        fact.cvss_score, fact.epss_score, fact.kev,
                        fact.published_at, fact.modified_at, fact.retrieved_at,
                        fact.schema_version, fact.payload_digest,
                    ),
                )
            connection.commit()
        return fact_id

    def save_findings(
        self,
        scope_id: str,
        findings: Iterable[ServiceFinding],
        source_revision: str,
    ) -> None:
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                for finding in findings:
                    cursor.execute(
                        """
                        INSERT INTO intel_findings
                            (finding_id, scope_id, asset_id, service_id, cve_id,
                             match_method, confidence, evidence, freshness,
                             priority_score, priority_inputs, formula_version,
                             source_revision)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s,
                                %s, %s::jsonb, %s, %s)
                        ON CONFLICT (scope_id, service_id, cve_id, source_revision)
                        DO UPDATE SET confidence = EXCLUDED.confidence,
                                      evidence = EXCLUDED.evidence,
                                      freshness = EXCLUDED.freshness,
                                      priority_score = EXCLUDED.priority_score,
                                      priority_inputs = EXCLUDED.priority_inputs,
                                      updated_at = CURRENT_TIMESTAMP
                        """,
                        (
                            str(uuid4()), scope_id, finding.asset_id,
                            finding.service_id, finding.cve_id,
                            finding.match_method, finding.confidence,
                            json.dumps(finding.evidence), finding.freshness,
                            finding.priority.score,
                            json.dumps(dict(finding.priority.inputs)),
                            finding.priority.formula_version,
                            source_revision,
                        ),
                    )
            connection.commit()

    def save_correlation(
        self,
        scope_id: str,
        findings: Iterable[ServiceFinding],
        uncertain_matches: Iterable[UncertainMatch],
        source_revision: str | None = None,
    ) -> None:
        """Persist confirmed findings and uncertain matches in one transaction."""
        revision = source_revision or ""
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                for finding in findings:
                    cursor.execute(
                        """
                        INSERT INTO intel_findings
                            (finding_id, scope_id, asset_id, service_id, cve_id,
                             match_method, confidence, evidence, freshness,
                             priority_score, priority_inputs, formula_version,
                             source_revision)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s,
                                %s, %s::jsonb, %s, %s)
                        ON CONFLICT (scope_id, service_id, cve_id, source_revision)
                        DO UPDATE SET confidence = EXCLUDED.confidence,
                                      evidence = EXCLUDED.evidence,
                                      freshness = EXCLUDED.freshness,
                                      priority_score = EXCLUDED.priority_score,
                                      priority_inputs = EXCLUDED.priority_inputs,
                                      updated_at = CURRENT_TIMESTAMP
                        """,
                        (
                            str(uuid4()), scope_id, finding.asset_id,
                            finding.service_id, finding.cve_id,
                            finding.match_method, finding.confidence,
                            json.dumps(finding.evidence), finding.freshness,
                            finding.priority.score,
                            json.dumps(dict(finding.priority.inputs)),
                            finding.priority.formula_version,
                            revision,
                        ),
                    )
                for match in uncertain_matches:
                    cursor.execute(
                        """
                        INSERT INTO intel_uncertain_matches
                            (uncertain_id, scope_id, asset_id, service_id, cve_id,
                             reason, evidence, freshness, source_revision)
                        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                        ON CONFLICT (scope_id, service_id, cve_id, reason, source_revision)
                        DO UPDATE SET evidence = EXCLUDED.evidence,
                                      freshness = EXCLUDED.freshness
                        """,
                        (
                            str(uuid4()), scope_id, match.asset_id,
                            match.service_id, match.cve_id, match.reason,
                            json.dumps(match.evidence), match.freshness,
                            match.source_revision,
                        ),
                    )
            connection.commit()

    def save_uncertain_matches(
        self,
        scope_id: str,
        matches: Iterable[UncertainMatch],
    ) -> None:
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                for match in matches:
                    cursor.execute(
                        """
                        INSERT INTO intel_uncertain_matches
                            (uncertain_id, scope_id, asset_id, service_id, cve_id,
                             reason, evidence, freshness, source_revision)
                        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                        ON CONFLICT (scope_id, service_id, cve_id, reason, source_revision)
                        DO UPDATE SET evidence = EXCLUDED.evidence,
                                      freshness = EXCLUDED.freshness
                        """,
                        (
                            str(uuid4()), scope_id, match.asset_id, match.service_id,
                            match.cve_id, match.reason, json.dumps(match.evidence),
                            match.freshness, match.source_revision,
                        ),
                    )
            connection.commit()

    def list_uncertain_matches(
        self, owner_id: str, *, page: int, page_size: int
    ) -> dict[str, object]:
        if page < 1 or not 1 <= page_size <= 100:
            raise ValueError("pagination values are invalid")
        with self.connection_factory() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT COUNT(*)
                    FROM intel_uncertain_matches AS u
                    JOIN recon_scopes AS s ON s.scope_id = u.scope_id
                    WHERE s.owner_id = %s
                    """,
                    (owner_id,),
                )
                total_items = int(cursor.fetchone()[0])
                cursor.execute(
                    """
                    SELECT u.uncertain_id, u.scope_id, u.asset_id, u.service_id,
                           u.cve_id, u.reason, u.evidence, u.freshness,
                           u.source_revision
                    FROM intel_uncertain_matches AS u
                    JOIN recon_scopes AS s ON s.scope_id = u.scope_id
                    WHERE s.owner_id = %s
                    ORDER BY u.uncertain_id
                    LIMIT %s OFFSET %s
                    """,
                    (owner_id, page_size, (page - 1) * page_size),
                )
                rows = cursor.fetchall()
        return {
            "items": [
                {
                    "uncertainId": str(row[0]),
                    "scopeId": str(row[1]),
                    "assetId": str(row[2]),
                    "serviceId": str(row[3]),
                    "cveId": row[4],
                    "reason": row[5],
                    "evidence": row[6],
                    "freshness": row[7],
                    "sourceRevision": row[8],
                }
                for row in rows
            ],
            "pagination": {
                "page": page,
                "pageSize": page_size,
                "totalItems": total_items,
                "totalPages": (total_items + page_size - 1) // page_size,
            },
        }
