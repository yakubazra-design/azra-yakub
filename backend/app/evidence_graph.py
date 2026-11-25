"""Evidence Intelligence Graph helpers (E.9.5C).

Builds intra-investigation nodes and edges from stored ledger rows only.
Relationships describe stored records; they do not prove a claim is true.
No provider calls. No public write API.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse

from app.textutil import host_of

GRAPH_NOTE = (
    "Relationships describe stored records. They do not prove the claim is true. "
    "Earliest observation is not necessarily original publication."
)

NODE_TYPES = frozenset({
    "investigation",
    "claim",
    "evidence_source",
    "url",
    "website",
    "image",
    "page",
    "finding",
    "assessment_result",
    "snapshot",
    "provenance_record",
    "publication_event",
    "observation_event",
})

REL_TYPES = frozenset({
    "CONTAINS",
    "REFERENCES",
    "DERIVED_FROM",
    "SUPPORTS",
    "CONTRADICTS",
    "PUBLISHED_AT",
    "OBSERVED_AT",
    "SUPERSEDES",
})

CERTAINTIES = frozenset({"CONFIRMED", "INFERRED", "UNCERTAIN"})

CONFIRMED_METHODS = frozenset({
    "system_structural",
    "system_clock",
    "system_supersession",
    "system_literal_alignment",
})

GRAPH_FAILURE_CATALOG = {
    "graph_persist_failed": "The evidence graph could not be updated.",
    "graph_scope_invalid": "The evidence graph scope is not valid.",
    "unknown": "The evidence graph could not be updated.",
}


def graph_failure_message(code: str | None) -> str:
    if not isinstance(code, str) or not code:
        return GRAPH_FAILURE_CATALOG["unknown"]
    return GRAPH_FAILURE_CATALOG.get(code, GRAPH_FAILURE_CATALOG["unknown"])


def scope_key(snapshot_id: str | None = None, assessment_result_id: str | None = None) -> str:
    return f"{snapshot_id or ''}|{assessment_result_id or ''}"


def normalize_url_key(url: str) -> str:
    text = (url or "").strip()
    if not text:
        return ""
    try:
        parsed = urlparse(text)
    except ValueError:
        return text.lower()
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path or ""
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    if not host:
        return text.lower()
    netloc = host
    if parsed.port and parsed.port not in (80, 443):
        netloc = f"{host}:{parsed.port}"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def website_key(url: str) -> str:
    host = host_of(url) or ""
    return host.lower().rstrip(".")


def evidence_fingerprint(payload: dict) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def validate_certainty(rel_type: str, certainty: str, method: str) -> None:
    if rel_type not in REL_TYPES:
        raise ValueError("invalid relationship type")
    if certainty not in CERTAINTIES:
        raise ValueError("invalid certainty")
    if not isinstance(method, str) or not method:
        raise ValueError("invalid method")
    if certainty == "CONFIRMED" and method not in CONFIRMED_METHODS:
        raise ValueError("confirmed method not allowed")
    if rel_type in ("SUPPORTS", "CONTRADICTS") and certainty == "CONFIRMED" and method.startswith("model_"):
        raise ValueError("model relationships cannot be confirmed")
    if rel_type == "PUBLISHED_AT" and certainty == "CONFIRMED":
        # Recorded metadata is never CONFIRMED as true publish time.
        raise ValueError("published_at cannot be confirmed as true publication")


def finding_support_certainty(evidence_status: str | None, alignment_reason: str | None) -> tuple[str, str]:
    """Map stored finding alignment to edge certainty and method.

    Literal alignment may be CONFIRMED via deterministic stored status only.
    Model-originated paraphrase signals stay INFERRED/UNCERTAIN.
    """
    status = evidence_status or ""
    reason = alignment_reason or ""
    if status == "literally_aligned" or reason == "literal_sentence":
        return "CONFIRMED", "system_literal_alignment"
    if status == "contradicted" or reason == "negation_conflict":
        return "CONFIRMED", "system_literal_alignment"
    if status in ("not_established", "") or "paraphrase" in reason:
        return "UNCERTAIN", "model_finding_status"
    return "INFERRED", "model_finding_status"


def published_at_certainty(date_certainty: str | None) -> str:
    if not date_certainty:
        return "UNCERTAIN"
    if date_certainty == "provider-reported":
        return "UNCERTAIN"
    return "INFERRED"


def walk_replace_cycle(conn, edge_id: str, replaces_edge_id: str | None, *, limit: int = 64) -> None:
    if not replaces_edge_id:
        return
    if replaces_edge_id == edge_id:
        raise ValueError("self-replacement")
    seen = {edge_id}
    current = replaces_edge_id
    depth = 0
    while current:
        if current in seen:
            raise ValueError("replacement cycle")
        seen.add(current)
        depth += 1
        if depth > limit:
            raise ValueError("replacement cycle")
        row = conn.execute(
            "SELECT replaces_edge_id FROM evidence_edges WHERE id = ?",
            (current,),
        ).fetchone()
        if row is None:
            return
        current = row["replaces_edge_id"] if isinstance(row, dict) or hasattr(row, "keys") else row[0]


def canonical_investigation(investigation_id: str) -> str:
    return f"inv:{investigation_id}"


def canonical_claim() -> str:
    return "claim:primary"


def canonical_snapshot(snapshot_id: str) -> str:
    return f"snapshot:{snapshot_id}"


def canonical_snap_source(snapshot_id: str, index: int) -> str:
    return f"snap:{snapshot_id}:src:{index}"


def canonical_live_source(source_id: str) -> str:
    return f"live_src:{source_id}"


def canonical_url(url: str) -> str:
    return f"url:{normalize_url_key(url)}"


def canonical_site(url: str) -> str:
    host = website_key(url)
    return f"site:{host}" if host else "site:"


def canonical_image(sha256: str) -> str:
    return f"image:{sha256}"


def canonical_page(page_id: str) -> str:
    return f"page:{page_id}"


def canonical_assessment(result_id: str) -> str:
    return f"assess:{result_id}"


def canonical_finding(result_id: str, position: int) -> str:
    return f"finding:{result_id}:{position}"


def canonical_provenance(snapshot_id: str) -> str:
    return f"prov:{snapshot_id}"


def canonical_publication(subject_key: str, date_role: str, published_at: str | None, date_certainty: str | None) -> str:
    return f"pub:{subject_key}:{date_role}:{published_at or ''}:{date_certainty or ''}"


def canonical_observation(kind: str, subject_key: str, observed_at: str) -> str:
    return f"obs:{kind}:{subject_key}:{observed_at}"


_SAFE_KEY = re.compile(r"^[\w:.\-|/=+@%]+$", re.UNICODE)


def is_safe_canonical_key(key: str) -> bool:
    return bool(key) and len(key) <= 512 and _SAFE_KEY.match(key) is not None


def props_claim(text: str) -> dict[str, Any]:
    return {"text": text[:2000], "role": "primary"}


def props_source(source: dict, *, sealed: bool) -> dict[str, Any]:
    return {
        "url": source.get("url") or "",
        "title": source.get("title"),
        "sealed": sealed,
        "publishedAt": source.get("publishedAt"),
        "dateCertainty": source.get("dateCertainty"),
        "dateType": source.get("dateType"),
        "qualityTier": (source.get("quality") or {}).get("tier") if isinstance(source.get("quality"), dict) else source.get("quality_tier"),
    }


class GraphBuilder:
    """Write graph rows inside a caller-owned SQLite transaction."""

    def __init__(self, conn, owner_id: str, investigation_id: str, *, now: str):
        self.conn = conn
        self.owner_id = owner_id
        self.investigation_id = investigation_id
        self.now = now
        self._node_cache: dict[tuple[str, str], str] = {}

    def upsert_node(
        self,
        node_type: str,
        canonical_key: str,
        props: dict,
        *,
        source_table: str | None = None,
        source_row_id: str | None = None,
        snapshot_id: str | None = None,
        assessment_result_id: str | None = None,
    ) -> str:
        if node_type not in NODE_TYPES:
            raise ValueError("invalid node type")
        existing = self.conn.execute(
            """
            SELECT id FROM evidence_nodes
            WHERE investigation_id = ? AND node_type = ? AND canonical_key = ?
            """,
            (self.investigation_id, node_type, canonical_key),
        ).fetchone()
        props_json = json.dumps(props, sort_keys=True, default=str)
        if existing is not None:
            node_id = existing["id"]
            self.conn.execute(
                """
                UPDATE evidence_nodes
                SET props_json = ?, source_table = ?, source_row_id = ?,
                    snapshot_id = COALESCE(?, snapshot_id),
                    assessment_result_id = COALESCE(?, assessment_result_id),
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    props_json,
                    source_table,
                    source_row_id,
                    snapshot_id,
                    assessment_result_id,
                    self.now,
                    node_id,
                ),
            )
        else:
            node_id = hashlib.sha256(
                f"{self.investigation_id}|{node_type}|{canonical_key}".encode()
            ).hexdigest()[:32]
            # Avoid rare collision with existing id.
            while self.conn.execute("SELECT 1 FROM evidence_nodes WHERE id = ?", (node_id,)).fetchone():
                node_id = hashlib.sha256((node_id + canonical_key).encode()).hexdigest()[:32]
            self.conn.execute(
                """
                INSERT INTO evidence_nodes (
                    id, owner_id, investigation_id, node_type, canonical_key,
                    source_table, source_row_id, snapshot_id, assessment_result_id,
                    props_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    node_id,
                    self.owner_id,
                    self.investigation_id,
                    node_type,
                    canonical_key,
                    source_table,
                    source_row_id,
                    snapshot_id,
                    assessment_result_id,
                    props_json,
                    self.now,
                    self.now,
                ),
            )
        self._node_cache[(node_type, canonical_key)] = node_id
        return node_id

    def ensure_active_edge(
        self,
        *,
        src_node_id: str,
        dst_node_id: str,
        rel_type: str,
        certainty: str,
        method: str,
        evidence: dict,
        snapshot_id: str | None = None,
        assessment_result_id: str | None = None,
        allow_replace: bool = False,
    ) -> str:
        validate_certainty(rel_type, certainty, method)
        if src_node_id == dst_node_id:
            raise ValueError("self edge")
        sk = scope_key(snapshot_id, assessment_result_id)
        evidence_json = json.dumps(evidence, sort_keys=True, default=str)
        fingerprint = evidence_fingerprint(
            {
                "rel_type": rel_type,
                "certainty": certainty,
                "method": method,
                "evidence": evidence,
            }
        )
        active = self.conn.execute(
            """
            SELECT edge_id FROM evidence_edge_active
            WHERE investigation_id = ? AND src_node_id = ? AND dst_node_id = ?
              AND rel_type = ? AND scope_key = ?
            """,
            (self.investigation_id, src_node_id, dst_node_id, rel_type, sk),
        ).fetchone()
        if active is not None:
            current = self.conn.execute(
                """
                SELECT id, certainty, method, evidence_json
                FROM evidence_edges WHERE id = ?
                """,
                (active["edge_id"],),
            ).fetchone()
            if current is not None:
                current_fp = evidence_fingerprint(
                    {
                        "rel_type": rel_type,
                        "certainty": current["certainty"],
                        "method": current["method"],
                        "evidence": json.loads(current["evidence_json"] or "{}"),
                    }
                )
                if current_fp == fingerprint:
                    return current["id"]
                if not allow_replace:
                    return current["id"]
                return self._replace_edge(
                    prior_id=current["id"],
                    src_node_id=src_node_id,
                    dst_node_id=dst_node_id,
                    rel_type=rel_type,
                    certainty=certainty,
                    method=method,
                    evidence_json=evidence_json,
                    snapshot_id=snapshot_id,
                    assessment_result_id=assessment_result_id,
                    sk=sk,
                )
        return self._insert_edge(
            src_node_id=src_node_id,
            dst_node_id=dst_node_id,
            rel_type=rel_type,
            certainty=certainty,
            method=method,
            evidence_json=evidence_json,
            snapshot_id=snapshot_id,
            assessment_result_id=assessment_result_id,
            sk=sk,
            replaces_edge_id=None,
        )

    def _replace_edge(self, *, prior_id: str, src_node_id: str, dst_node_id: str, rel_type: str,
                      certainty: str, method: str, evidence_json: str, snapshot_id: str | None,
                      assessment_result_id: str | None, sk: str) -> str:
        prior = self.conn.execute(
            """
            SELECT id, owner_id, investigation_id, src_node_id, dst_node_id, rel_type, scope_key
            FROM evidence_edges WHERE id = ?
            """,
            (prior_id,),
        ).fetchone()
        if prior is None:
            raise ValueError("missing prior edge")
        if prior["owner_id"] != self.owner_id or prior["investigation_id"] != self.investigation_id:
            raise ValueError("cross-owner replace")
        if (
            prior["src_node_id"] != src_node_id
            or prior["dst_node_id"] != dst_node_id
            or prior["rel_type"] != rel_type
            or prior["scope_key"] != sk
        ):
            raise ValueError("replace identity mismatch")
        new_id = hashlib.sha256(f"edge|{prior_id}|{evidence_json}|{self.now}".encode()).hexdigest()[:32]
        walk_replace_cycle(self.conn, new_id, prior_id)
        edge_id = self._insert_edge(
            src_node_id=src_node_id,
            dst_node_id=dst_node_id,
            rel_type=rel_type,
            certainty=certainty,
            method=method,
            evidence_json=evidence_json,
            snapshot_id=snapshot_id,
            assessment_result_id=assessment_result_id,
            sk=sk,
            replaces_edge_id=prior_id,
            edge_id=new_id,
        )
        return edge_id

    def _insert_edge(
        self,
        *,
        src_node_id: str,
        dst_node_id: str,
        rel_type: str,
        certainty: str,
        method: str,
        evidence_json: str,
        snapshot_id: str | None,
        assessment_result_id: str | None,
        sk: str,
        replaces_edge_id: str | None,
        edge_id: str | None = None,
    ) -> str:
        if replaces_edge_id:
            walk_replace_cycle(self.conn, edge_id or "pending", replaces_edge_id)
            prior = self.conn.execute(
                "SELECT owner_id, investigation_id FROM evidence_edges WHERE id = ?",
                (replaces_edge_id,),
            ).fetchone()
            if prior is None:
                raise ValueError("missing replace target")
            if prior["owner_id"] != self.owner_id or prior["investigation_id"] != self.investigation_id:
                raise ValueError("cross-investigation replace")
        eid = edge_id or hashlib.sha256(
            f"{self.investigation_id}|{src_node_id}|{dst_node_id}|{rel_type}|{sk}|{evidence_json}".encode()
        ).hexdigest()[:32]
        while self.conn.execute("SELECT 1 FROM evidence_edges WHERE id = ?", (eid,)).fetchone():
            if replaces_edge_id:
                break
            eid = hashlib.sha256((eid + "x").encode()).hexdigest()[:32]
        if replaces_edge_id:
            walk_replace_cycle(self.conn, eid, replaces_edge_id)
        self.conn.execute(
            """
            INSERT INTO evidence_edges (
                id, owner_id, investigation_id, src_node_id, dst_node_id, rel_type,
                certainty, method, evidence_json, snapshot_id, assessment_result_id,
                scope_key, replaces_edge_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                eid,
                self.owner_id,
                self.investigation_id,
                src_node_id,
                dst_node_id,
                rel_type,
                certainty,
                method,
                evidence_json,
                snapshot_id,
                assessment_result_id,
                sk,
                replaces_edge_id,
                self.now,
            ),
        )
        self.conn.execute(
            """
            INSERT INTO evidence_edge_active (
                investigation_id, src_node_id, dst_node_id, rel_type, scope_key, edge_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(investigation_id, src_node_id, dst_node_id, rel_type, scope_key)
            DO UPDATE SET edge_id = excluded.edge_id
            """,
            (self.investigation_id, src_node_id, dst_node_id, rel_type, sk, eid),
        )
        return eid

    def set_checkpoint(self, scope_type: str, scope_id: str, status: str, error_code: str | None = None) -> None:
        row = self.conn.execute(
            """
            SELECT attempt_count FROM evidence_graph_checkpoints
            WHERE investigation_id = ? AND scope_type = ? AND scope_id = ?
            """,
            (self.investigation_id, scope_type, scope_id),
        ).fetchone()
        attempts = int(row["attempt_count"]) + 1 if row is not None else 1
        self.conn.execute(
            """
            INSERT INTO evidence_graph_checkpoints (
                investigation_id, owner_id, scope_type, scope_id, status,
                attempt_count, last_error_code, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(investigation_id, scope_type, scope_id) DO UPDATE SET
                status = excluded.status,
                attempt_count = excluded.attempt_count,
                last_error_code = excluded.last_error_code,
                updated_at = excluded.updated_at,
                owner_id = excluded.owner_id
            """,
            (
                self.investigation_id,
                self.owner_id,
                scope_type,
                scope_id,
                status,
                attempts,
                error_code,
                self.now,
            ),
        )


def delete_graph_for_investigation(conn, owner_id: str, investigation_id: str) -> None:
    conn.execute(
        "DELETE FROM evidence_graph_checkpoints WHERE investigation_id = ? AND owner_id = ?",
        (investigation_id, owner_id),
    )
    conn.execute(
        "DELETE FROM evidence_edge_active WHERE investigation_id = ?",
        (investigation_id,),
    )
    conn.execute(
        "DELETE FROM evidence_edges WHERE investigation_id = ? AND owner_id = ?",
        (investigation_id, owner_id),
    )
    conn.execute(
        "DELETE FROM evidence_nodes WHERE investigation_id = ? AND owner_id = ?",
        (investigation_id, owner_id),
    )


def delete_graph_for_owner(conn, owner_id: str) -> None:
    owned = "(SELECT id FROM investigations WHERE owner_id = ?)"
    conn.execute(
        f"""
        DELETE FROM evidence_graph_checkpoints
        WHERE owner_id = ? OR investigation_id IN {owned}
        """,
        (owner_id, owner_id),
    )
    conn.execute(
        f"""
        DELETE FROM evidence_edge_active
        WHERE investigation_id IN {owned}
        """,
        (owner_id,),
    )
    conn.execute(
        f"""
        DELETE FROM evidence_edges
        WHERE owner_id = ? OR investigation_id IN {owned}
        """,
        (owner_id, owner_id),
    )
    conn.execute(
        f"""
        DELETE FROM evidence_nodes
        WHERE owner_id = ? OR investigation_id IN {owned}
        """,
        (owner_id, owner_id),
    )
