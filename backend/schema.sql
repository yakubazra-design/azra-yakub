-- Local evidence ledger. Rows record what the server stored. They do not
-- prove that a source is authentic. Passwords are stored only as Argon2id
-- hashes. Older databases may lack email and password_hash; startup adds
-- those columns without deleting investigations.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    email TEXT,
    password_hash TEXT
);

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL,
    input_text TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS page_fetches (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL UNIQUE REFERENCES investigations(id),
    requested_url TEXT NOT NULL,
    final_url TEXT NOT NULL,
    title TEXT,
    body_text TEXT NOT NULL,
    published_at TEXT,
    date_certainty TEXT,
    date_type TEXT,
    provider TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_sources (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    position INTEGER NOT NULL,
    url TEXT NOT NULL,
    title TEXT,
    snippet TEXT NOT NULL,
    published_at TEXT,
    date_certainty TEXT,
    date_type TEXT,
    provider TEXT,
    quality_tier TEXT NOT NULL,
    quality_reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (investigation_id, position)
);

CREATE TABLE IF NOT EXISTS claim_analyses (
    investigation_id TEXT PRIMARY KEY REFERENCES investigations(id),
    primary_claim TEXT NOT NULL,
    verifiable_points TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

-- A sealed snapshot records what an assessment was allowed to see. It does
-- not prove that the underlying source material is authentic. The token
-- itself is not stored; token_hash is an HMAC. consumed_at is the only
-- column that may change after the row is written.
CREATE TABLE IF NOT EXISTS assessment_snapshots (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    owner_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE TRIGGER IF NOT EXISTS assessment_snapshots_sealed
BEFORE UPDATE OF id, investigation_id, owner_id, token_hash, snapshot_json, created_at, expires_at
ON assessment_snapshots
BEGIN
    SELECT RAISE(ABORT, 'sealed snapshot');
END;

-- Fixed-window counters. The subject is an account id or the connection
-- address. Passwords, session tokens, and assessment tokens are not stored.
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket TEXT NOT NULL,
    subject TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (bucket, subject, window_start)
);

-- One submitted image per investigation. The file bytes are not stored in
-- this database. storage_name is a server-generated file name, not a path
-- and not the name supplied by the browser.
CREATE TABLE IF NOT EXISTS image_assets (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL UNIQUE REFERENCES investigations(id),
    owner_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    received_at TEXT NOT NULL,
    retention TEXT NOT NULL,
    client_hash_status TEXT NOT NULL,
    storage_name TEXT NOT NULL,
    consent_version TEXT NOT NULL,
    metadata_consent_version TEXT NOT NULL,
    metadata_consent_decision TEXT NOT NULL,
    metadata_consent_at TEXT NOT NULL
);

-- A file that must still be removed. The row keeps the name when replacement
-- or a failed write cannot unlink it yet. Account and investigation deletion
-- remove these files and then these rows. A retry is safe when the file is
-- already gone.
CREATE TABLE IF NOT EXISTS asset_cleanup (
    storage_name TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- A deletion that has started. The row is written in the first deletion
-- transaction even when there is no image or cleanup row yet. It stays
-- until that account or investigation is actually deleted. investigation_id
-- is an empty string when every investigation belonging to the account is
-- being deleted. Uploads and new snapshots stay refused while the row exists.
CREATE TABLE IF NOT EXISTS pending_deletions (
    owner_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (owner_id, investigation_id)
);

CREATE INDEX IF NOT EXISTS investigations_owner ON investigations(owner_id);
CREATE INDEX IF NOT EXISTS image_assets_owner ON image_assets(owner_id);
CREATE INDEX IF NOT EXISTS asset_cleanup_owner ON asset_cleanup(owner_id);
CREATE INDEX IF NOT EXISTS asset_cleanup_investigation ON asset_cleanup(investigation_id);
CREATE INDEX IF NOT EXISTS assessment_snapshots_investigation ON assessment_snapshots(investigation_id);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS evidence_sources_investigation ON evidence_sources(investigation_id);

-- Composite uniqueness so assessment_results can enforce owner/investigation/snapshot
-- consistency with foreign keys (Phase A Evidence Intelligence persistence).
CREATE UNIQUE INDEX IF NOT EXISTS investigations_id_owner
    ON investigations(id, owner_id);
CREATE UNIQUE INDEX IF NOT EXISTS assessment_snapshots_id_inv_owner
    ON assessment_snapshots(id, investigation_id, owner_id);

-- Durable assessment outcomes and findings. A row records what the server
-- stored for one sealed snapshot. It does not prove the claim is true.
-- One result per snapshot (completed or failed). Assessment content is
-- immutable; authorized deletion of the investigation or account removes rows.
CREATE TABLE IF NOT EXISTS assessment_results (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('completed', 'failed')),
    model_assessment TEXT,
    facing_assessment TEXT,
    failure_code TEXT,
    failure_message TEXT,
    why_json TEXT,
    uncertainty_json TEXT,
    original_material_json TEXT,
    image_evidence_json TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (snapshot_id),
    CHECK (
        (
            status = 'completed'
            AND model_assessment IS NOT NULL
            AND facing_assessment IS NOT NULL
            AND model_assessment IN (
                'VERIFIED', 'PARTIALLY_VERIFIED', 'CONTRADICTED',
                'INSUFFICIENT_EVIDENCE', 'POTENTIAL_MANIPULATION', 'UNRESOLVED'
            )
            AND facing_assessment IN (
                'VERIFIED', 'PARTIALLY_VERIFIED', 'CONTRADICTED',
                'INSUFFICIENT_EVIDENCE', 'POTENTIAL_MANIPULATION', 'UNRESOLVED'
            )
            AND failure_code IS NULL
            AND failure_message IS NULL
            AND why_json IS NOT NULL
            AND uncertainty_json IS NOT NULL
            AND original_material_json IS NOT NULL
        )
        OR
        (
            status = 'failed'
            AND model_assessment IS NULL
            AND facing_assessment IS NULL
            AND failure_code IS NOT NULL
            AND why_json IS NULL
            AND uncertainty_json IS NULL
            AND original_material_json IS NULL
            AND image_evidence_json IS NULL
        )
    ),
    FOREIGN KEY (investigation_id, owner_id)
        REFERENCES investigations(id, owner_id),
    FOREIGN KEY (snapshot_id, investigation_id, owner_id)
        REFERENCES assessment_snapshots(id, investigation_id, owner_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    assessment_result_id TEXT NOT NULL REFERENCES assessment_results(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    finding_type TEXT NOT NULL,
    evidence_status TEXT NOT NULL,
    alignment_reason TEXT,
    text TEXT NOT NULL,
    source_indexes_json TEXT NOT NULL,
    UNIQUE (assessment_result_id, position)
);

-- Append-only links between completed assessments. Never mutate result rows.
CREATE TABLE IF NOT EXISTS assessment_supersessions (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    prior_result_id TEXT NOT NULL REFERENCES assessment_results(id),
    successor_result_id TEXT NOT NULL REFERENCES assessment_results(id),
    reason TEXT NOT NULL CHECK (reason IN ('reassessment', 'correction')),
    created_at TEXT NOT NULL,
    UNIQUE (prior_result_id, successor_result_id),
    CHECK (prior_result_id <> successor_result_id),
    FOREIGN KEY (investigation_id, owner_id)
        REFERENCES investigations(id, owner_id)
);

CREATE INDEX IF NOT EXISTS assessment_results_investigation_created
    ON assessment_results(investigation_id, created_at);
CREATE INDEX IF NOT EXISTS assessment_results_owner_created
    ON assessment_results(owner_id, created_at);
CREATE INDEX IF NOT EXISTS findings_assessment_result
    ON findings(assessment_result_id);
CREATE INDEX IF NOT EXISTS assessment_supersessions_investigation
    ON assessment_supersessions(investigation_id, created_at);

-- Content is immutable. DELETE remains allowed for investigation/account erasure.
CREATE TRIGGER IF NOT EXISTS assessment_results_immutable
BEFORE UPDATE ON assessment_results
BEGIN
    SELECT RAISE(ABORT, 'immutable assessment result');
END;

CREATE TRIGGER IF NOT EXISTS findings_immutable
BEFORE UPDATE ON findings
BEGIN
    SELECT RAISE(ABORT, 'immutable finding');
END;

CREATE TRIGGER IF NOT EXISTS assessment_supersessions_immutable
BEFORE UPDATE ON assessment_supersessions
BEGIN
    SELECT RAISE(ABORT, 'immutable assessment supersession');
END;

-- Findings may attach only to completed assessment results.
CREATE TRIGGER IF NOT EXISTS findings_require_completed
BEFORE INSERT ON findings
BEGIN
    SELECT RAISE(ABORT, 'findings require completed assessment')
    WHERE NOT EXISTS (
        SELECT 1 FROM assessment_results
        WHERE id = NEW.assessment_result_id AND status = 'completed'
    );
END;

-- Supersession endpoints must be distinct completed results for the same owner/investigation.
CREATE TRIGGER IF NOT EXISTS assessment_supersessions_integrity
BEFORE INSERT ON assessment_supersessions
BEGIN
    SELECT RAISE(ABORT, 'invalid assessment supersession')
    WHERE NOT EXISTS (
        SELECT 1
        FROM assessment_results prior
        JOIN assessment_results successor ON successor.id = NEW.successor_result_id
        WHERE prior.id = NEW.prior_result_id
          AND prior.status = 'completed'
          AND successor.status = 'completed'
          AND prior.owner_id = NEW.owner_id
          AND successor.owner_id = NEW.owner_id
          AND prior.investigation_id = NEW.investigation_id
          AND successor.investigation_id = NEW.investigation_id
          AND prior.id <> successor.id
    );
END;

-- Evidence Intelligence Graph (E.9.5C). Intra-investigation only.
-- Relationships describe stored records; they do not prove a claim is true.
CREATE TABLE IF NOT EXISTS evidence_nodes (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    node_type TEXT NOT NULL CHECK (node_type IN (
        'investigation',
        'claim',
        'evidence_source',
        'url',
        'website',
        'image',
        'page',
        'finding',
        'assessment_result',
        'snapshot',
        'provenance_record',
        'publication_event',
        'observation_event'
    )),
    canonical_key TEXT NOT NULL,
    source_table TEXT,
    source_row_id TEXT,
    snapshot_id TEXT,
    assessment_result_id TEXT,
    props_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (investigation_id, node_type, canonical_key),
    FOREIGN KEY (investigation_id, owner_id)
        REFERENCES investigations(id, owner_id),
    FOREIGN KEY (snapshot_id, investigation_id, owner_id)
        REFERENCES assessment_snapshots(id, investigation_id, owner_id)
);

CREATE TABLE IF NOT EXISTS evidence_edges (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    src_node_id TEXT NOT NULL REFERENCES evidence_nodes(id),
    dst_node_id TEXT NOT NULL REFERENCES evidence_nodes(id),
    rel_type TEXT NOT NULL CHECK (rel_type IN (
        'CONTAINS',
        'REFERENCES',
        'DERIVED_FROM',
        'SUPPORTS',
        'CONTRADICTS',
        'PUBLISHED_AT',
        'OBSERVED_AT',
        'SUPERSEDES'
    )),
    certainty TEXT NOT NULL CHECK (certainty IN ('CONFIRMED', 'INFERRED', 'UNCERTAIN')),
    method TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    snapshot_id TEXT,
    assessment_result_id TEXT,
    scope_key TEXT NOT NULL,
    replaces_edge_id TEXT REFERENCES evidence_edges(id),
    created_at TEXT NOT NULL,
    CHECK (src_node_id <> dst_node_id),
    CHECK (replaces_edge_id IS NULL OR replaces_edge_id <> id),
    FOREIGN KEY (investigation_id, owner_id)
        REFERENCES investigations(id, owner_id),
    FOREIGN KEY (snapshot_id, investigation_id, owner_id)
        REFERENCES assessment_snapshots(id, investigation_id, owner_id)
);

CREATE TABLE IF NOT EXISTS evidence_edge_active (
    investigation_id TEXT NOT NULL,
    src_node_id TEXT NOT NULL,
    dst_node_id TEXT NOT NULL,
    rel_type TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    edge_id TEXT NOT NULL UNIQUE REFERENCES evidence_edges(id),
    PRIMARY KEY (investigation_id, src_node_id, dst_node_id, rel_type, scope_key)
);

CREATE TABLE IF NOT EXISTS evidence_graph_checkpoints (
    investigation_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    scope_type TEXT NOT NULL CHECK (scope_type IN (
        'investigation_skeleton',
        'snapshot',
        'assessment_result'
    )),
    scope_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'complete', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error_code TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (investigation_id, scope_type, scope_id),
    FOREIGN KEY (investigation_id, owner_id)
        REFERENCES investigations(id, owner_id)
);

CREATE INDEX IF NOT EXISTS evidence_nodes_investigation_type
    ON evidence_nodes(investigation_id, node_type);
CREATE INDEX IF NOT EXISTS evidence_nodes_owner_created
    ON evidence_nodes(owner_id, created_at);
CREATE INDEX IF NOT EXISTS evidence_edges_investigation_created
    ON evidence_edges(investigation_id, created_at);
CREATE INDEX IF NOT EXISTS evidence_edges_src ON evidence_edges(src_node_id);
CREATE INDEX IF NOT EXISTS evidence_edges_dst ON evidence_edges(dst_node_id);
CREATE INDEX IF NOT EXISTS evidence_graph_checkpoints_status
    ON evidence_graph_checkpoints(investigation_id, status);

CREATE TRIGGER IF NOT EXISTS evidence_edges_same_scope
BEFORE INSERT ON evidence_edges
BEGIN
    SELECT RAISE(ABORT, 'edge endpoints out of investigation scope')
    WHERE NOT EXISTS (
        SELECT 1 FROM evidence_nodes s
        JOIN evidence_nodes d ON d.id = NEW.dst_node_id
        WHERE s.id = NEW.src_node_id
          AND s.owner_id = NEW.owner_id
          AND d.owner_id = NEW.owner_id
          AND s.investigation_id = NEW.investigation_id
          AND d.investigation_id = NEW.investigation_id
    );
END;

-- Application validate_certainty and this trigger must agree:
-- PUBLISHED_AT is never CONFIRMED; CONFIRMED requires the system allow-list.
CREATE TRIGGER IF NOT EXISTS evidence_edges_certainty_policy
BEFORE INSERT ON evidence_edges
BEGIN
    SELECT RAISE(ABORT, 'invalid certainty for relationship')
    WHERE
        (NEW.rel_type = 'PUBLISHED_AT' AND NEW.certainty = 'CONFIRMED')
        OR (
            NEW.certainty = 'CONFIRMED'
            AND NEW.method NOT IN (
                'system_structural',
                'system_clock',
                'system_supersession',
                'system_literal_alignment'
            )
        );
END;

CREATE TRIGGER IF NOT EXISTS evidence_edges_immutable
BEFORE UPDATE OF owner_id, investigation_id, src_node_id, dst_node_id, rel_type,
    certainty, method, evidence_json, snapshot_id, assessment_result_id,
    scope_key, replaces_edge_id, created_at
ON evidence_edges
BEGIN
    SELECT RAISE(ABORT, 'immutable evidence edge');
END;

CREATE TRIGGER IF NOT EXISTS evidence_edge_active_immutable
BEFORE UPDATE OF investigation_id, src_node_id, dst_node_id, rel_type, scope_key
ON evidence_edge_active
BEGIN
    SELECT RAISE(ABORT, 'immutable evidence edge active key');
END;

-- V1.2.A Secure Video Ingestion (additive). One video attachment per
-- investigation. Bytes are not stored in SQLite. attachment_status follows
-- the V1.2.2E state machine; missing/integrity_failed rows are never
-- auto-deleted by reconcile (seal remains blocked until ready or explicit removal).
CREATE TABLE IF NOT EXISTS video_assets (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL UNIQUE REFERENCES investigations(id),
    owner_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    received_at TEXT NOT NULL,
    retention TEXT NOT NULL CHECK (retention IN ('retained', 'retiring')),
    client_hash_status TEXT NOT NULL,
    storage_name TEXT NOT NULL,
    consent_version TEXT NOT NULL,
    metadata_consent_version TEXT NOT NULL,
    metadata_consent_decision TEXT NOT NULL,
    metadata_consent_at TEXT NOT NULL,
    attachment_status TEXT NOT NULL CHECK (attachment_status IN (
        'ready', 'missing', 'integrity_failed', 'retiring', 'removed_by_user'
    )),
    failure_code TEXT,
    duration_ms INTEGER,
    width INTEGER,
    height INTEGER,
    video_codec TEXT,
    audio_codec TEXT,
    format_name TEXT,
    frame_rate TEXT,
    bit_rate INTEGER,
    probe_summary_json TEXT,
    probed_at TEXT,
    CHECK (byte_length >= 0)
);

CREATE TABLE IF NOT EXISTS video_processing_runs (
    id TEXT PRIMARY KEY,
    video_asset_id TEXT,
    investigation_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    stage TEXT NOT NULL CHECK (stage IN ('probe')),
    status TEXT NOT NULL CHECK (status IN ('started', 'succeeded', 'failed', 'interrupted')),
    failure_code TEXT,
    toolchain_version TEXT,
    isolation_tier TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    resource_ms INTEGER
);

CREATE TABLE IF NOT EXISTS video_asset_cleanup (
    storage_name TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS video_assets_owner ON video_assets(owner_id);
CREATE INDEX IF NOT EXISTS video_assets_sha ON video_assets(owner_id, sha256);
CREATE INDEX IF NOT EXISTS video_processing_runs_investigation
    ON video_processing_runs(investigation_id, started_at);
CREATE INDEX IF NOT EXISTS video_asset_cleanup_owner ON video_asset_cleanup(owner_id);
CREATE INDEX IF NOT EXISTS video_asset_cleanup_investigation
    ON video_asset_cleanup(investigation_id);
