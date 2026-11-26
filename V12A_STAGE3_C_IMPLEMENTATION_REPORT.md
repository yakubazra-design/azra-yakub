# RealityCheck AI — V1.2.A Stage 3.C Implementation Report

**Document:** `V12A_STAGE3_C_IMPLEMENTATION_REPORT.md`  
**Phase:** Phase 2  
**Version:** V1.2.A  
**Stage:** 3.C — Video Probe Processing Run Persistence  
**Generated (UTC):** 2026-11-26T07:20:00Z  
**Branch:** `cursor/stage-3c-video-probe-run-persistence-ced2`  
**Base HEAD at start:** `f9905423133e61e734dfe23a944cfe8e5991d885`  
**Stash (untouched):** `stash@{0}` `7dc169db5edd3b9932ac2872947ffecbf8984af0` — `preserve-e32-frontend-wip`  
**Prior acceptance:** Stage 3.B.3 ACCEPT WITH DOCUMENTED RESIDUALS (`V12A_STAGE3_B3_INDEPENDENT_FINAL_ACCEPTANCE.md`, full-file SHA-256 `fb5080e748036934721357e05fdfac98138268f631e9596cffcec8f7db368cf9`)

---

## 1. Executive summary

Stage 3.C implements durable `video_processing_runs` persistence for **actual user-upload** Tier A probe operations.

- Reused the existing `video_processing_runs` schema (**no migration**).
- Inserts `stage='probe'` / `status='started'` immediately before `probe_video_file` on the upload path, then completes to `succeeded` or `failed` after the probe outcome (and after durable asset save on success).
- Boot self-tests, sandboxed version capture, and synthetic `probe_video_file(..., skip_boot_check=True)` calls do **not** create user processing runs.
- DB transactions are not held open during FFprobe.
- Successful HTTP responses require successful processing-run completion after asset save.
- Feature flags unchanged: `video_ingest_enabled=False`, `video_allow_tier_b=False`, `video_seal_integration=True`.
- Stage 3.A / 3.A.1 / 3.B contracts preserved; frontend/stash untouched by this stage’s edits.
- New tests: **21 passed**. Broad regression including 3.A–3.C + image/seal/snapshot: **133 passed**.

**Stage 3.D was not started.**

---

## 2. Architecture inspection findings

| Area | Finding |
|---|---|
| Table | `video_processing_runs` already exists in `backend/schema.sql` |
| Columns | `id`, `video_asset_id` (nullable), `investigation_id`, `owner_id`, `stage` CHECK (`probe`), `status` CHECK (`started`/`succeeded`/`failed`/`interrupted`), `failure_code`, `toolchain_version`, `isolation_tier`, `started_at`, `finished_at`, `resource_ms` |
| Prior inserts | **None** — only DELETE on investigation/account erasure |
| User probe site | `POST /api/investigations/{id}/video` in `main.py` after container validation, calling `probe_video_file` |
| Boot/canary | `ensure_boot_self_test` / `tier_a_ready` in `video_probe.py` — never touched ledger runs (Stage 3.A test already asserted count==0) |
| Locking | Owner-scoped `fcntl.flock` via `VideoStore.try_acquire_upload_lock` wraps upload+probe |
| Erasure | Already deletes `video_processing_runs` by owner/investigation |

**Discrepancy vs prompt assumption:** none material. Prompt assumed missing insert path — confirmed. Schema already supports required fields → **no migration**.

---

## 3. Concise implementation plan (executed)

1. Add ledger APIs: `start_video_probe_run`, `complete_video_probe_run`, `video_processing_runs` (owner-scoped read for tests/internal).
2. Export `sandboxed_ffprobe_version()` for safe toolchain labeling (no host `-version`).
3. Wire upload path: start → probe → on failure complete failed; on success save asset → complete succeeded with `video_asset_id`.
4. Fail closed when start persistence fails (no probe). Fail closed when success-path complete fails (no durable success response).
5. Add `tests/test_video_stage3c.py`; run Stage 3.C then 3.A–3.B regressions.
6. Do not change flags, Nginx, frontend, stash, or live ledger.

---

## 4. Files changed

| Path | Role |
|---|---|
| `backend/app/ledger.py` | Probe-run start/complete/list APIs; path-like failure codes rejected |
| `backend/app/main.py` | Upload-path persistence wiring + `time` / version import |
| `backend/app/video_probe.py` | Public `sandboxed_ffprobe_version()` |
| `backend/tests/test_video_stage3c.py` | **New** Stage 3.C tests |
| `V12A_STAGE3_C_IMPLEMENTATION_REPORT.md` | This report |

No schema migration files. No frontend edits in Stage 3.C. No stash operations.

---

## 5. Processing lifecycle mapping

| Event | Persistence behavior |
|---|---|
| Pre-probe validation fail (empty/unsupported container) | **No** processing run |
| Valid container; about to probe | `started` row committed |
| Probe fails (timeout, output limit, unsupported/codec, sandbox, toolchain, etc.) | `failed` + safe `failure_code` |
| Probe succeeds; promote/save fails | `failed` with store/ledger classification |
| Probe succeeds; asset saved; run complete succeeds | `succeeded` + `video_asset_id` |
| Probe succeeds; run complete fails | HTTP unavailable — **not** durable success |
| Boot self-test / version / synthetic probe | **No** user run |

Statuses used: `started`, `succeeded`, `failed`. `interrupted` remains available in schema for future use; not written by this path.

---

## 6. Security review of the new path

| Control | Status |
|---|---|
| User-upload-only runs | Only `upload_video` calls start/complete |
| No paths/commands/stdout/stderr/bytes in rows | Enforced |
| Failure code sanitization | Rejects path-like / oversized codes |
| Owner-scoped start/complete/list | `owner_id` + investigation ownership check |
| No public processing-history endpoint | Confirmed |
| Tier A sandbox unchanged | No new FFprobe invocation mechanism |
| Flags unchanged | Defaults remain ingest off |
| Stage 3.B `videoEvidence` meaning unchanged | Projection path not altered for authenticity |
| Live ledger not accessed | Tests use `tmp_path` only |

---

## 7. Compatibility with Stage 3.A / 3.B

- SHA-256 identity, sealing, path-free `sealedVideo`, Option A `videoEvidence` projection preserved.
- Client `videoEvidence` / `sealedVideo` remain untrusted.
- No video bytes added to model prompts.
- Processing runs are **not** presented as authenticity evidence.
- `video_seal_integration` unchanged (`True`).
- Frontend Video Evidence UI not modified in Stage 3.C.

---

## 8. Test results

### Stage 3.C focused

```bash
cd /workspace/backend && python -m pytest tests/test_video_stage3c.py -q --tb=line
```

**21 passed**, 1 warning (Starlette TestClient deprecation), ~8.8s. **0 failed.**

Coverage includes: success run; failed codes (invalid/timeout/output-limit/sandbox/toolchain/codec); pre-probe no-run; boot/version/synthetic no-run; cross-account; cross-investigation; retry without incorrect duplicate completion; asset deletion keeps history; investigation/account erasure clears runs; persistence failure after probe; start failure aborts before probe; owner-lock concurrency check; defaults; failure-code sanitization.

### Broad regression

```bash
cd /workspace/backend && python -m pytest \
  tests/test_video_stage3a.py \
  tests/test_video_stage3a1.py \
  tests/test_video_stage3b.py \
  tests/test_video_stage3b_frontend.py \
  tests/test_video_stage3c.py \
  tests/test_image_evidence.py \
  tests/test_seal_flow.py \
  tests/test_seal_http.py \
  tests/test_snapshots.py \
  tests/test_provenance_snapshot.py -q --tb=line
```

**133 passed**, 1 warning, ~32s. **0 failed.**

### Erasure suite

```bash
cd /workspace/backend && python -m pytest tests/test_erasure.py -q --tb=line
```

**5 passed**, 1 warning.

Logs: `/opt/cursor/artifacts/stage3c_tests.log`, `stage3c_regression.log`, `stage3c_erasure.log`.

---

## 9. Migration decision

**No migration required.** Existing `video_processing_runs` CHECK constraints and columns are sufficient. Live ledger was not migrated or queried.

---

## 10. Remaining limitations (unchanged)

- L1 / L2 reconcile residuals.
- Single-host locking only.
- Filesystem + SQLite not one atomic transaction (probe remains outside DB txn by design).
- No GitHub CI workflow in prior posture.
- Nginx 8 MiB body limit.
- Video ingestion remains disabled.
- Stage 3.B residuals (assets disclosure wording; `_public_video` probe extras) unchanged.

Stage 3.C-specific residual: if probe fails and failure-run completion also fails, the API still returns the probe error (correct for the client) and a `started` row may remain until erasure — not reported as success.

---

## 11. Preservation confirmations

| Check | Result |
|---|---|
| Stash identity | `7dc169db5edd3b9932ac2872947ffecbf8984af0` unchanged |
| No stash apply/pop/drop | Confirmed |
| Live ledger not accessed | Confirmed |
| Flags unchanged | Confirmed |
| Stage 3.D not started | Confirmed |
| Frontend not rewritten for 3.C | Confirmed |

---

## 12. Recommendation

Stage 3.C is ready for owner review / independent audit. Do **not** begin Stage 3.D automatically. Keep ingest disabled until explicitly authorized.

---

## 13. SHA-256 checksum and byte count

The SHA-256 below is computed over the UTF-8 bytes of sections 1–12 (everything before the `## 13.` heading).

| Property | Value |
|---|---|
| Sections 1–12 SHA-256 | `ee0827daeec980d1f12373c5edcd44d13286ffa2f6fbd34e6af039a8dfa4c360` |
| Sections 1–12 byte count | 8709 |

---

*End of Stage 3.C implementation report.*
