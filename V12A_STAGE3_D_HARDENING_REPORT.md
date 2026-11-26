# RealityCheck AI — V1.2.A Stage 3.D Hardening Report

**Document:** `V12A_STAGE3_D_HARDENING_REPORT.md`  
**Phase:** Phase 2  
**Version:** V1.2.A  
**Stage:** 3.D — End-to-End Hardening, Integration Testing and Regression Verification  
**Task type:** Controlled engineering implementation and verification  
**Generated (UTC):** 2026-11-26T07:38:00Z  
**Branch:** `cursor/stage-3c-video-probe-run-persistence-ced2`  
**Base HEAD at Stage 3.D start:** `796b937285c81b3f213c877b4d71cdaf36134b5d`  
**Stash (untouched):** `stash@{0}` `7dc169db5edd3b9932ac2872947ffecbf8984af0` — `preserve-e32-frontend-wip`  
**Prior acceptance:** Stage 3.C accepted with residuals (`V12A_STAGE3_C_IMPLEMENTATION_REPORT.md` SHA-256 `59a3d6d579044318a812e2c53b323e0d96a6a064ad1c04d811496b1507dfc129`); Stage 3.C.1 audit PASS WITH LIMITATIONS (`V12A_STAGE3_C1_INDEPENDENT_SECURITY_AUDIT.md` SHA-256 `db6f6225a63b063da7945ab758c78e072a5f39f15b84e8f27b3fcc2318f4e5c0`)

---

## 1. Executive summary

Stage 3.D performed controlled end-to-end hardening verification of the integrated image and video investigation workflow on the accepted Stage 3.C baseline.

- **No production application code changes were required.** No genuine in-scope functional defect was found that required a product fix.
- New hardening suite: `backend/tests/test_stage3d_e2e_hardening.py` — **23 passed**.
- Stage 3.A–3.D consolidated: **94 passed** (~33s).
- Broader related regressions: **175 passed**, **1 failed** (known accepted residual #8 — assets disclosure wording).
- Additional API/evidence/integration regressions: **110 passed**.
- Feature flags unchanged: `video_ingest_enabled=False`, `video_allow_tier_b=False`, `video_seal_integration=True`.
- Stash untouched. Live ledger not opened. Video ingestion not enabled. Stage 3.E not started. No deploy.

**Verdict: PASS WITH DOCUMENTED RESIDUALS** (all residuals are pre-accepted; none newly introduced by Stage 3.D).

---

## 2. Repository state verification (first action)

| Check | Result |
|---|---|
| Branch | `cursor/stage-3c-video-probe-run-persistence-ced2` |
| HEAD | `796b937` — *Implement Stage 3.C video probe processing-run persistence.* |
| Tracked working tree at start | Clean (no modified tracked files) |
| Untracked (preserved) | Prior `V12A_*` reports, `.env.example`, `.gitignore`, `deploy/`, `owner-download/`, `realitycheck-ai/`, Stage 3.C.1 audit |
| Stage 3.C report SHA-256 | `59a3d6d5…` **MATCH** companion `.sha256` |
| Stage 3.C.1 audit SHA-256 | `db6f6225…` **MATCH** companion `.sha256` |
| Stage 3.B frontend | Present under `frontend/` (`engine.js` contains `serverVideoEvidence` / `renderVideoEvidence`) |
| Stage 3.A/3.B/3.C tests | Present (`test_video_stage3a.py`, `3a1`, `3b`, `3b_frontend`, `3c`) |
| Stash | `stash@{0}` `7dc169db…` `preserve-e32-frontend-wip` — **unchanged** |
| Defaults | ingest **off**, Tier B **off**, seal integration **on** |

No material discrepancy vs the Stage 3.C accepted state. Work proceeded on the current branch without switching.

---

## 3. Scope executed

| Subsection | Action |
|---|---|
| 3.D.1 End-to-end workflow | Image-only, video-only, and combined image+video assessment paths with mocked OpenAI |
| 3.D.2 Failure handling | Invalid uploads, probe failure codes, success-complete failure, concurrent upload lock, oversized body |
| 3.D.3 Security / ownership / erasure | Cross-account rejection; no download/stream routes; account erasure removes runs+assets |
| 3.D.4 Snapshot consistency | Client sealedVideo/videoEvidence ignored; post-seal DELETE rejected; bytes-loss → subsequently_deleted without identity rewrite |
| 3.D.5 Resource limits | Constants verified; probe scratch cleaned; oversized rejected pre-run |
| 3.D.6 Consolidated regression | Stage 3.A–3.D + broader image/seal/erasure/video/limits suites |

Isolated temporary ledgers and temporary video stores only.

---

## 4. Files changed

| Path | Role |
|---|---|
| `backend/tests/test_stage3d_e2e_hardening.py` | **New** Stage 3.D E2E hardening and regression tests |
| `V12A_STAGE3_D_HARDENING_REPORT.md` | This report |
| `V12A_STAGE3_D_HARDENING_REPORT.md.sha256` | Full-file SHA-256 companion |

No changes to `backend/app/*`, feature flags, Nginx, frontend, stash, `.env`, or schema.

---

## 5. End-to-end workflow results (3.D.1)

| Scenario | Observed |
|---|---|
| Image-only create → upload → assess → latest → delete | `imageEvidence` present; `videoEvidence` null; prompt excludes videoEvidence; snapshots cleared on investigation delete |
| Video-only create → upload → probe run → assess (client forgeries ignored) → latest | `videoEvidence` version `video-evidence-1`; SHA-256 matches asset; processing-run `succeeded`; sealedVideo path-free; prompt excludes digest/videoEvidence/bytes |
| Image + video on one investigation | Separate contracts (`image-evidence-1` / `video-evidence-1`); distinct SHA-256; no storage paths in public body; snapshot stores sealedVideo not videoEvidence |

Image and video evidence remain separate. Video bytes/evidence are not introduced into the model prompt. Processing-run records are not interpreted as authenticity findings.

---

## 6. Failure handling results (3.D.2)

| Scenario | HTTP / state | Notes |
|---|---|---|
| Invalid image upload | ≥400 | Fail closed |
| Invalid video container | 400 `invalid_video` | No processing run |
| Probe timeout / output too large / isolation / codec / invalid (monkeypatched) | ≥400 matching code | Run recorded `failed` with same `failure_code` |
| Success-path `complete_video_probe_run` failure | 503 | No `succeeded` row |
| Client SHA-256 mismatch header | 200 upload; server identity sealed | `clientHashStatus=mismatch`; assess uses server digest |
| Concurrent second upload while lock held | 409 `video_upload_in_progress` | No processing run |
| Oversized stream (test-lowered MAX_VIDEO_BYTES) | 413 `request_too_large` | No processing run; partial cleaned |
| Post-seal user DELETE | 409 `video_after_seal` | Sealed identity retained; availability stays `retained` |

For each: no false success; no authenticity conclusion; no sealed-identity silent loss; no unauthorized exposure; one-shot assess policy unchanged (mocked single provider response).

**Not implemented:** a new recovery subsystem (prohibited). Dual-failure orphan-`started` residual remains accepted (see §9).

---

## 7. Security, ownership, erasure (3.D.3)

| Property | Result |
|---|---|
| Cross-account investigation / video / assessment / latest | Rejected (403/404 / ≥400); no videoEvidence leakage |
| Client `sealedVideo` / `videoEvidence` on assess | Ignored; server projection wins |
| Filesystem paths in public evidence | Absent (`storageName` / `assets/video` not present) |
| Video download/stream endpoints | **Not present**; GET `/video` metadata block has no FileResponse/StreamingResponse/read_bytes |
| Account erasure | Removes `video_processing_runs` and `video_assets` |
| Owner upload lock | Continues to serialize uploads (`fcntl.flock`, single-host) |

---

## 8. Snapshot and historical consistency (3.D.4)

| Property | Result |
|---|---|
| sealedVideo from verified asset | SHA-256 matches uploaded bytes |
| Snapshot path-free | No `storageName` / path fields |
| Option A | `videoEvidence` not stored in snapshot_json |
| Bytes loss after seal | Historical identity unchanged; availability `subsequently_deleted` |
| Unavailable ≠ authentic | Disclaimer retained; banned authenticity phrases absent |
| Contract version | `video-evidence-1` |
| Image vs video | Independent versions and digests |

Assessment outcome policy unchanged.

---

## 9. Resource limits (3.D.5)

| Limit | Expected | Observed |
|---|---|---|
| MAX_IMAGE_BYTES | 8 MiB | Unchanged |
| MAX_VIDEO_BYTES | 100 MiB | Unchanged |
| MAX_VIDEO_DURATION_MS | 180_000 | Unchanged |
| Resolution | 1920×1080 | Unchanged |
| Frame rate | 60 fps | Unchanged |
| Bitrate | 20 Mbps | Unchanged |
| Audio streams | 1 | Unchanged |
| PROBE_WALL_SECONDS | 25 | Unchanged |
| PROBE_STDOUT_MAX | 1 MiB | Unchanged |
| Probe scratch cleanup | Empty after success | Pass |
| DB txn during FFprobe | Not held (Stage 3.C design) | Unchanged; covered by 3.C tests |

No stress testing against production. No real customer media. No unbounded buffering introduced.

---

## 10. Consolidated regression commands and counts (3.D.6)

### Stage 3.A–3.D

```bash
cd /workspace/backend && python -m pytest \
  tests/test_video_stage3a.py \
  tests/test_video_stage3a1.py \
  tests/test_video_stage3b.py \
  tests/test_video_stage3b_frontend.py \
  tests/test_video_stage3c.py \
  tests/test_stage3d_e2e_hardening.py -q --tb=line
```

| Suite | Collected | Result |
|---|---|---|
| Stage 3.A | 13 | pass |
| Stage 3.A.1 | 14 | pass |
| Stage 3.B backend | 16 | pass |
| Stage 3.B frontend | 7 | pass |
| Stage 3.C | 21 | pass |
| Stage 3.D | 23 | pass |
| **Combined** | **94** | **94 passed**, 1 warning (Starlette TestClient deprecation), ~32.3s |

### Broader related backend

```bash
cd /workspace/backend && python -m pytest \
  tests/test_image_evidence.py \
  tests/test_assessment_persistence.py \
  tests/test_seal_http.py \
  tests/test_seal_flow.py \
  tests/test_erasure.py \
  tests/test_assets.py \
  tests/test_video_stage1.py \
  tests/test_video_stage2.py \
  tests/test_video_stage2_1.py \
  tests/test_video_stage2_3.py \
  tests/test_limits.py \
  tests/test_provenance_response.py -q --tb=line
```

**Result:** 175 passed, **1 failed**, 1 warning, ~59.1s.

| Failure | Classification |
|---|---|
| `test_assets.py::test_frontend_discloses_transmission_before_a_file_is_sent` | **Existing known residual #8** — expects literal `uploads the original file to the RealityCheck AI server`; E32 `index.html` uses equivalent `goes to the RealityCheck AI server`. Not a Stage 3.D regression. Test not modified to force a pass. |

### Additional API / evidence / integration

```bash
cd /workspace/backend && python -m pytest \
  tests/test_api.py \
  tests/test_integration.py \
  tests/test_evidence_graph.py \
  tests/test_evidence_validation.py \
  tests/test_metadata.py \
  tests/test_provenance_ui.py \
  tests/test_image_evidence.py \
  tests/test_video_stage3b_frontend.py -q --tb=line
```

**Result:** 110 passed, 1 warning, ~31.9s.

### Isolated Stage 3.D suite

```bash
cd /workspace/backend && python -m pytest tests/test_stage3d_e2e_hardening.py -q --tb=short
```

**Result:** 23 passed, 1 warning, ~8.6s.

Artifact logs: `/opt/cursor/artifacts/stage3d_*.log`.

---

## 11. Accepted residuals — not reclassified

| # | Residual | Status after 3.D |
|---|---|---|
| 1 | Startup reconciliation L1/L2 race | Unchanged / accepted |
| 2 | Single-host `fcntl.flock`; multi-host unsupported | Unchanged / accepted |
| 3 | FS/SQLite not fully atomic | Unchanged / accepted |
| 4 | Orphan `started` if probe + failure-persist both fail | Unchanged / accepted (3.C.1 residual A) |
| 5 | Saved asset may remain if success-complete fails; HTTP fail-closed | Unchanged / accepted; re-verified |
| 6 | Processing-run table has no FKs | Unchanged / accepted |
| 7 | Remote GitHub CI has no check runs / statuses | Unchanged / accepted |
| 8 | Assets disclosure wording mismatch | **Still fails** as documented; not “fixed” |
| 9 | `/video` response may expose broader probe metadata than `videoEvidence` | Unchanged / accepted |
| 10 | Nginx `client_max_body_size 8m` below planned 105000000 | Unchanged / accepted; not modified |
| 11 | Video ingestion remains disabled | Confirmed defaults False |

No multi-host support, reconciliation redesign, DB redesign, or proxy/deployment change was performed.

---

## 12. Defects found and disposition

| Finding | Disposition |
|---|---|
| No new in-scope product defect requiring a code fix | N/A — hardening tests only |
| Post-seal DELETE returns `video_after_seal` (409) | **Correct fail-closed behavior** — covered by new regression test; not a bug |
| Assets disclosure string mismatch | Pre-accepted residual #8 — documented; test left unchanged |

---

## 13. Prohibited actions — confirmation

Not performed:

- Enabling `video_ingest_enabled` or `video_allow_tier_b`
- Changing production feature-flag defaults or `video_seal_integration` semantics
- Deploy / DNS / firewall / TLS / Nginx body-limit changes
- Modifying `.env` or secrets
- Live ledger access
- Real provider calls or paid APIs
- Frame extraction / OCR / ASR / C2PA video / social downloaders
- Stage 3.E
- Stash mutation or branch switch

---

## 14. Conclusion

Stage 3.D establishes that the integrated image and video investigation workflow behaves consistently across ownership, ingestion, probing, sealing, evidence projection, historical retrieval, erasure, failure modes, and resource limits — within the documented accepted limitations.

**Recommendation:** Accept Stage 3.D with the same residual set as Stages 3.B.3 / 3.C.1. Proceed to Stage 3.E only under separate authorization. Do not enable video ingestion or deploy on the basis of this stage alone.
