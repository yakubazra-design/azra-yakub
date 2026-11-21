# RealityCheck AI — Controlled Pilot Runbook (single host)

This runbook prepares and operates one secure production host for a controlled
pilot. It matches the application in `backend/app/` and the templates in
`deploy/`. It does not deploy the application by itself.

**C2PA Choice A (required for this pilot):** Content Credentials may show
technical or unavailable results. Do **not** claim trusted C2PA credential
verification. Do not wire trust-witness or root-control services. Do not
configure OS trust fallback or remote trust fetching. Leave all `C2PA_*`
variables unset in the production environment file.

## Legend

- **Adapt:** replace the example path, hostname, user, or value for your host.
- **As written:** run after Adapt values are substituted, or run unchanged when
  no host-specific token appears.

Example paths used below (all Adapt):

| Role | Example |
| --- | --- |
| App checkout | `/opt/realitycheck` |
| Virtualenv | `/opt/realitycheck/.venv` |
| Service user/group | `realitycheck` |
| Ledger directory | `/var/lib/realitycheck` |
| Ledger file | `/var/lib/realitycheck/ledger.sqlite` |
| Image assets | `/var/lib/realitycheck/assets` (created beside the ledger) |
| Production env directory | `/etc/realitycheck` |
| Production env file | `/etc/realitycheck/production.env` |
| Backup directory | `/var/backups/realitycheck` |
| Public hostname | `realitycheck.example` (from `deploy/Caddyfile` / `deploy/nginx.conf`) |

---

## 1. Single-host architecture

```
Internet → Caddy or nginx (TLS :443) → 127.0.0.1:8000 Uvicorn (1 worker)
                                              ↓
                                    LEDGER_PATH + assets/
```

- One Uvicorn process with `--workers 1`. SQLite has one writer; more workers
  are not supported (`backend/README.md`).
- The reverse proxy terminates HTTPS. Uvicorn stays on localhost.
- The same process serves `frontend/` and the API (`backend/app/main.py`).

---

## 2. Host prerequisites

**Adapt** package installs to your OS. Required runtime pieces:

- Python 3.12+ (or the version used to install `backend/requirements.txt`)
- Ability to create users, directories, and systemd units
- Outbound HTTPS to OpenAI and Parallel
- Either Caddy or nginx + Certbot for TLS

**As written** (after Adapt checkout path), install Python dependencies into a
dedicated virtualenv:

```bash
cd /opt/realitycheck
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
```

Pinned / declared packages include FastAPI, Uvicorn, httpx, pydantic-settings,
argon2-cffi, and `c2pa-python==0.39.0` (see `backend/requirements.txt`).

---

## 3. Dedicated service account

**Adapt** the username if you choose another name; keep it non-root.

```bash
sudo useradd --system --home /var/lib/realitycheck --shell /usr/sbin/nologin realitycheck
```

---

## 4. Private application and data directories

**Adapt** paths; keep the ledger outside `frontend/`.

```bash
sudo mkdir -p /opt/realitycheck /var/lib/realitycheck /var/backups/realitycheck /etc/realitycheck
sudo chown -R realitycheck:realitycheck /var/lib/realitycheck /var/backups/realitycheck
sudo chmod 0700 /var/lib/realitycheck /var/backups/realitycheck
```

### Production environment directory vs environment file

Use one consistent design so both systemd and the manual smoke test work:

| Path | Owner | Mode | Why |
| --- | --- | --- | --- |
| `/etc/realitycheck` (directory) | `root:realitycheck` | `0750` | systemd (root) and the service user can traverse; other users cannot list or enter |
| `/etc/realitycheck/production.env` (file) | `realitycheck:realitycheck` | `0600` | only the service account (and root) can read secrets |

```bash
sudo chown root:realitycheck /etc/realitycheck
sudo chmod 0750 /etc/realitycheck
```

Place the application tree at `/opt/realitycheck` so it contains `backend/` and
`frontend/`. The service account needs read access to the checkout and execute
access to the virtualenv interpreter. Keep the application source tree
read-only for the service; do not grant write access for `__pycache__`.
The unit sets `PYTHONDONTWRITEBYTECODE=1` for that reason.

On first successful start, the application restricts the ledger directory to
`0700` and the database / WAL / SHM files to `0600`. Image files live in
`assets/` beside the ledger at `0700` / `0600` (`AssetStore.for_ledger`).
Restore journals are also written beside the ledger (same directory).

---

## 5. Production environment configuration

### Authoritative env file (required)

`backend/app/config.py` loads settings from process environment variables and
may also read a checkout-root `.env` next to the application (`ROOT/.env`).
On the production host:

1. **Do not** keep a checkout `.env` that could override or supplement pilot
   settings. Remove it or move it off the host before starting the service:
   ```bash
   # Adapt checkout path. Only if a leftover development .env exists:
   sudo rm -f /opt/realitycheck/.env
   ```
2. Use `/etc/realitycheck/production.env` as the **only** authoritative
   production configuration (loaded via systemd `EnvironmentFile=` and, for
   manual smoke, sourced by the service user).

### Create the production env file

1. **Adapt:** copy `.env.production.example` to `/etc/realitycheck/production.env`.
2. Keep `REALITYCHECK_ENV=production` and `COOKIE_SECURE=true`.
3. Generate a unique `AUTH_SECRET` on this host (see §6). Never reuse the
   example placeholder `REPLACE_ME` — it is shorter than 32 characters so the
   application refuses to start in production until replaced.
4. Replace provider `CHANGE_ME` placeholders with real keys before the
   supervised smoke test.
5. Lock down the file (**as written** after Adapt ownership names):

```bash
sudo chown realitycheck:realitycheck /etc/realitycheck/production.env
sudo chmod 0600 /etc/realitycheck/production.env
```

Confirm directory vs file modes:

```bash
sudo namei -l /etc/realitycheck/production.env
# expect: /etc/realitycheck  root:realitycheck  0750
# expect: production.env     realitycheck:realitycheck  0600
```

### Required production gate (enforced at startup)

| Variable | Requirement |
| --- | --- |
| `REALITYCHECK_ENV` | `production` |
| `COOKIE_SECURE` | `true` |
| `AUTH_SECRET` | at least 32 characters (`MIN_SECRET_LENGTH` in `backend/app/auth.py`) |
| `LEDGER_PATH` | absolute path to a regular DB file outside `frontend/` |
| `TRUSTED_PROXIES` | at least one IP (e.g. `127.0.0.1`); no hostnames/CIDR |

Missing or invalid values raise `StartupError` and refuse to start.

### Provider and model settings

| Variable | Purpose |
| --- | --- |
| `OPENAI_API_KEY` | Assessment / claim extraction |
| `PARALLEL_API_KEY` | Search and extract |
| `OPENAI_MODEL_DEFAULT` | Default model (example: `gpt-4.1-mini`) |
| `OPENAI_MODEL_COMPLEX` | Complex assessment model (example: `gpt-4.1`) |
| `OPENAI_API_BASE` | Default `https://api.openai.com` |
| `PARALLEL_API_BASE` | Default `https://api.parallel.ai` |
| `PARALLEL_MCP_URL` | Default `https://search.parallel.ai/mcp` |
| `ALLOWED_ORIGINS` | Leave empty for same-origin behind the proxy |
| `SESSION_TTL_SECONDS` | Default `43200` (12 hours) |

### C2PA (Choice A)

Leave unset / commented in the env file:

- `C2PA_TRUST_ROOT`
- `C2PA_TRUST_STATE_PATH`
- `C2PA_TRUST_PIN_PATH`
- `C2PA_TRUST_CALLER_ID`
- `C2PA_WITNESS_MAC_KEY`
- `C2PA_ROOT_MAC_KEY`

The default runtime does not inject trust-witness or root-control services.
Seals still succeed; provenance remains technical/unavailable.

---

## 6. Secure `AUTH_SECRET` generation and storage

Generate a unique secret **on the production host**. Do not paste the output
into chat, tickets, or git. Do not ship a pre-made secret in the repository.

**As written** on the host:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put the result in `/etc/realitycheck/production.env` as `AUTH_SECRET=...`
(file mode `0600`). Then confirm it meets the application minimum (**as
written** after the file exists; requires length ≥ 32):

```bash
sudo -u realitycheck bash -lc '
  set -a
  . /etc/realitycheck/production.env
  set +a
  len=${#AUTH_SECRET}
  echo "AUTH_SECRET length: $len"
  if [ "$len" -lt 32 ]; then
    echo "AUTH_SECRET is shorter than MIN_SECRET_LENGTH (32). Refuse to start." >&2
    exit 1
  fi
'
```

Rotate by writing a new secret, restarting the service, and signing users in
again (existing sessions become invalid).

---

## 7. HTTPS reverse proxy

Choose **one** of Caddy or nginx. Templates:

- `deploy/Caddyfile`
- `deploy/nginx.conf`

**Adapt** every `realitycheck.example` hostname (and nginx certificate paths)
before enabling the site. Do not point DNS at the host until intentional.

Both templates:

- Forward to `http://127.0.0.1:8000`
- Cap request bodies at 8 MB / `8m` (image upload limit)
- Replace `X-Forwarded-For` with the single accepted client address

Set `TRUSTED_PROXIES` to the address Uvicorn sees for that proxy (normally
`127.0.0.1`; add `::1` only for IPv6 localhost).

Port 8000 must not be reachable from the public network.

---

## 8. Single-worker Uvicorn (manual start)

Use this only for a supervised smoke before installing systemd.

**Adapt** paths; keep `--workers 1` and the bind address exactly:

```bash
cd /opt/realitycheck
sudo -u realitycheck -H bash -lc '
  set -a
  . /etc/realitycheck/production.env
  set +a
  export PYTHONPATH=backend
  export PYTHONDONTWRITEBYTECODE=1
  exec /opt/realitycheck/.venv/bin/python3 -m uvicorn app.main:app \
    --host 127.0.0.1 --port 8000 --workers 1
'
```

Entry point: `app.main:app` (`DeferredApplication` runs production gates on
first use).

---

## 9. systemd service installation and management

Unit template: `deploy/realitycheck.service`.

**Adapt** in the unit before install:

- `User=` / `Group=`
- `WorkingDirectory=`
- `EnvironmentFile=`
- `ExecStart=` interpreter path
- `ReadWritePaths=` ledger directory
- `Documentation=` path if the checkout location differs

The unit already sets `Environment=PYTHONDONTWRITEBYTECODE=1` and keeps
`ProtectSystem=strict` with `ReadWritePaths` limited to the ledger directory.
It does **not** set `PrivateDevices=true`: `backend/app/c2pa_reader.py` runs
the native reader in a multiprocessing child with a `Queue`, which needs
`/dev/shm` on Linux. Dropping `PrivateDevices` is preferred over binding
extra device paths. Other hardening directives remain enabled.

**Adapt** install path; then **as written** reload, validate, and start:

```bash
sudo install -m 0644 /opt/realitycheck/deploy/realitycheck.service /etc/systemd/system/realitycheck.service
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/realitycheck.service
sudo systemctl enable realitycheck.service
sudo systemctl start realitycheck.service
sudo systemctl status realitycheck.service --no-pager
```

`systemd-analyze verify` on a developer workstation against the unadapted
template may warn that `/opt/realitycheck/.venv/bin/python3` is missing.
That is expected for a path template. Run the same command on the pilot host
**after** substituting real paths; treat failures there as blocking.

Common controls (**as written** after the unit is installed):

```bash
sudo systemctl restart realitycheck.service
sudo systemctl stop realitycheck.service
sudo journalctl -u realitycheck.service -e --no-pager
```

---

## 10. Health checks and supervised smoke test

### Health (ledger + config flags)

**Adapt** the hostname. From an operator workstation or the host:

```bash
curl -fsS https://realitycheck.example/api/health
```

Expect HTTP 200 and JSON including:

- `"status": "ok"` — ledger opens, tables query, SQLite integrity check passes
- `"authReady": true` — production auth secret accepted
- `"openaiConfigured": true` / `"parallelConfigured": true` — **non-empty
  configuration values are present only**. These flags do **not** prove that
  provider authentication or API connectivity works.

HTTP 503 with `"status": "unhealthy"` means the ledger side failed; the body
does not include paths or SQL errors.

Localhost check while SSH’d to the host (**as written** once Uvicorn is up):

```bash
curl -fsS http://127.0.0.1:8000/api/health
```

### Functional smoke (supervised — required)

Health alone is insufficient. With real provider keys configured, perform a
supervised end-to-end check:

1. Open `https://<your-host>/` over HTTPS.
2. Register or sign in (CSRF required for state-changing calls).
3. Create an investigation; run search against Parallel; optionally upload an
   image (≤ 8 MiB).
4. Seal and assess once against OpenAI.
5. Confirm the six assessment outcomes UI still operates.
6. Confirm Content Credentials show technical/unavailable under Choice A — not
   a trusted credential conclusion.

Do not treat the pilot as ready until this supervised provider smoke succeeds.

---

## 11. Backup, retention, and restore

Stop the application before backup or restore. A plain copy of `ledger.sqlite`
is not a backup (WAL pages and `assets/` would be missed).

### Backup

**Adapt** ledger and destination paths. The application must **not** restart
unless the backup command succeeds and the expected artifacts exist:

```bash
sudo systemctl stop realitycheck.service
cd /opt/realitycheck
sudo -u realitycheck -H env PYTHONPATH=backend \
  /opt/realitycheck/.venv/bin/python3 -m app.backup backup \
  --ledger /var/lib/realitycheck/ledger.sqlite \
  --dest /var/backups/realitycheck \
&& backup_db=$(ls -1t /var/backups/realitycheck/realitycheck-ledger-*.sqlite | head -1) \
&& test -n "$backup_db" \
&& test -f "${backup_db}.manifest.json" \
&& test -d "${backup_db}.assets" \
&& echo "Backup OK: $backup_db" \
&& sudo systemctl start realitycheck.service
```

If any step fails, the `&&` chain stops: the service stays stopped and must
not be treated as upgraded or backed up. Inspect the error, fix the cause,
and retry the backup before starting the service.

Success prints `Backup written:` and a timestamped database name. Keep together:

- `realitycheck-ledger-YYYYMMDDTHHMMSSZ.sqlite`
- `…sqlite.manifest.json`
- `…sqlite.assets/` directory

Retention guidance from `backend/README.md`: at least 14 daily and 8 weekly
copies; keep another copy on a different disk/machine; directory `0700`, files
`0600`; never under `frontend/` or in git. The tool does not delete old backups.

### Restore (data rollback)

**Adapt** the backup filename:

```bash
sudo systemctl stop realitycheck.service
cd /opt/realitycheck
sudo -u realitycheck -H env PYTHONPATH=backend \
  /opt/realitycheck/.venv/bin/python3 -m app.backup restore \
  --backup /var/backups/realitycheck/realitycheck-ledger-YYYYMMDDTHHMMSSZ.sqlite \
  --ledger /var/lib/realitycheck/ledger.sqlite \
  --application-stopped \
&& echo "Restore completed successfully" \
&& sudo systemctl start realitycheck.service
```

Wait for the CLI `Restore completed.` line and a successful exit before the
`systemctl start` runs. Then re-check `/api/health`. Do not restore a
pre-deletion backup if an account erasure must remain in effect.

---

## 12. Application upgrade and rollback

### Upgrade

1. Stop the service and take a successful backup (§11). Do **not** continue if
   the backup `&&` chain fails.
2. Keep the service **stopped** while replacing application files under the
   Adapt checkout path. Preserve `/etc/realitycheck/production.env` and
   `/var/lib/realitycheck`.
3. Reinstall dependencies if `backend/requirements.txt` changed.
4. Do **not** start the service until validation below passes.
5. Validation while still stopped / carefully started only for checks:
   - `systemd-analyze verify` on the installed unit (if the unit changed)
   - start the service once checks are ready
   - `/api/health` shows `status: ok` and `authReady: true`
   - supervised provider smoke (§10) succeeds
6. If validation fails: stop the service, restore the previous application
   revision and/or follow §11 restore, then complete §12 Rollback.

### Rollback

1. Stop the service and leave it stopped while restoring files or data.
2. Restore the last known-good backup (§11) **or** check out the previous
   application revision if only code is bad and the ledger is fine.
3. Start the service only after restore/revision swap succeeds; confirm
   `/api/health` and smoke login / provider smoke as needed.

---

## 13. Troubleshooting

| Symptom | Likely cause | What to check |
| --- | --- | --- |
| Service fails immediately | Production gate | `journalctl -u realitycheck`; confirm `COOKIE_SECURE`, `AUTH_SECRET` length ≥ 32, absolute `LEDGER_PATH`, `TRUSTED_PROXIES` IPs |
| `authReady` false / sign-in 503 | Secret too short or `COOKIE_SECURE` mismatch | Env file; length check in §6; restart |
| Manual smoke cannot source env | Directory mode/owner | `/etc/realitycheck` must be `root:realitycheck` `0750`; file `0600` |
| Browser never stores session | Cookie not Secure/HTTPS | Serve only via HTTPS with `COOKIE_SECURE=true` |
| `/api/health` 503 | Ledger/assets integrity | Permissions `0700`/`0600`; disk space; restore from backup if corrupt |
| `openaiConfigured`/`parallelConfigured` true but search/assess fail | Flags only mean keys are non-empty | Run supervised provider smoke; check egress and real credentials |
| Image upload 413 | Body over 8 MiB | Proxy `client_max_body_size` / `request_body max_size`; app limit |
| Startup mentions C2PA remote/relative path | Accidental C2PA config | Unset all `C2PA_*` for Choice A |
| Import / `__pycache__` errors under systemd | Bytecode writes to read-only tree | Confirm `PYTHONDONTWRITEBYTECODE=1` in the unit |
| Multiple writers / DB locks | More than one worker or process | Ensure `--workers 1` and a single unit instance |

---

## 14. Related files

| File | Role |
| --- | --- |
| `deploy/realitycheck.service` | systemd unit template |
| `.env.production.example` | production env names and placeholders |
| `deploy/Caddyfile` | Caddy HTTPS reverse proxy template |
| `deploy/nginx.conf` | nginx HTTPS reverse proxy template |
| `backend/README.md` | Auth, backup, HTTPS, rate limits, retention |
| `backend/app/config.py` | Settings / environment variable source of truth |
| `backend/app/backup.py` | `python -m app.backup` CLI |

---

## 15. Out of scope for this pilot stage

- Changing DNS, firewall, or certificates from this repository
- Installing packages or starting services from a developer workstation
- Trusted C2PA / trust-witness implementation
- Multi-host or multi-worker deployment
