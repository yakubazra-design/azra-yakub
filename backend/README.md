# RealityCheck AI backend

FastAPI service for the migration off Claude's artifact runtime. The same process serves `frontend/` and the investigation API.

- `GET /api/health` returns `status: ok` only when the ledger opens, its tables can be queried, and SQLite's integrity check passes. Otherwise the response is HTTP 503 with `status: unhealthy`. The body does not include the database path, SQL, or the integrity-check text.
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `DELETE /api/auth/account`
- `GET /api/auth/session`
- `POST /api/investigations`
- `POST /api/investigations/{id}/search`
- `POST /api/investigations/{id}/fetch`
- `GET /api/investigations/{id}/evidence`
- `POST /api/investigations/{id}/extract-claims`
- `POST /api/investigations/{id}/seal`
- `POST /api/investigations/{id}/assess`
- `DELETE /api/investigations/{id}`

Check Now calls the investigation routes. Search and fetch call Parallel's server-side Search and Extract APIs. Claim extraction and assessment build their prompts in `backend/app/prompts.py` and validate model output in `backend/app/validation.py`. Keys are read from the environment or a local `.env` and are never returned to the client.

Source quality, independence, and the evidence timeline are calculated in `backend/app/quality.py` and `backend/app/evidence.py` from the rows stored for that investigation. A source list, quality tier, independence object, timeline, or snapshot sent with the assessment request is ignored.

Search and fetch write the provider result. The provider name and date fields are the ones returned by that call. A source URL is checked before it is stored. `http` and `https` URLs that include a host are kept, including mixed-case schemes, after surrounding whitespace is removed. `javascript:`, `data:`, `file:`, `blob:`, and every other scheme are stored only as text and are not links. The page checks the scheme again before it creates a source anchor, and an unsafe URL is shown as text. This does not change the Parallel request, and it does not close the separate gap where Parallel opens its own connection. A kept date is still an exact `YYYY-MM-DD` calendar day and stays `provider-reported`. Missing, blank, and impossible dates stay off the timeline. Nothing fills a gap with an estimated date. `published`, `updated`, and `unspecified` still come from wording in the stored title or snippet. Storing a row does not prove the source is authentic.

## Authentication

Accounts are required for every investigation route.

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `DELETE /api/auth/account`
- `GET /api/auth/session`

Passwords are stored only as Argon2id hashes. A session cookie carries a random token, and the database stores an HMAC of that token. The cookie is HttpOnly, `Path=/`, and expires with the server session. Local HTTP uses `rc_session` with `SameSite=Lax`. Set `COOKIE_SECURE=true` for HTTPS so the cookie is `Secure`, `SameSite=Strict`, and named `__Host-rc_session`. Leave `COOKIE_SECURE` unset on local HTTP, or the browser will not store the cookie.

`AUTH_SECRET` must be at least 32 characters whenever `COOKIE_SECURE=true`. If it is missing or shorter, sign-in and investigation routes return 503 and do not fall back to an empty secret. Local HTTP without `AUTH_SECRET` uses a process-local secret, so sessions end when the process restarts. `SESSION_TTL_SECONDS` defaults to 12 hours. Logout revokes the session row.

`REALITYCHECK_ENV=production` is the production gate. In that mode the process refuses to start unless `COOKIE_SECURE=true`, `AUTH_SECRET` is at least 32 characters, `LEDGER_PATH` is an absolute path to a regular database file outside `frontend/`, and `TRUSTED_PROXIES` lists at least one IP address. Production does not invent an `AUTH_SECRET`. A symlink, a directory, a relative path, or a path under the public frontend is rejected before the database is opened. Local development leaves `REALITYCHECK_ENV` unset or set to `local`, and the local HTTP behavior above stays in place.

The ledger directory is created with mode `0700`. The database file, and any `ledger.sqlite-wal` or `ledger.sqlite-shm` file beside it, is set to mode `0600`. Existing files are restricted in place. They are not deleted or recreated, and the accounts, investigations, evidence, and snapshots already in the file stay there. A permission or initialization failure does not include the file path in the error returned to a client. In production that failure stops startup.

State-changing requests send the `X-CSRF-Token` value returned by login or `GET /api/auth/session`. Login uses the same error for an unknown email and a wrong password. Signing in does not prove that a source is authentic.

Investigations created before accounts remain in the database. This stage does not delete them and does not attach them to a new account. The old `rc_owner` cookie is no longer accepted. A later migration can set `investigations.owner_id` to an account id, or add `email` and `password_hash` to an existing user row. Neither change is run here.

## Assessment snapshots

`POST /api/investigations/{id}/seal` freezes the investigation's stored claim, verifiable points, evidence sources, and the quality, independence, and timeline calculated from those sources. It returns a random assessment token and an expiry 10 minutes later. The database stores an HMAC of the token, not the token.

`POST /api/investigations/{id}/assess` accepts that token once. The token is marked used, and the change is committed, before the model is called. A provider failure, a second request, or two overlapping requests cannot use it again. A forged token, a token for another account, and a token for another investigation are all rejected without consuming a token that belongs to someone else. An expired token is rejected and is not marked used. After ten minutes it cannot be used.

The model prompt is built only from the sealed snapshot. The seal reads the stored image identity in the same write transaction that inserts the snapshot. Replacing the live evidence rows, or sending a claim, source list, quality, independence, timeline, snapshot, or asset hash in the assessment body, does not change that sealed copy. The snapshot row cannot be rewritten in place. Deleting the investigation removes its snapshots. A sealed snapshot records what the system assessed. It does not prove that the underlying source material is authentic.

If extract-claims has not run, the seal uses the text stored on the investigation. A confirmed image upload is stored before sealing. Its server hash identifies the received file and is not an authenticity conclusion. Camera and location details are not copied into the model prompt.

## Rate limits

Limits are enforced in the server process with fixed windows stored in the ledger. Overlapping requests take one immediate transaction, and the counter update is conditional, so two requests cannot share the last available slot. A limited request returns 429 with `{"code":"rate_limited","message":"Too many requests. Try again later."}` and a `Retry-After` header. The check happens before a provider call. A limited assessment does not consume its token.

Login and registration limits use the TCP peer. `X-Forwarded-For` is used only when that peer is listed in `TRUSTED_PROXIES` and the header is exactly one IP address. A list, a hostname, and the `Forwarded` header are ignored. A client that connects directly cannot change its limit key by sending either header. Login is 10 per 15 minutes per visitor address. Registration is 5 per hour per visitor address. Per account, each hour allows 30 new investigations, 30 URL fetches, 60 evidence searches, 60 claim analyses, 60 seals, 30 assessment attempts, 120 evidence reads, and 20 image uploads. Empty claims, queries, and URLs return 400 and are not sent to a provider. A JSON body larger than 64 KiB returns 413. An image upload larger than 8 MiB returns 413. Claim text sent to the model is still capped at 6,000 characters, and a search query is still capped at 6 words.

Old counter windows are deleted. The rows do not contain passwords, session tokens, or assessment tokens. The server does not log those values. A request whose JSON cannot be read returns `{"code":"invalid_request","message":"The request could not be read."}` and does not repeat the submitted body.

## Data retention

The ledger file is `data/ledger.sqlite` unless `LEDGER_PATH` points somewhere else. Production must set `LEDGER_PATH` to an absolute file outside `frontend/`. The directory is mode `0700` and the database, WAL, and SHM files are mode `0600`. The file is gitignored and is not served by the application. It contains account email addresses, Argon2id password hashes, session token hashes, assessment-token hashes, sealed evidence snapshots, submitted claims, fetched page text, source URLs, snippets, provider names, and date provenance.

`DELETE /api/investigations/{id}` removes that owner's investigation and its page, claim analysis, source, and snapshot rows in one transaction. Another owner's request gets the same not-found response as an unknown id. The account and its sessions remain. Do not commit the ledger or place it under `frontend/`.

Accounts and their investigations stay until that person deletes the account. There is no automatic expiry of investigations. `DELETE /api/auth/account` requires the signed-in session, that session's CSRF token, and the current password. The account is the session's account. A user id or email in the request does not select a different account. The password is checked with the stored Argon2id hash. A legacy owner row, one with no email or no password hash, is refused and left unchanged, including its investigations.

The password is checked before any image file is removed. The account's current image files and any files still listed for cleanup are removed next. The database deletion then runs in one immediate transaction. It removes that account's assessment snapshots, image rows, cleanup rows, evidence sources, page fetches, claim analyses, investigations, every session row, rate-limit rows whose subject is that account id, and then the user row. Login and registration counters stay, because those subjects are visitor addresses and may be shared. If a file cannot be removed, the account remains. If some files were removed and the database step then fails, the account still exists and the deletion can be retried safely: a file that is already gone counts as removed. Another account's rows are not deleted. After a successful deletion the response clears the session cookie. The deleted email cannot sign in, and a saved session token no longer opens the application. Image bytes live in the `assets` directory beside the ledger, not in the database file. A cleanup row remembers a file that still needs to be deleted, including a replaced file whose unlink failed.

A backup taken before the deletion still contains the account. A backup taken after the committed deletion does not. Restoring the earlier backup replaces the live ledger and brings the deleted account back, so do not restore a pre-deletion backup when the deletion must remain in effect. Keep at least 14 daily backups and 8 weekly backups, outside `frontend/`, at directory mode `0700` and file mode `0600`. The application does not delete those files. When a backup or a `.pre-restore-` file is past that retention period, remove it from the backup host without restoring it. The directory is not world-readable. On an encrypted disk, unlinking the file is the removal. On a disk that is not encrypted, overwrite the file and then unlink it. Do not copy an expired backup into the public web root or into git.

## Database backup and restore

A normal online backup does **not** require stopping the application: the tool takes a write lock, reads the image and cleanup rows, copies those files, and uses SQLite's backup API so the database includes the committed WAL pages. Copying `ledger.sqlite` by itself is not a backup. In WAL mode, committed rows can still be in `ledger.sqlite-wal`, and a plain file copy misses them. The backup also misses the `assets` directory. A file in `assets` that has no row, or a row whose file is missing or has a different size or SHA-256, stops the backup. An existing backup is not overwritten or deleted. **Restore** still requires the application to be stopped (see below).

The backup directory has to be outside `frontend/`. Local backups can use `data/backups/`. Production should use a directory on another disk, such as `/var/backups/realitycheck`. The tool creates that directory at mode `0700`. The database file and manifest are mode `0600`, and the copied asset directory is mode `0700` with files at mode `0600`. The database name is `realitycheck-ledger-YYYYMMDDTHHMMSSZ.sqlite`. The manifest is that name plus `.manifest.json`, and the files are in the directory with `.assets` added. If that name already exists, a numeric suffix is added. The name is only a timestamp. Passwords, session tokens, assessment tokens, and API keys are never written into the file name or the command's output.

```
PYTHONPATH=backend python3 -m app.backup backup \
  --ledger /var/lib/realitycheck/ledger.sqlite \
  --dest /var/backups/realitycheck
```

The command prints `Backup written:` and the database file name. It runs `PRAGMA integrity_check` on the new file and checks the manifest against that file. It leaves no database, manifest, or asset copy behind when a check fails. An existing backup is not overwritten or deleted. A backup created before image files were added has no manifest. It can be restored only when it contains no image or cleanup rows.

Keep at least 14 daily backups and 8 weekly backups. Keep another copy on a different machine or disk, still outside the public web root, on an encrypted volume. Do not commit a backup, do not put one under `frontend/`, and do not send it to a public bucket. A backup contains email addresses, Argon2id password hashes, session-token hashes, assessment-token hashes, claims, and stored page text. This project does not use a paid backup service, and the tool does not delete old backups. After a newer backup has been restored and checked, the operator can remove the copies that are past that retention.

Stop the application before a restore, and leave it stopped until the command finishes. Restoring over a database that another process has open is refused, and the live file is left as it was.

```
PYTHONPATH=backend python3 -m app.backup restore \
  --backup /var/backups/realitycheck/realitycheck-ledger-YYYYMMDDTHHMMSSZ.sqlite \
  --ledger /var/lib/realitycheck/ledger.sqlite \
  --application-stopped
```

The restore checks the backup database, the manifest, and every asset file's name, size, and SHA-256 before it changes the live ledger. A missing file, a corrupt file, a digest mismatch, or an extra file in the backup's asset directory stops the restore. It then copies the new database and assets beside the live files and writes a journal, `.ledger-name.restore-journal`, before renaming anything live. The journal is updated and synced before each rename. The previous database file and any `-wal` and `-shm` companions are renamed with a `.pre-restore-YYYYMMDDTHHMMSSZ` suffix. The previous `assets` directory is renamed `assets.pre-restore-YYYYMMDDTHHMMSSZ`. They are not deleted. If that name already exists, the restore picks another suffix. The database and the asset directory are two paths: a rename of one is atomic, and the pair is not one atomic replace. The command checks the live pair and prints `Restore completed.` only after that check. If a check fails, or the process stops with the journal still present, the next start puts the previous database and assets back. Startup keeps the new pair only when the journal state is already `validated` and the live database and asset files pass the integrity and digest checks. A pair that is merely in place, but not yet recorded as `validated`, is rolled back. A half-installed file is renamed aside, not deleted. Do not move an old WAL onto the restored file: that would undo the restore. Keep the database, manifest, and `.assets` directory together, under the same retention as the database file: at least 14 daily backups and 8 weekly backups. Start Uvicorn only after the success line, then request `GET /api/health`. A healthy ledger returns HTTP 200 and `status: ok`. An unreadable ledger, a failed integrity check, a partial upload file, a quarantined file, or an asset file that does not match its row returns HTTP 503 and `status: unhealthy` with no path and no SQLite error text.

The proxy in front of Uvicorn must refuse a body larger than 8 MB (`client_max_body_size 8m` in nginx, `request_body max_size 8MB` in Caddy). That is the image-upload limit. The application also refuses an oversized ASGI message before it adds the message to its buffer, including a request with no Content-Length. It cannot release memory the server or the proxy already allocated for that message.

```
PYTHONPATH=backend python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
```

The local page is `http://127.0.0.1:8000/`. Use one worker. SQLite has one writer, and more workers are not supported.

## HTTPS reverse proxy

Production terminates HTTPS at Caddy or nginx and forwards to that one Uvicorn process on `127.0.0.1:8000`. The sample files are `deploy/Caddyfile` and `deploy/nginx.conf`. Replace `realitycheck.example` with the real hostname before use. This repository does not start the proxy, obtain a certificate, or change DNS.

Set these values for that process:

```
REALITYCHECK_ENV=production
COOKIE_SECURE=true
AUTH_SECRET=  # at least 32 characters, stored outside the image
LEDGER_PATH=/var/lib/realitycheck/ledger.sqlite
TRUSTED_PROXIES=127.0.0.1
```

Add `::1` to `TRUSTED_PROXIES` only when the proxy connects over IPv6. Do not list a visitor network. The proxy must replace `X-Forwarded-For` with the single address it accepted. It must not append a client-supplied list. The application ignores `Forwarded`.

`COOKIE_SECURE=true` makes the session cookie `Secure`, `SameSite=Strict`, and `__Host-rc_session`. The browser sends it only on HTTPS. The hop from the proxy to Uvicorn is HTTP on localhost, which is why Uvicorn stays bound to `127.0.0.1` and port 8000 is not open to the network.

## Browser security headers

Every response includes:

```
Content-Security-Policy: default-src 'self'; base-uri 'none'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; style-src-attr 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; img-src 'self' blob:; connect-src 'self'; worker-src 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

`REALITYCHECK_ENV=production` also sends `Strict-Transport-Security: max-age=31536000`. Local HTTP does not. The policy does not include `includeSubDomains` or `preload`.

The existing page needs three CSP exceptions. `style-src-attr 'unsafe-inline'` keeps the style attributes already in the markup. JavaScript that sets element styles is unaffected and does not need that permission. `style-src` and `font-src` allow the existing Google Fonts stylesheets and font files. `img-src` allows `blob:` because a chosen image is previewed with a local object URL. Scripts are only `script-src 'self'`. `script-src` does not allow `'unsafe-inline'` or `'unsafe-eval'`.

Image metadata uses exifr 7.1.3, served as `frontend/vendor/exifr-7.1.3.umd.js`. That file is the `dist/full.umd.js` from the npm package `exifr@7.1.3`, whose tarball integrity is `sha512-g/aje2noHivrRSLbAUtBPWFbxKdKhgj/xr1vATDdUXPOFYJlQ62Ft0oy+72V6XLIpDJfHs6gXLbBLAolqOXYRw==`. The vendored file's SHA-256 is `2bd05117781c12ddd965dee846de3b3f986b5ecb4c7f6a78f2d2ec1db7c65ae7`. The page does not load it from a third-party host.

Caddy obtains and renews a certificate automatically when the hostname resolves to the host and ports 80 and 443 reach Caddy. Its HTTP listener redirects to HTTPS. Nginx uses Certbot: `certbot --nginx -d realitycheck.example`. Renewal is Certbot's existing timer, `certbot renew`. The nginx sample redirects port 80 to HTTPS. Do not run either command until the hostname is intentionally pointed at the host.

Non-live tests (mocked Parallel and OpenAI):

```
PYTHONPATH=backend python3 -m pytest backend/tests -q
```

## URL check limitations

Before a page is sent to Parallel, `backend/app/urls.py` and `backend/app/ssrf.py` allow only `http` and `https`, reject credentials, and reject localhost, `.local`, `.internal`, `.localhost`, cloud-metadata names, and literal private, loopback, link-local, reserved, multicast, unspecified, and other non-global addresses. Hostnames are resolved twice. A blocked address in either answer rejects the fetch. The check connects only to an address from that result, then follows redirects itself, up to five, and checks every hop the same way. The preflight uses a 5 second connect timeout, an 8 second read timeout, and reads at most 1 MiB.

Parallel then opens its own connection. A name can change addresses, or a redirect can change, between this check and Parallel's connection. That gap remains, so this is not complete SSRF protection.
