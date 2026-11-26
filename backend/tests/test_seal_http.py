"""HTTP seal integration. Temporary databases, asset directories, and injected stores only.

Nothing in this module opens the live ledger or a database backup.
"""

import json
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.c2pa_statuses import ASSESSMENT_OUTCOMES, FAILURE_CODES
from app.main import StartupError, create_app
from app.provenance import READER_VERSION
from app.seal_flow import UnavailableTrustStore
from app.trust_store import TrustStore, failure
from test_api import DUMMY_OPENAI, _create, _ensure_auth, _ledger, _settings
from test_assets import _png, _upload
from test_seal_flow import (
    ACTIVATION,
    ACTIVATION_NEXT,
    MANIFEST,
    MANIFEST_NEXT,
    SUSPENSION_NEXT,
    TIMESTAMP,
    TIMESTAMP_NEXT,
    Reader,
    Store,
    _checks,
    _confirmed,
    _credential,
    _pin,
    _select,
    _text_sha,
)

FORGED_HASH = "ff" * 32
CLIENT_MARKER = "client-supplied-provenance-marker"
SECRET = "p" * 32


def _snapshots(path: str):
    connection = sqlite3.connect(path)
    try:
        return connection.execute("SELECT id, snapshot_json FROM assessment_snapshots").fetchall()
    finally:
        connection.close()


def _app(tmp_path: Path, **kwargs):
    path = _ledger(tmp_path)
    settings = kwargs.pop("settings", None) or _settings(ledger_path=path, openai_api_key=DUMMY_OPENAI)
    return path, create_app(settings=settings, **kwargs)


def _client(app):
    client = TestClient(app)
    _ensure_auth(client)
    return client


def _image_case(tmp_path: Path, **kwargs):
    path, app = _app(tmp_path, **kwargs)
    client = _client(app)
    investigation = _create(client, "The event happened.")
    uploaded = _upload(client, investigation, _png())
    assert uploaded.status_code == 200, uploaded.text
    return path, app, client, investigation


def _stored(path: str) -> dict:
    rows = _snapshots(path)
    assert len(rows) == 1
    return json.loads(rows[0][1])


def _success_store():
    return Store(
        [_pin(4, MANIFEST, TIMESTAMP)],
        [_select(4, MANIFEST, TIMESTAMP), _select(4, MANIFEST, TIMESTAMP), _select(4, MANIFEST, TIMESTAMP)],
        [_confirmed(4)],
    )


class Observed:
    def __init__(self, inner, path: str):
        self.inner = inner
        self.path = path
        self.selects = 0
        self.rows_at_select = []

    def pin(self):
        return self.inner.pin()

    def select(self):
        self.selects += 1
        self.rows_at_select.append(len(_snapshots(self.path)))
        return self.inner.select()

    def revalidate(self, pinned):
        return self.inner.revalidate(pinned)


class Down:
    def __init__(self, code: str):
        self.code = code
        self.selects = 0

    def pin(self):
        return failure(self.code)

    def select(self):
        self.selects += 1
        raise AssertionError("An unavailable store was selected.")

    def revalidate(self, _pinned):
        raise AssertionError("An unavailable store was revalidated.")


class ExplodingReader:
    def __init__(self):
        self.calls = 0

    def __call__(self, _data, **_kwargs):
        self.calls += 1
        raise RuntimeError("reader exploded")


def _assessment():
    return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({
        "assessment": "INSUFFICIENT_EVIDENCE",
        "findings": [],
        "why": {},
        "uncertainty": [],
    })}}]})


def _production(tmp_path: Path, **overrides):
    data = dict(
        realitycheck_env="production",
        cookie_secure=True,
        auth_secret=SECRET,
        ledger_path=_ledger(tmp_path, "production.sqlite"),
        trusted_proxies="127.0.0.1",
    )
    data.update(overrides)
    return _settings(**data)


def test_seal_without_an_image_keeps_the_token_response(tmp_path):
    path, app = _app(tmp_path, c2pa_reader=ExplodingReader(), trust_store=Down("witness_unavailable"))
    with TestClient(app) as client:
        investigation = _create(client, "Warm water cures diabetes.")
        sealed = client.post(f"/api/investigations/{investigation}/seal")
    body = sealed.json()
    stored = _stored(path)
    assert sealed.status_code == 200
    assert set(body) == {"assessmentToken", "expiresAt"}
    assert body["assessmentToken"].encode() not in Path(path).read_bytes()
    assert stored["primaryClaim"] == "Warm water cures diabetes."
    assert "provenance" not in stored
    assert app.state.c2pa_reader.calls == 0
    assert app.state.trust_store.selects == 0


def test_authorized_credential_snapshot_uses_the_commit_callback(tmp_path):
    path = _ledger(tmp_path)
    store = Observed(_success_store(), path)
    reader = Reader([_credential("credentials_trusted", label="urn:c2pa:sealed")])
    seen = {}

    def _remember(request):
        seen["body"] = request.content.decode()
        return _assessment()

    app = create_app(
        settings=_settings(ledger_path=path, openai_api_key=DUMMY_OPENAI),
        trust_store=store,
        c2pa_reader=reader,
        openai_transport=httpx.MockTransport(_remember),
    )
    with TestClient(app) as client:
        _ensure_auth(client)
        investigation = _create(client, "The event happened.")
        uploaded = _upload(client, investigation, _png())
        assert uploaded.status_code == 200, uploaded.text
        server_hash = uploaded.json()["sha256"]
        sealed = client.post(
            f"/api/investigations/{investigation}/seal",
            headers={"X-Client-Sha256": FORGED_HASH},
            json={
                "provenance": {
                    "marker": CLIENT_MARKER,
                    "result": {"status": "POTENTIAL_MANIPULATION"},
                    "policy": {"activationDigest": "99" * 32},
                },
                "sha256": FORGED_HASH,
            },
        )
        assessed = client.post(
            f"/api/investigations/{investigation}/assess",
            json={"assessmentToken": sealed.json()["assessmentToken"], "primaryClaim": "FORGED"},
        )
    stored = _stored(path)
    provenance = stored["provenance"]
    assert sealed.status_code == 200
    assert set(sealed.json()) == {"assessmentToken", "expiresAt"}
    assert "BEGIN CERTIFICATE" not in sealed.text
    assert CLIENT_MARKER not in sealed.text
    assert store.selects == 3
    assert store.rows_at_select[2] == 0
    assert provenance["result"]["status"] == "credentials_trusted"
    assert provenance["result"]["kind"] == "credential"
    assert provenance["policy"]["releaseSequence"] == 4
    assert provenance["policy"]["activationDigest"] == ACTIVATION
    assert provenance["image"]["sha256"] == server_hash
    assert provenance["image"]["sha256"] != FORGED_HASH
    assert CLIENT_MARKER not in json.dumps(stored)
    assert "99" * 32 not in json.dumps(stored)
    assert FORGED_HASH not in json.dumps(stored)
    assert "BEGIN CERTIFICATE" not in json.dumps(stored)
    assert "POTENTIAL_MANIPULATION" not in json.dumps(stored)
    assert assessed.status_code == 200
    assert assessed.json()["assessment"] == "INSUFFICIENT_EVIDENCE"
    assert assessed.json()["imageEvidence"]["provenance"]["result"]["status"] == "credentials_trusted"
    assert assessed.json()["imageEvidence"]["provenance"]["result"]["kind"] == "credential"
    assert assessed.json()["imageEvidence"]["provenance"]["eventDepiction"] == "not_established"
    assert "credentials_trusted" not in seen["body"]
    assert "BEGIN CERTIFICATE" not in seen["body"]
    assert _text_sha(MANIFEST) not in seen["body"]
    assert CLIENT_MARKER not in seen["body"]


def test_reader_timeout_and_crash_still_seal(tmp_path):
    path, _app_obj, client, investigation = _image_case(
        tmp_path,
        trust_store=_success_store(),
        c2pa_reader=Reader([{
            "version": READER_VERSION,
            "status": "verification_failed",
            "failureCode": "reader_timeout",
            "checks": None,
            "manifests": [],
            "actions": [],
            "actionsWithheld": True,
        }]),
    )
    sealed = client.post(f"/api/investigations/{investigation}/seal")
    stored = _stored(path)
    assert sealed.status_code == 200
    assert set(sealed.json()) == {"assessmentToken", "expiresAt"}
    assert stored["provenance"]["result"]["failureCode"] == "reader_timeout"
    assert stored["provenance"]["result"]["status"] == "verification_failed"
    assert stored["provenance"]["result"]["kind"] == "technical"
    assert stored["provenance"]["result"]["status"] not in ASSESSMENT_OUTCOMES

    crash_dir = tmp_path / "crash"
    crash_dir.mkdir()
    crash_path, crash_app = _app(
        crash_dir,
        trust_store=_success_store(),
        c2pa_reader=ExplodingReader(),
    )
    with TestClient(crash_app) as crash_client:
        _ensure_auth(crash_client)
        crash_case = _create(crash_client, "The event happened.")
        assert _upload(crash_client, crash_case, _png()).status_code == 200
        crashed = crash_client.post(f"/api/investigations/{crash_case}/seal")
    crashed_record = _stored(crash_path)["provenance"]
    assert crashed.status_code == 200
    assert crashed_record["result"]["failureCode"] == "reader_crash"
    assert crashed_record["policy"]["releaseSequence"] == 4
    assert "exploded" not in json.dumps(crashed_record)
    assert crash_app.state.c2pa_reader.calls == 1


def test_unsupported_c2pa_container_still_seals(tmp_path):
    path, _app_obj, client, investigation = _image_case(
        tmp_path,
        trust_store=_success_store(),
        c2pa_reader=Reader([{
            "version": READER_VERSION,
            "status": "not_performed",
            "checks": None,
            "actions": [],
            "actionsWithheld": True,
        }]),
    )
    sealed = client.post(f"/api/investigations/{investigation}/seal")
    record = _stored(path)["provenance"]
    assert sealed.status_code == 200
    assert record["result"]["status"] == "not_performed"
    assert record["result"]["kind"] == "credential"
    assert record["result"]["failureCode"] is None
    assert record["policy"]["releaseSequence"] == 4
    assert record["result"]["status"] not in ASSESSMENT_OUTCOMES


def test_missing_trust_configuration_seals_a_technical_record(tmp_path, monkeypatch):
    reader = ExplodingReader()
    path, app, client, investigation = _image_case(tmp_path, c2pa_reader=reader)
    monkeypatch.setattr(
        "ssl.create_default_context",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("operating-system trust")),
    )
    sealed = client.post(f"/api/investigations/{investigation}/seal")
    record = _stored(path)["provenance"]
    assert isinstance(app.state.trust_store, UnavailableTrustStore)
    assert sealed.status_code == 200
    assert record["policy"] is None
    assert record["result"]["kind"] == "technical"
    assert record["result"]["failureCode"] == "trust_configuration"
    assert reader.calls == 0
    assert "trust" not in sealed.json()
    assert "BEGIN CERTIFICATE" not in sealed.text


def test_unavailable_trust_store_keeps_its_failure_code(tmp_path):
    store = Down("witness_unavailable")
    path, _app_obj, client, investigation = _image_case(tmp_path, trust_store=store, c2pa_reader=ExplodingReader())
    sealed = client.post(f"/api/investigations/{investigation}/seal")
    record = _stored(path)["provenance"]
    assert sealed.status_code == 200
    assert record["policy"] is None
    assert record["result"]["failureCode"] == "witness_unavailable"
    assert record["result"]["status"] == "verification_failed"
    assert store.selects == 0
    assert _app_obj.state.c2pa_reader.calls == 0


def test_changed_image_returns_identity_mismatch_and_no_snapshot(tmp_path):
    path, _app_obj, client, investigation = _image_case(tmp_path, trust_store=_success_store(), c2pa_reader=Reader([
        _credential("credentials_trusted", label="urn:c2pa:should-not-run"),
    ]))
    stored_file = next((Path(path).parent / "assets").glob("*.bin"))
    stored_file.write_bytes(b"\x00" * 16)
    sealed = client.post(f"/api/investigations/{investigation}/seal")
    assert sealed.status_code == 409
    assert sealed.json() == {
        "code": "identity_mismatch",
        "message": "The stored image changed before the assessment could be sealed.",
    }
    assert sealed.json()["code"] not in ASSESSMENT_OUTCOMES
    assert sealed.json()["code"] != "ledger_unavailable"
    assert "manipulation" not in sealed.text.lower()
    assert _snapshots(path) == []
    assert _app_obj.state.c2pa_reader.calls == []


def test_policy_suspension_retries_once_before_insertion(tmp_path):
    path = _ledger(tmp_path)
    store = Observed(Store(
        [
            _pin(4, MANIFEST, TIMESTAMP),
            _pin(6, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
        ],
        [
            _select(4, MANIFEST, TIMESTAMP),
            _select(4, MANIFEST, TIMESTAMP),
            failure("root_suspended"),
            _select(6, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
            _select(6, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
            _select(6, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
        ],
        [_confirmed(4), _confirmed(6, ACTIVATION_NEXT)],
    ), path)
    reader = Reader([
        _credential("credentials_trusted", label="urn:c2pa:stale-root"),
        _credential("credentials_untrusted", _checks(certificateTrust="untrusted"), label="urn:c2pa:fresh-root"),
    ])
    app = create_app(
        settings=_settings(ledger_path=path, openai_api_key=DUMMY_OPENAI),
        trust_store=store,
        c2pa_reader=reader,
    )
    with TestClient(app) as client:
        _ensure_auth(client)
        investigation = _create(client, "The event happened.")
        assert _upload(client, investigation, _png()).status_code == 200
        sealed = client.post(f"/api/investigations/{investigation}/seal")
    stored = _stored(path)
    assert sealed.status_code == 200
    assert store.selects == 6
    assert store.rows_at_select[2] == 0
    assert store.rows_at_select[5] == 0
    assert stored["provenance"]["policy"]["releaseSequence"] == 6
    assert stored["provenance"]["result"]["status"] == "credentials_untrusted"
    assert "stale-root" not in json.dumps(stored)
    assert len(reader.calls) == 2
    assert reader.calls[1]["manifest"] == MANIFEST_NEXT


def test_policy_supersession_retries_exactly_once(tmp_path):
    path, _app_obj, client, investigation = _image_case(
        tmp_path,
        trust_store=Store(
            [
                _pin(4, MANIFEST, TIMESTAMP),
                _pin(9, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
            ],
            [
                _select(4, MANIFEST, TIMESTAMP),
                _select(4, MANIFEST, TIMESTAMP),
                _select(9, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
                _select(9, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
                _select(9, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
                _select(9, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
            ],
            [_confirmed(4), _confirmed(9, ACTIVATION_NEXT)],
        ),
        c2pa_reader=Reader([
            _credential("credentials_trusted", label="urn:c2pa:first-policy"),
            _credential("credentials_trusted", label="urn:c2pa:second-policy"),
        ]),
    )
    sealed = client.post(f"/api/investigations/{investigation}/seal")
    stored = _stored(path)
    assert sealed.status_code == 200
    assert stored["provenance"]["policy"]["releaseSequence"] == 9
    assert stored["provenance"]["policy"]["activationDigest"] == ACTIVATION_NEXT
    assert stored["provenance"]["result"]["status"] == "credentials_trusted"
    assert "first-policy" not in json.dumps(stored)
    assert "second-policy" in json.dumps(stored)
    assert len(_app_obj.state.c2pa_reader.calls) == 2


def test_second_authorization_failure_discards_both_credential_results(tmp_path):
    path, app, client, investigation = _image_case(
        tmp_path,
        trust_store=Store(
            [_pin(4, MANIFEST, TIMESTAMP), _pin(6, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT)],
            [
                _select(4, MANIFEST, TIMESTAMP),
                _select(4, MANIFEST, TIMESTAMP),
                _select(9, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
                _select(6, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
                _select(6, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
                failure("root_suspended"),
            ],
            [_confirmed(4), _confirmed(6, ACTIVATION_NEXT)],
        ),
        c2pa_reader=Reader([
            _credential("credentials_trusted", label="urn:c2pa:first-attempt"),
            _credential("credentials_trusted", label="urn:c2pa:second-attempt"),
        ]),
    )
    sealed = client.post(f"/api/investigations/{investigation}/seal")
    record = _stored(path)["provenance"]
    assert sealed.status_code == 200
    assert record["policy"] is None
    assert record["result"] == {
        "kind": "technical",
        "status": "verification_failed",
        "failureCode": "root_suspended",
        "checks": None,
        "manifests": [],
    }
    raw = json.dumps(_stored(path))
    assert "first-attempt" not in raw
    assert "second-attempt" not in raw
    assert "BEGIN CERTIFICATE" not in raw
    assert len(app.state.c2pa_reader.calls) == 2
    assert len(_snapshots(path)) == 1


def test_other_authorization_failure_does_not_retry(tmp_path):
    path, app, client, investigation = _image_case(
        tmp_path,
        trust_store=Store(
            [_pin(4, MANIFEST, TIMESTAMP), _pin(8, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT)],
            [
                _select(4, MANIFEST, TIMESTAMP),
                _select(4, MANIFEST, TIMESTAMP),
                _select(4, MANIFEST, TIMESTAMP, purpose="suspension"),
                _select(8, MANIFEST_NEXT, TIMESTAMP_NEXT, ACTIVATION_NEXT, SUSPENSION_NEXT),
            ],
            [_confirmed(4), _confirmed(8, ACTIVATION_NEXT)],
        ),
        c2pa_reader=Reader([
            _credential("credentials_trusted", label="urn:c2pa:downgraded"),
            _credential("credentials_trusted", label="urn:c2pa:should-not-run"),
        ]),
    )
    sealed = client.post(f"/api/investigations/{investigation}/seal")
    record = _stored(path)["provenance"]
    assert sealed.status_code == 200
    assert record["policy"] is None
    assert record["result"]["failureCode"] == "policy_downgrade"
    assert "downgraded" not in json.dumps(record)
    assert "should-not-run" not in json.dumps(record)
    assert len(app.state.c2pa_reader.calls) == 1


def test_remote_and_relative_trust_configuration_is_refused(tmp_path):
    with pytest.raises(StartupError, match="local path"):
        create_app(settings=_production(tmp_path / "remote", c2pa_trust_root="https://trust.example/root"))
    with pytest.raises(StartupError, match="absolute local paths"):
        create_app(settings=_production(tmp_path / "relative", c2pa_trust_root="trust/root"))
    with pytest.raises(StartupError, match="local path"):
        create_app(settings=_settings(
            ledger_path=_ledger(tmp_path / "local-url"),
            c2pa_trust_root="https://trust.example/root",
        ))


def test_complete_local_configuration_does_not_use_operating_system_trust(tmp_path, monkeypatch):
    root = tmp_path / "trust-root"
    state = tmp_path / "state" / "high-water.json"
    pin = tmp_path / "pin" / "root-pin.json"
    ledger_path = _ledger(tmp_path / "db")
    settings = _settings(
        ledger_path=ledger_path,
        openai_api_key=DUMMY_OPENAI,
        c2pa_trust_root=str(root),
        c2pa_trust_state_path=str(state),
        c2pa_trust_pin_path=str(pin),
        c2pa_trust_caller_id="runtime",
        c2pa_witness_mac_key="ab" * 32,
        c2pa_root_mac_key="cd" * 32,
    )

    class Offline:
        def read(self, _caller):
            raise RuntimeError("offline witness")

        def compare_and_set(self, *_args):
            raise RuntimeError("offline witness")

        def append_suspension(self, *_args):
            raise RuntimeError("offline witness")

        def append_replacement(self, *_args):
            raise RuntimeError("offline witness")

    reader = ExplodingReader()
    app = create_app(settings=settings, trust_witness=Offline(), trust_root_control=Offline(), c2pa_reader=reader)
    assert isinstance(app.state.trust_store, TrustStore)
    monkeypatch.setattr(
        "ssl.create_default_context",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("operating-system trust")),
    )
    with TestClient(app) as client:
        _ensure_auth(client)
        investigation = _create(client, "The event happened.")
        assert _upload(client, investigation, _png()).status_code == 200
        sealed = client.post(f"/api/investigations/{investigation}/seal")
        health = client.get("/api/health")
    record = _stored(ledger_path)["provenance"]
    assert sealed.status_code == 200
    assert record["policy"] is None
    assert record["result"]["failureCode"] in FAILURE_CODES
    assert record["result"]["failureCode"] not in ASSESSMENT_OUTCOMES
    assert reader.calls == 0
    assert str(root) not in sealed.text
    assert "ab" * 32 not in sealed.text
    assert "BEGIN CERTIFICATE" not in sealed.text
    assert "c2paTrust" not in health.text
    assert str(root) not in health.text


def test_a_trust_path_cannot_name_the_ledger(tmp_path):
    ledger_path = _ledger(tmp_path)
    settings = _settings(
        ledger_path=ledger_path,
        c2pa_trust_root=ledger_path,
        c2pa_trust_state_path=str(tmp_path / "state" / "high-water.json"),
        c2pa_trust_pin_path=str(tmp_path / "pin" / "root-pin.json"),
        c2pa_trust_caller_id="runtime",
        c2pa_witness_mac_key="ab" * 32,
        c2pa_root_mac_key="cd" * 32,
    )

    class Offline:
        def read(self, _caller):
            raise AssertionError("witness")

        def compare_and_set(self, *_args):
            raise AssertionError("witness")

        def append_suspension(self, *_args):
            raise AssertionError("witness")

        def append_replacement(self, *_args):
            raise AssertionError("witness")

    app = create_app(settings=settings, trust_witness=Offline(), trust_root_control=Offline())
    assert isinstance(app.state.trust_store, UnavailableTrustStore)
    assert not (tmp_path / "releases").exists()
