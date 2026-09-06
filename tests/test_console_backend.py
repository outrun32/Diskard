from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from diskard.console.bridge import (
    FakeExecutionBridge,
    InvestmentExecutionBridge,
    auto_bootstrap_enabled,
)
from diskard.console.contracts import EventRecord, RunSpec, TargetProfile
from diskard.console.redaction import REDACTED, redact
from diskard.console.reports import render
from diskard.console.repository import RunStore, make_engine, migrate
from diskard.console.runtime import default_local_profile
from diskard.console.settings import ConsoleSettings


def profile() -> TargetProfile:
    return TargetProfile.model_validate(
        {
            "id": "fixture",
            "name": "Fixture",
            "adapter": "fixture",
            "base_url": "http://fixture.local",
            "actors": {},
        }
    )


@pytest.mark.asyncio
async def test_investment_target_validation_uses_healthz(monkeypatch):
    requested: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, json={"status": "ok"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    monkeypatch.setattr("diskard.console.bridge.httpx.AsyncClient", lambda **_: client)
    target = TargetProfile.model_validate(
        {
            "id": "investment",
            "name": "Investment stand",
            "adapter": "investment-stand",
            "base_url": "http://stand.local",
        }
    )

    report = await InvestmentExecutionBridge().validate(target, attacks=[])

    assert requested == ["http://stand.local/healthz"]
    target_check = next(check for check in report.checks if check["id"] == "target_api")
    assert target_check["status"] == "ready"


@pytest.mark.asyncio
async def test_local_bootstrap_is_validated_disabled_and_cached(monkeypatch):
    import examples.connectors.investment_stand.identity as identity

    calls = {"tokens": 0, "keys": 0}
    key_tokens: list[str] = []

    class FakeBootstrap:
        fail = False

        def __init__(self, **kwargs):
            pass

        async def get_user_access_token(self, cus):
            calls["tokens"] += 1
            if self.fail:
                raise RuntimeError("keycloak unavailable")
            return f"token-{cus}"

        async def create_api_key(self, access_token):
            calls["keys"] += 1
            key_tokens.append(access_token)
            return f"key-{access_token}"

    async def healthy(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(healthy))
    monkeypatch.setattr("diskard.console.bridge.httpx.AsyncClient", lambda **_: client)
    monkeypatch.setattr(identity, "KeycloakBootstrap", FakeBootstrap)
    monkeypatch.setenv("DISKARD_TEST_STALE_TOKEN", "stale-token")
    target = TargetProfile.model_validate(
        {
            "id": "investment-local",
            "name": "Local investment stand",
            "adapter": "investment-stand",
            "base_url": "http://stand.local",
            "actors": {
                "attacker": {"cus": "1001"},
                "trigger_user": {"cus": "1002"},
                "data_subject": {
                    "cus": "1003",
                    "access_token_env": "DISKARD_TEST_STALE_TOKEN",
                },
            },
            "adapter_options": {
                "auto_bootstrap": True,
                "invest_url": "http://invest.local",
            },
        }
    )
    bridge = InvestmentExecutionBridge()

    attacks = ["cross-user-global-policy-poisoning"]
    report = await bridge.validate(target, attacks=attacks)
    assert report.ready
    assert calls["keys"] == 3
    assert "stale-token" not in key_tokens

    actors = await bridge._actors(
        target, required_roles={"attacker", "trigger_user", "data_subject"}
    )
    assert actors["data_subject"].access_token == "token-1003"
    assert calls["keys"] == 3

    FakeBootstrap.fail = True
    failed = await InvestmentExecutionBridge().validate(target, attacks=attacks)
    actor_checks = [item for item in failed.checks if item["id"].startswith("actor:")]
    assert actor_checks and all(item["status"] == "blocked" for item in actor_checks)

    disabled = target.model_copy(update={"adapter_options": {"auto_bootstrap": False}})
    assert auto_bootstrap_enabled(disabled) is False


def test_default_local_profile_keeps_agent_endpoint_in_sync(monkeypatch):
    monkeypatch.setenv("DISKARD_TARGET_URL", "http://custom.local:9999")
    target = default_local_profile()
    assert target.base_url == "http://custom.local:9999"
    assert target.adapter_options["agent_api_url"] == target.base_url


@pytest.fixture
def store(tmp_path: Path):
    engine = make_engine("sqlite:///" + str(tmp_path / "console.db").replace("\\", "/"))
    migrate(engine)
    value = RunStore(engine, event_max_bytes=80)
    yield value
    engine.dispose()


def test_full_check_is_atomic_and_retry_does_not_duplicate(store, monkeypatch):
    saved_profile = store.upsert_profile(profile())
    kwargs = dict(
        profile=saved_profile,
        attacks=["first", "second"],
        driver="fixture",
        submission_id="full-check",
        source_sha="test",
    )
    group = store.create_check(**kwargs)
    assert store.create_check(**kwargs)["id"] == group["id"]
    assert len(store.check(group["id"])["runs"]) == 2
    assert store.overview()["counts"]["runs"] == 2
    original = store.create_run

    def fail_second(**values):
        if values["attack"] == "second":
            raise ValueError("injected failure")
        return original(**values)

    monkeypatch.setattr(store, "create_run", fail_second)
    with pytest.raises(ValueError, match="injected"):
        store.create_check(**{**kwargs, "submission_id": "rollback"})
    assert store.list_runs()[1] == 2


def test_redaction_covers_nested_headers_urls_and_known_values():
    value = redact(
        {
            "headers": {"Authorization": "Bearer abc"},
            "url": "https://user:password@example.test/path?api_key=abc",
            "nested": ["abc", {"password": "abc"}],
        },
        ("abc",),
    )
    assert REDACTED in str(value)
    assert "abc" not in str(value)
    assert "password" not in value["url"]


def test_repository_persists_ordered_events_and_idempotent_submission(store: RunStore):
    stored_profile = store.upsert_profile(profile())
    first = store.create_run(
        run_id="run-1",
        profile=stored_profile,
        mode="experiment",
        origin="test",
        attack="fixture",
        driver="fixture",
        options={"budget": 1, "repeat": 1},
        client_submission_id="same-submit",
    )
    second = store.create_run(
        run_id="run-2",
        profile=stored_profile,
        mode="experiment",
        origin="test",
        attack="fixture",
        driver="fixture",
        options={"budget": 1, "repeat": 1},
        client_submission_id="same-submit",
    )
    assert first["id"] == second["id"] == "run-1"

    store.append_event("run-1", EventRecord(type="one", data={"secret": "Bearer abc"}))
    store.append_event("run-1", EventRecord(type="two", data={"large": "x" * 500}))
    page = store.events_page("run-1")
    assert [item["sequence"] for item in page["items"]] == [1, 2]
    assert page["items"][0]["data"]["secret"] == REDACTED
    assert page["items"][1]["truncated"] is True
    assert page["items"][1]["artifact"].startswith("{")
    assert page["last_event_sequence"] == 2


def test_profile_edit_increments_version(store: RunStore):
    first = store.upsert_profile(profile())
    changed = profile().model_copy(update={"name": "Fixture v2"})
    second = store.upsert_profile(changed, explicit=True)
    assert first["version"] == 1
    assert second["version"] == 2


def test_legacy_import_is_deduplicated_and_marks_missing_trace(tmp_path: Path, store: RunStore):
    source = tmp_path / "result.json"
    source.write_text(
        '{"attack":"legacy-attack","status":"vulnerable","details":{"x":1}}',
        encoding="utf-8",
    )
    run_id = store.import_legacy(source)
    assert store.import_legacy(source) == run_id
    saved = store.run(run_id)
    assert saved["status"] == "imported"
    assert saved["finished_at"] is None
    assert saved["summary"]["missing_fields"] == ["trace", "replay_inputs", "execution_timestamps"]
    assert saved["events"][0]["type"] == "legacy_import"


def test_fake_bridge_provides_exact_recorded_replay():
    events: list[EventRecord] = []

    async def emit(item: EventRecord):
        events.append(item)

    result = asyncio.run(
        FakeExecutionBridge().execute(
            RunSpec(
                run_id="fixture-run",
                profile=profile(),
                attack="fixture",
                driver="fixture",
                options={"budget": 1, "repeat": 1},
                resolved_manifest={"schema_version": 1},
            ),
            emit,
            type("Token", (), {"is_set": lambda self: False})(),
        )
    )
    assert result.status == "completed"
    assert result.replay_spec["complete"] is True
    assert len(events) == 2


def test_html_report_escapes_stored_content_and_junit_keeps_failures():
    run = {
        "id": "x",
        "mode": "experiment",
        "origin": "test",
        "target_profile_id": "fixture",
        "target_profile_version": 1,
        "status": "completed",
        "engine_version": "test",
        "scenario_version": "fixture",
        "summary": {"verdict": "vulnerable", "message": "<script>alert(1)</script>"},
        "events": [{"sequence": 1, "type": "reply", "actor_id": "a", "data": {"text": "<b>x</b>"}}],
        "replay_spec": {"complete": False, "unsupported_reasons": ["fixture"]},
    }
    html, _ = render(run, "html", max_bytes=100000)
    junit, _ = render(run, "junit", max_bytes=100000)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "<failure" in junit


def test_settings_reject_non_postgres_database():
    with pytest.raises(ValueError):
        ConsoleSettings(database_url="sqlite:///nope")


def test_investment_bridge_runs_existing_giskard_scenario_with_mocked_transport(monkeypatch):
    import examples.connectors.investment_stand.backend as adapter

    class FakeStand:
        def __init__(self, base_url):
            self.base_url = base_url

        async def chat(self, api_key, session_id, message, auth_mode="vulnerable"):
            return {"reply": "synthetic target reply", "raw": {"session_id": session_id}}

        async def finalize(self, api_key, session_id):
            return {"ok": True}

        async def aclose(self):
            return None

    class FakeMongo:
        def __init__(self, mongo_uri):
            self.snapshots = 0

        def snapshot(self):
            self.snapshots += 1
            return (
                []
                if self.snapshots == 1
                else [{"policy_id": "synthetic", "statement": "for cus=1003"}]
            )

        @staticmethod
        def new_records(before, after):
            before_ids = {item["policy_id"] for item in before}
            return [item for item in after if item["policy_id"] not in before_ids]

        def delete_by_source_session(self, cleanup_key):
            return 1

    class FakeSemantic:
        def __init__(self, mongo_uri):
            pass

        def find_by_user(self, user_id):
            return []

        def delete_by_user(self, user_id):
            return 0

    class FakeInvest:
        def __init__(self, base_url):
            self.base_url = base_url

        async def get_client(self, cus, access_token):
            return {"accounts": [{"account_id": "synthetic-account"}]}

        async def aclose(self):
            return None

    monkeypatch.setattr(adapter, "StandClient", FakeStand)
    monkeypatch.setattr(adapter, "MongoEvidence", FakeMongo)
    monkeypatch.setattr(adapter, "SemanticMemoryEvidence", FakeSemantic)
    monkeypatch.setattr(adapter, "InvestServerEvidence", FakeInvest)
    for name in (
        "DISKARD_TEST_ATTACKER_KEY",
        "DISKARD_TEST_TRIGGER_KEY",
        "DISKARD_TEST_SUBJECT_KEY",
    ):
        monkeypatch.setenv(name, "synthetic-secret")
    monkeypatch.setenv("DISKARD_TEST_MONGO", "mongodb://synthetic")
    profile_value = TargetProfile.model_validate(
        {
            "id": "investment-fixture",
            "name": "Investment fixture",
            "adapter": "investment-stand",
            "base_url": "http://fixture.local",
            "actors": {
                "attacker": {"cus": "1001", "credential_env": "DISKARD_TEST_ATTACKER_KEY"},
                "trigger_user": {
                    "cus": "1002",
                    "credential_env": "DISKARD_TEST_TRIGGER_KEY",
                },
                "data_subject": {
                    "cus": "1003",
                    "credential_env": "DISKARD_TEST_SUBJECT_KEY",
                    "access_token_env": "DISKARD_TEST_SUBJECT_KEY",
                },
            },
            "adapter_options": {
                "invest_url": "http://fixture-invest.local",
                "mongo_uri_env": "DISKARD_TEST_MONGO",
            },
        }
    )
    events: list[EventRecord] = []
    result = asyncio.run(
        InvestmentExecutionBridge().execute(
            RunSpec(
                run_id="bridge-fixture-run",
                profile=profile_value,
                attack="cross-user-global-policy-poisoning",
                driver="template",
                options={"budget": 1, "repeat": 1},
                resolved_manifest={"schema_version": 1},
            ),
            events.append,
            SimpleNamespace(is_set=lambda: False),
        )
    )
    assert result.status == "completed"
    assert result.summary["check_status"] == "pass"
    assert any(event.type == "operation.started" for event in events)
    assert any(event.type == "run.result" for event in events)
