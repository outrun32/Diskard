"""Durability regressions: no target credentials or network required."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest
from sqlalchemy import inspect, text

from diskard.console.bridge import FakeExecutionBridge, _suite_status
from diskard.console.contracts import EventRecord, TargetProfile
from diskard.console.redaction import redact
from diskard.console.reports import render_junit, render_markdown
from diskard.console.repository import ExecutorBusy, RunStore, make_engine, migrate
from diskard.console.runtime import ConsoleRuntime
from diskard.console.settings import ConsoleSettings


@pytest.fixture
def store(tmp_path):
    engine = make_engine("sqlite:///" + (tmp_path / "regression.db").as_posix())
    migrate(engine)
    yield RunStore(engine, event_max_bytes=64)
    engine.dispose()


def add_run(store, run_id="test", **kwargs):
    profile = store.upsert_profile(
        TargetProfile(
            id="fixture", name="Original", adapter="fixture", base_url="http://fixture.invalid"
        )
    )
    return store.create_run(
        run_id=run_id,
        profile=profile,
        mode="experiment",
        origin="test",
        attack="fixture",
        driver="fixture",
        options={"budget": 1},
        **kwargs,
    )


def test_migrations_use_alembic_and_are_repeatable(store):
    migrate(store.engine)
    assert "alembic_version" in inspect(store.engine).get_table_names()
    with store.engine.connect() as connection:
        assert (
            connection.execute(text("select version_num from alembic_version")).scalar_one()
            == "0003_event_sequence_constraint"
        )


def test_concurrent_events_have_contiguous_unique_sequence(store):
    add_run(store)
    with ThreadPoolExecutor(max_workers=8) as workers:
        list(
            workers.map(
                lambda index: store.append_event(
                    "test", EventRecord(type="test", data={"i": index})
                ),
                range(40),
            )
        )
    assert [e["sequence"] for e in store.events_page("test")["items"]] == list(range(1, 41))
    assert len(store.events_page("test", after=10, limit=3)["items"]) == 3


def test_finalization_updates_replay_and_is_immutable(store):
    add_run(store, replay_spec={"complete": False})
    store.claim_next_run()
    result = dict(
        status="completed",
        raw_engine_result={"check_status": "pass"},
        summary={"verdict": "clean"},
        replay_spec={"complete": True, "resolved_inputs": {"text": "frozen"}},
    )
    store.finalize("test", **result)
    assert store.run("test")["replay_spec"]["resolved_inputs"] == {"text": "frozen"}
    with pytest.raises(ValueError):
        store.finalize("test", **result)
    with pytest.raises(ValueError):
        store.append_event("test", EventRecord(type="late"))
    assert store.request_cancel("test")["status"] == "completed"


def test_same_submission_rejects_different_parent(store):
    add_run(store, client_submission_id="once")
    with pytest.raises(ValueError, match="different request"):
        add_run(store, "other", client_submission_id="once", parent_run_id="different")


def test_no_false_pass_and_valid_xml_for_hostile_errors():
    for status in ("queued", "running", "cancelling", "completed", "imported"):
        root = ElementTree.fromstring(render_junit({"id": '<x>"', "status": status}))
        assert root.find("testcase/skipped") is not None
    root = ElementTree.fromstring(render_junit({"status": "failed", "error": 'bad "<&>"'}))
    assert root.find("testcase/error").attrib["message"] == 'bad "<&>"'
    assert "payload text" in render_markdown({"events": [{"data": {"message": "payload text"}}]})


def test_redaction_handles_embedded_urls_and_bad_ports():
    value = redact("connection failed at postgresql://user:password@localhost:5432/db")
    assert "password" not in value
    assert redact("https://user:secret@host:bad") == "[REDACTED]"


def test_oracle_errors_are_never_suite_pass():
    result = SimpleNamespace(
        results=[
            SimpleNamespace(
                steps=[SimpleNamespace(error=None, results=[SimpleNamespace(status="error")])]
            )
        ]
    )
    assert _suite_status(result) == "error"


@pytest.mark.asyncio
async def test_snapshot_execution_and_rerun_survive_profile_change(store, monkeypatch, tmp_path):
    import diskard.console.runtime as runtime_module

    seen = []

    class RecordingBridge(FakeExecutionBridge):
        async def execute(self, spec, sink, cancellation):
            seen.append(spec)
            return await super().execute(spec, sink, cancellation)

    monkeypatch.setattr(runtime_module, "make_engine", lambda _: store.engine)
    runtime = ConsoleRuntime(
        ConsoleSettings(database_url="postgresql://local/test", profile_file=tmp_path / "none"),
        bridge_factory=RecordingBridge,
    )
    runtime.start()
    try:
        store.upsert_profile(
            TargetProfile(
                id="fixture", name="Original", adapter="fixture", base_url="http://original.invalid"
            )
        )
        parent = runtime.create_run(
            profile_id="fixture",
            attack="fixture",
            driver="fixture",
            options={"budget": 1},
            origin="test",
            submission_id="once",
        )
        store.upsert_profile(
            TargetProfile(
                id="fixture", name="Edited", adapter="fixture", base_url="http://edited.invalid"
            ),
            explicit=True,
        )

        async def finished(run_id):
            for _ in range(100):
                saved = store.run(run_id)
                if saved["status"] in {"completed", "failed"}:
                    assert saved["status"] == "completed", saved
                    return saved
                await asyncio.sleep(0.02)
            pytest.fail("executor did not finish")

        saved = await finished(parent["id"])
        assert saved["replay_spec"]["complete"]
        child = await runtime.rerun(parent["id"])
        await finished(child["id"])
        assert child["parent_run_id"] == parent["id"]
        assert child["id"] != parent["id"]
        assert [item.profile.base_url for item in seen] == ["http://original.invalid"] * 2
        assert (
            seen[1].resolved_manifest["resolved_inputs"] == saved["replay_spec"]["resolved_inputs"]
        )
    finally:
        await runtime.stop()


@pytest.mark.asyncio
async def test_shutdown_holds_lease_until_worker_finishes(store, monkeypatch, tmp_path):
    import diskard.console.runtime as runtime_module

    entered, release = threading.Event(), threading.Event()

    class BlockingBridge(FakeExecutionBridge):
        async def execute(self, spec, sink, cancellation):
            entered.set()
            await asyncio.to_thread(release.wait, 10)
            assert cancellation.is_set()
            return await super().execute(spec, sink, cancellation)

    monkeypatch.setattr(runtime_module, "make_engine", lambda _: store.engine)
    runtime = ConsoleRuntime(
        ConsoleSettings(database_url="postgresql://local/test", profile_file=tmp_path / "none"),
        bridge_factory=BlockingBridge,
    )
    add_run(store)
    runtime.start()
    try:
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.02)
        assert entered.is_set()
        stopping = asyncio.create_task(runtime.stop())
        await asyncio.sleep(0.05)
        assert not stopping.done()
        with pytest.raises(ExecutorBusy):
            store.acquire_executor()
        release.set()
        await stopping
        assert store.run("test")["status"] == "cancelled"
    finally:
        release.set()


def test_postgres_concurrency_and_ownership_when_configured():
    import os
    from uuid import uuid4

    url = os.getenv("DISKARD_TEST_DATABASE_URL")
    if not url:
        pytest.skip("set DISKARD_TEST_DATABASE_URL to a disposable PostgreSQL database")
    engine = make_engine(url)
    migrate(engine)
    store = RunStore(engine)
    run_id = "pg-" + uuid4().hex
    try:
        lease = store.acquire_executor()
        with pytest.raises(ExecutorBusy):
            store.acquire_executor()
        lease.check()
        lease.release()
        with store.acquire_executor().connection as connection:
            connection.execute(text("select pg_advisory_unlock_all()"))
        with ThreadPoolExecutor(max_workers=8) as workers:
            results = list(
                workers.map(lambda _: add_run(store, run_id, client_submission_id=run_id), range(8))
            )
        assert {row["id"] for row in results} == {run_id}
        with ThreadPoolExecutor(max_workers=8) as workers:
            list(
                workers.map(
                    lambda i: store.append_event(
                        run_id, EventRecord(type="parallel", data={"i": i})
                    ),
                    range(30),
                )
            )
        assert [e["sequence"] for e in store.events_page(run_id)["items"]] == list(range(1, 31))
    finally:
        engine.dispose()
