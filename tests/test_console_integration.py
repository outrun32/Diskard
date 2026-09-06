"""Merged application acceptance; fixture execution never contacts a target."""

import asyncio

import httpx
import pytest

from diskard.console.bridge import FakeExecutionBridge
from diskard.console.repository import make_engine
from diskard.console.runtime import ConsoleRuntime
from diskard.console.settings import ConsoleSettings


@pytest.mark.asyncio
async def test_http_operator_journey(tmp_path, monkeypatch):
    import diskard.console.runtime as runtime_module
    import ui.server as server

    engine = make_engine("sqlite:///" + (tmp_path / "journey.db").as_posix())
    monkeypatch.setattr(runtime_module, "make_engine", lambda _: engine)
    runtime = ConsoleRuntime(
        ConsoleSettings(database_url="postgresql://localhost/test", profile_file=tmp_path / "none"),
        bridge_factory=FakeExecutionBridge,
    )
    runtime.start()
    monkeypatch.setattr(server.ctx, "console", runtime)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server.app), base_url="http://localhost:8700"
    ) as client:
        try:
            profile = {
                "id": "fixture",
                "name": "Synthetic HTTP test",
                "adapter": "fixture",
                "base_url": "http://fixture.invalid",
            }
            assert (await client.post("/api/v1/targets", json=profile)).status_code == 200
            assert (await client.post("/api/v1/targets/fixture/validate")).json()["ready"]
            assert (await client.get("/api/v1/catalog?target_id=fixture")).json()["attacks"]
            payload = {
                "profile_id": "fixture",
                "attack": "fixture",
                "driver": "fixture",
                "submission_id": "single-click",
            }
            response = await client.post("/api/v1/runs", json=payload)
            assert response.status_code == 200, response.text
            run_id = response.json()["id"]
            assert (await client.post("/api/v1/runs", json=payload)).json()["id"] == run_id
            for _ in range(100):
                saved = (await client.get(f"/api/v1/runs/{run_id}")).json()
                if saved["status"] == "completed":
                    break
                await asyncio.sleep(0.03)
            assert saved["status"] == "completed"
            events = (await client.get(f"/api/v1/runs/{run_id}/events")).json()
            assert events["items"][-1]["sequence"] == saved["last_event_sequence"]
            for format in ("html", "markdown", "json", "junit"):
                export = await client.get(f"/api/v1/runs/{run_id}/report?format={format}")
                assert export.status_code == 200
                assert "Synthetic" in export.text or "synthetic" in export.text
            assert (await client.get(f"/api/v1/runs/{run_id}/bundle")).status_code == 200
            child = (await client.post(f"/api/v1/runs/{run_id}/rerun", json={})).json()
            assert child["parent_run_id"] == run_id
            assert (await client.post(f"/api/v1/runs/{child['id']}/cancel")).status_code == 200
            assert (
                await client.get(f"/api/v1/compare?left_id={run_id}&right_id={child['id']}")
            ).status_code == 200
            invalid = {
                **profile,
                "actors": {"attacker": {"cus": "a", "credential_env": "SENSITIVE-invalid-key"}},
            }
            rejected = await client.post("/api/v1/targets", json=invalid)
            assert rejected.status_code == 400
            assert "SENSITIVE" not in rejected.text
            rejected = await client.post(
                "/api/v1/runs", json={**payload, "budget": "SENSITIVE-invalid-key"}
            )
            assert rejected.status_code == 422 and "SENSITIVE" not in rejected.text
            check = await client.post(
                "/api/v1/checks",
                json={
                    "profile_id": "fixture",
                    "driver": "fixture",
                    "submission_id": "all-scenarios",
                },
            )
            assert check.status_code == 200, check.text
            check_id = check.json()["id"]
            assert check.json()["attacks"] == ["fixture"]
            assert len((await client.get(f"/api/v1/checks/{check_id}")).json()["runs"]) == 1
            assert (await client.post(f"/api/v1/checks/{check_id}/cancel")).status_code == 200
            assert (await client.get(f"/api/v1/checks/{check_id}/report")).status_code == 200
            assert (await client.get("/api/v1/overview")).json()["checks"][0]["id"] == check_id
            from diskard.console.contracts import ReadinessReport

            async def unavailable(profile, attacks=None):
                return ReadinessReport(
                    checks=[
                        {
                            "id": "target",
                            "label": "Target",
                            "status": "blocked",
                            "reason": "Unavailable",
                        }
                    ]
                )

            monkeypatch.setattr(runtime.bridge, "validate", unavailable)
            before = runtime.store.list_runs()[1]
            blocked = await client.post(
                "/api/v1/checks",
                json={
                    "profile_id": "fixture",
                    "driver": "fixture",
                    "submission_id": "blocked-check",
                },
            )
            assert blocked.status_code == 409
            assert blocked.json()["detail"]["checks"][0]["status"] == "blocked"
            assert runtime.store.list_runs()[1] == before
            retry = await client.post(
                "/api/v1/checks",
                json={
                    "profile_id": "fixture",
                    "driver": "fixture",
                    "submission_id": "all-scenarios",
                },
            )
            assert retry.status_code == 200 and retry.json()["id"] == check_id
        finally:
            await runtime.stop()


@pytest.mark.asyncio
async def test_static_routes_are_not_api_fallback(tmp_path, monkeypatch):
    from fastapi.staticfiles import StaticFiles

    import ui.server as server

    (tmp_path / "index.html").write_text('<div id="root">console</div>', encoding="utf-8")
    (tmp_path / "assets").mkdir()
    monkeypatch.setattr(server, "FRONTEND_DIST", tmp_path)
    monkeypatch.setattr(server.ctx, "console", None)
    mount = next(r for r in server.app.routes if getattr(r, "name", None) == "assets")
    monkeypatch.setattr(mount, "app", StaticFiles(directory=tmp_path / "assets"))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server.app), base_url="http://localhost"
    ) as client:
        for path in (
            "/",
            "/live",
            "/runs",
            "/runs/new",
            "/runs/id/trace",
            "/targets/id/edit",
            "/reports/id",
            "/compare",
            "/settings",
        ):
            response = await client.get(path)
            assert response.status_code == 200 and 'id="root"' in response.text
        for path in (
            "/api/v1/typo",
            "/assets/missing.js",
            "/runs/id/typo",
            "/missing.js",
            "/unknown",
        ):
            assert (await client.get(path)).status_code == 404
        assert (await client.head("/runs/id/trace")).status_code == 200
