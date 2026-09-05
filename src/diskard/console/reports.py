"""Offline report renderers over immutable stored run data."""

from __future__ import annotations

import json
from html import escape
from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring


class ExportTooLarge(RuntimeError):
    pass


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str, sort_keys=True)


def _label(run: dict[str, Any]) -> str:
    summary = run.get("summary") or {}
    return str(summary.get("verdict") or "unknown")


def render_markdown(run: dict[str, Any]) -> str:
    summary = run.get("summary") or {}
    replay = run.get("replay_spec") or {}
    lines = [
        f"# Diskard Console run {run.get('id')}",
        "",
        f"- mode: {run.get('mode')}",
        f"- origin: {run.get('origin')}",
        f"- target profile: {run.get('target_profile_id')} v{run.get('target_profile_version')}",
        f"- execution status: **{run.get('status')}**",
        f"- engine verdict: **{_label(run)}**",
        f"- engine version: {run.get('engine_version')}",
        f"- source/build SHA: {run.get('source_sha') or 'unknown'}",
        f"- scenario version: {run.get('scenario_version')}",
        "",
        str(summary.get("message") or ""),
        "",
        "## Replay",
        "",
        "- availability: **"
        + ("available" if replay.get("complete") else "configuration rerun only")
        + "**",
        "- limitations: "
        + (", ".join(map(str, replay.get("unsupported_reasons") or [])) or "none recorded"),
        "",
        "## Events",
        "",
    ]
    for event in run.get("events") or []:
        data = event.get("data") or {}
        preview = event.get("artifact") or _json(data)
        lines.append(
            f"- {event.get('sequence')} {event.get('type')} "
            f"actor={event.get('actor_id') or '-'} session={event.get('session_id') or '-'}: "
            f"{escape(str(preview))}"
        )
    lines += ["", "## Stored summary", "", "~~~json", _json(summary), "~~~", ""]
    if run.get("error"):
        lines += ["## Error", "", "~~~text", str(run["error"]), "~~~", ""]
    # Indented code remains literal even if target text contains fences/HTML.
    lines += ["## Complete stored record", ""]
    lines += ["    " + line for line in _json(run).splitlines()]
    return "\n".join(lines)


def render_html(run: dict[str, Any]) -> str:
    summary = run.get("summary") or {}
    replay = run.get("replay_spec") or {}
    rows = []
    for event in run.get("events") or []:
        rows.append(
            "<tr>"
            f"<td>{escape(str(event.get('sequence')))}</td>"
            f"<td>{escape(str(event.get('type')))}</td>"
            f"<td>{escape(str(event.get('actor_id') or '-'))}</td>"
            f"<td><pre>{escape(event.get('artifact') or _json(event.get('data') or {}))}</pre></td>"
            "</tr>"
        )
    body = "".join(rows) or '<tr><td colspan="4">No events captured.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Diskard run {escape(str(run.get("id")))}</title>
<style>
body{{font:14px system-ui,sans-serif;max-width:1100px;margin:32px auto;padding:0 20px;
color:#17202a}}
h1{{font-size:24px}} .meta{{display:grid;grid-template-columns:180px 1fr;gap:6px 16px}}
.badge{{font-weight:700}} table{{width:100%;border-collapse:collapse;margin-top:20px}}
th,td{{text-align:left;border:1px solid #d0d7de;padding:8px;vertical-align:top}}
pre{{white-space:pre-wrap;word-break:break-word;margin:0}} .muted{{color:#57606a}}
</style></head><body>
<h1>Diskard Console run <code>{escape(str(run.get("id")))}</code></h1>
<div class="meta">
<div>Execution status</div><div class="badge">{escape(str(run.get("status")))}</div>
<div>Engine verdict</div><div class="badge">{escape(_label(run))}</div>
<div>Target profile</div><div>{escape(str(run.get("target_profile_id")))}
v{escape(str(run.get("target_profile_version")))}</div>
<div>Engine/scenario</div><div>{escape(str(run.get("engine_version")))} /
{escape(str(run.get("scenario_version")))}</div>
<div>Source/build SHA</div><div>{escape(str(run.get("source_sha") or "unknown"))}</div>
<div>Replay</div><div>{
        escape("exact resolved-inputs" if replay.get("complete") else "same configuration only")
    }</div>
</div>
<p>{escape(str(summary.get("message") or ""))}</p>
<h2>Events</h2><table><thead><tr><th>Seq</th><th>Type</th><th>Actor</th>
<th>Stored data</th></tr></thead>
<tbody>{body}</tbody></table>
<h2>Summary</h2><pre>{escape(_json(summary))}</pre>
<h2>Complete stored record, evidence and limitations</h2><pre>{escape(_json(run))}</pre>
</body></html>"""


def render_json(run: dict[str, Any]) -> str:
    return _json(
        {
            "schema_version": 1,
            "manifest": {
                "run_id": run.get("id"),
                "status": run.get("status"),
                "engine_version": run.get("engine_version"),
                "source_sha": run.get("source_sha"),
                "scenario_version": run.get("scenario_version"),
            },
            "run": run,
        }
    )


def render_junit(run: dict[str, Any]) -> str:
    status = str(run.get("status"))
    verdict = _label(run)
    kind = None
    message = ""
    if status in {"failed", "interrupted", "cancelled"}:
        kind, message = "error", str(run.get("error") or status)
    elif verdict in {"vulnerable", "fail", "failed"}:
        kind, message = "failure", f"security verdict: {verdict}"
    elif (
        status != "completed"
        or verdict not in {"clean", "pass"}
        or run.get("mode") == "legacy-import"
    ):
        kind, message = "skipped", "No conclusive completed security check"
    suite = Element(
        "testsuite",
        name="diskard",
        tests="1",
        failures=str(int(kind == "failure")),
        errors=str(int(kind == "error")),
        skipped=str(int(kind == "skipped")),
    )
    case = SubElement(
        suite, "testcase", name=str(run.get("id") or "diskard console run"), classname="diskard"
    )
    if kind:
        SubElement(case, kind, message=message)
    SubElement(case, "system-out").text = _json(run)
    return tostring(suite, encoding="unicode", xml_declaration=True)


def render(run: dict[str, Any], format: str, *, max_bytes: int) -> tuple[str, str]:
    renderers = {
        "html": (render_html, "text/html"),
        "markdown": (render_markdown, "text/markdown"),
        "json": (render_json, "application/json"),
        "junit": (render_junit, "application/xml"),
    }
    if format not in renderers:
        raise ValueError("format must be html, markdown, json or junit")
    content = renderers[format][0](run)
    if len(content.encode("utf-8")) > max_bytes:
        raise ExportTooLarge(
            f"export exceeds DISKARD_EXPORT_MAX_BYTES ({max_bytes}); "
            "request a smaller report or increase the local limit"
        )
    return content, renderers[format][1]
