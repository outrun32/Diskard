# Repository guidance for coding agents

When a task adds or changes an agent-system connector, target harness, identity
provider, evidence collector, isolation boundary, or target profile, read and
follow:

`.agents/skills/diskard-agent-integration/SKILL.md`

The complete contract and examples are in
`docs/integrating-agent-systems.md`. Target-specific code belongs outside
`src/diskard`; secrets must remain environment or file references; and an
integration is not complete until its restore/verify tests pass on a disposable
environment.

For scenario-only, report-only, or frontend-only work, use the ordinary project
workflow and consult only the relevant documentation.
