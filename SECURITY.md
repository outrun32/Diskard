# Security policy

Diskard executes adversarial scenarios against AI applications. Use it only on systems you own or have explicit permission to test.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, sensitive evidence or a working exploit against a deployed system. Use GitHub private vulnerability reporting for this repository.

Include the affected version, a minimal reproduction, expected impact and any suggested containment steps. Remove real customer data and secrets from the report.

## Test data

Use synthetic identities and sandboxed tools by default. Persistent-memory tests must restore their baseline state even when execution fails.
