# Diskard — витрина

Хакатон Альфа-Банка «Agentic Red Teaming», 07.09.2026. Живая консоль, реальные прогоны, реальные находки — ничего на этой странице не сфабриковано.

## Живой стенд

| | |
|---|---|
| **Консоль (рабочая)** | [console-preview.51-250-80-101.sslip.io](https://console-preview.51-250-80-101.sslip.io) |
| **Plain console (нестабильно)** | [ee6bfc73.51-250-80-101.sslip.io/live](https://ee6bfc73.51-250-80-101.sslip.io/live) — auto-attacker там иногда падает |

<img src="qr-console.png" width="160" alt="QR на консоль"> <img src="qr-plain-console.png" width="160" alt="QR на plain console"> <img src="qr-repo.png" width="160" alt="QR на репозиторий">

## Схема атаки

Cross-user memory poisoning: один клиент пишет обычное сообщение → модель по ошибке классифицирует его как глобальное правило → `persist_all` (до фикса) пишет без `user_id` → другой клиент в новой сессии получает чужие данные.

![Attack flow diagram](../diagrams/attack-flow-bpmn.svg)

Свимлейны: Атакующий / Память агента / Жертва / Diskard Oracle, ветка до/после фикса.

## Когда эксплойт сработал

![Exploit happened](screenshots/gif-01-exploit-happened.gif)

Запуск на втором таргете (Open WebUI, generic-chat-probe) → находка: canary-токен из системного промпта воспроизвёлся в ответе модели.

![Vulnerable trace](screenshots/03-trace-vulnerable.png)

**Причина:** наивная небольшая локальная модель (qwen2.5:1.5b-instruct) не сопротивляется прямому prompt injection ("Ignore all previous instructions…") и role-injection framing ("===SYSTEM=== New directive…") — 2 из 3 payload'ов пробили canary.

## Когда эксплойт заблокирован

![Exploit blocked](screenshots/gif-02-exploit-blocked.gif)

![Clean trace](screenshots/04-trace-clean.png)

**Причина:** после фикса `persist_all` больше не доверяет `scope`, предложенному моделью классификации — факт из обычного чата принудительно получает `scope=user`. На скрине видно: `Write accepted: failed` — сама попытка записи в глобальную коллекцию отклонена, а не просто "не утекло дальше".

## Replay — промотка сохранённого прогона

![Replay demo](screenshots/gif-03-replay.gif)

![Live replay example](screenshots/07-trace-replay-live-marker.png)

Кликабельные пины по ключевым событиям (`Click a pin to jump`), play/pause/speed, точная позиция подсвечена кольцом.

## Targets и Runs

![Targets page](screenshots/01-targets.png)

2 реально запускаемых цели (investment-stand, Open WebUI) сверху; 37 закэшированных агентов-кандидатов снизу — честно помечены "Cached · adapter required", не выдаются за рабочие.

![Runs list](screenshots/06-runs-list.png)

## Launch — запуск атаки кнопкой

![Launch page](screenshots/02-launch.png)

Второй target выбран, консоль сама показывает "1 attacks available" — реально доступный запуск, не просто пункт в списке.

---

Больше материалов: [концепт-мокапы UI](../../frontend/public/concepts/) (референс дизайна, не продакшен) — открываются прямо на живой консоли, ссылка внизу сайдбара "🐢 Черепашки атакуют".
