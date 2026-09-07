# Diskard — витрина

Хакатон Альфа-Банка «Agentic Red Teaming», 07.09.2026. Живая консоль, реальные прогоны, реальные находки.

## Живой стенд

| | |
|---|---|
| **Консоль (рабочая)** | [console-preview.51-250-80-101.sslip.io](https://console-preview.51-250-80-101.sslip.io) |
| **Plain console** | [ee6bfc73.51-250-80-101.sslip.io/live](https://ee6bfc73.51-250-80-101.sslip.io/live) |
| **Репозиторий** | [github.com/outrun32/Diskard](https://github.com/outrun32/Diskard) |

<img src="qr-console.png" width="150" alt="QR на консоль"> <img src="qr-plain-console.png" width="150" alt="QR на plain console"> <img src="qr-repo.png" width="150" alt="QR на репозиторий">

## Targets — рабочие цели и кэш кандидатов

![Targets page](screenshots/01-targets.png)

2 реально запускаемых цели (investment-stand, Open WebUI) сверху; 37 закэшированных агентов-кандидатов внизу — честно помечены "Cached · adapter required".

## Когда эксплойт сработал

![Vulnerable trace](screenshots/03-trace-vulnerable.png)

Canary-токен из системного промпта воспроизвёлся в ответе модели — реальный, живой prompt-injection finding.

## Когда эксплойт заблокирован

![Clean trace](screenshots/04-trace-clean.png)

После фикса `persist_all` факт из обычного чата принудительно получает `scope=user`. `Write accepted: failed` — сама попытка записи в глобальную коллекцию отклонена.
