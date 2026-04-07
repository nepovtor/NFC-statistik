# NFC Statistics App

Аккуратный self-hosted сервис для NFC-меток, редиректов и статистики.

```text
NFC-метка -> /go/{code} -> запись визита -> редирект на нужную ссылку
```

Проект помогает не просто открыть ссылку по NFC, а управлять метками, смотреть аналитику, выдавать доступ клиентам и держать всё под своим контролем.

[Витринная версия проекта](./SHOWCASE.md)

## Что это за проект

Приложение решает простой, но очень практичный сценарий:

1. Ты создаёшь метку, например `menu7`.
2. Привязываешь к ней обычную ссылку.
3. Записываешь в NFC полный адрес вида `https://your-domain.com/go/menu7`.
4. Когда пользователь открывает эту ссылку, сервис:
   - находит нужный URL
   - записывает визит в статистику
   - сразу делает редирект

Это удобно для:

- меню в заведениях
- визиток
- витрин и стендов
- каталогов и прайсов
- Instagram / Telegram / сайт / форму заказа
- клиентов, которым нужно отслеживать свои NFC отдельно

## Ключевые возможности

| Возможность | Что даёт |
| --- | --- |
| NFC-редиректы | Одна стабильная ссылка на метку, которую можно перенаправлять куда угодно |
| Статистика переходов | Учёт сканов и переходов по каждой метке |
| Админка | Управление метками, ссылками, клиентами и журналом визитов |
| Аудит действий | История критичных действий администратора |
| Кабинет клиента | Клиент видит только свои NFC и только свою статистику |
| Редактирование клиентом | Клиент может менять название, ссылку и статус своей метки |
| Экспорт CSV | Выгрузка статистики и audit log с фильтрами по тегу, клиенту и действию |
| Тёмная тема | Интерфейс сразу выглядит современно и удобно |
| Docker и production-режим | Можно запустить локально или вынести на сервер |
| Tailscale-защита админки | Публичный сайт остаётся открытым, админка остаётся приватной |

## Как устроено внутри

| Путь | Назначение |
| --- | --- |
| `main.py` | Точка входа |
| `nfc_app/app.py` | Сборка FastAPI-приложения |
| `nfc_app/settings.py` | Настройки и переменные окружения |
| `nfc_app/database.py` | SQLite, миграции, sync-admin и prune-data |
| `nfc_app/auth.py` | Авторизация, cookie, защита админки |
| `nfc_app/presentation.py` | Общие redirect/CSV/chart helpers для UI |
| `nfc_app/visit_policy.py` | Privacy-policy для визитов и retention-cutoff |
| `nfc_app/repositories/visit_repository.py` | Запись визитов, выборки журналов и CSV-экспорт |
| `nfc_app/repositories/analytics_repository.py` | Dashboard-метрики и аналитические SQL-запросы |
| `nfc_app/repositories/audit_repository.py` | Сохранение и чтение admin audit log |
| `nfc_app/services/admin_audit_service.py` | Прикладная логика аудита и подготовка audit-view |
| `nfc_app/services/` | Прикладная логика: логины, клиенты, метки, визиты |
| `nfc_app/repositories/` | SQL-слой и работа с данными |
| `nfc_app/dashboard_service.py` | Оркестрация данных для дашбордов |
| `nfc_app/routers/` | Админка, кабинет клиента и публичные маршруты |
| `templates/` | Jinja-шаблоны интерфейса |
| `static/` | Стили и статика |
| `scripts/` | Локальные утилиты для Mac |
| `deploy/` | Файлы и скрипты для сервера |
| `tests/` | Базовые тесты |

## Режимы запуска

| Режим | Когда использовать | Результат |
| --- | --- | --- |
| Локально через Python | Быстрая разработка | явный migrate-step и запуск на `127.0.0.1:8001` |
| Локально через Docker | Удобный повседневный запуск | контейнер с SQLite и healthcheck |
| Mac + Tailscale | Приватный стабильный режим без отдельного сервера | сайт внутри tailnet |
| Production с доменом | Публичный доступ для клиентов | HTTPS, reverse proxy, приватная админка |

## Текущий стабильный режим на этом Mac

Сейчас проект уже настроен для стабильной локальной работы через Tailscale.

Рабочие адреса:

- сайт: `https://nepovtor.tail3b401a.ts.net/`
- админка: `https://nepovtor.tail3b401a.ts.net/admin/login`
- кабинет клиента: `https://nepovtor.tail3b401a.ts.net/client/login`

Что уже настроено:

- локальный `docker compose` поднимает приложение на `8001`
- `PUBLIC_BASE_URL` берётся из локального `.env`
- `tailscale serve` публикует сайт внутри tailnet
- `launchd`-агент запускает фоновую проверку сайта каждые 60 секунд
- watchdog умеет поднять `Docker.app`, `Tailscale.app`, контейнер и `tailscale serve`

Важно:

- этот режим работает только внутри твоего Tailscale
- Mac должен быть включён, подключён к сети и не уходить в сон
- для клиентов без Tailscale нужен production-режим на сервере

## Быстрый статус на Mac

Проверить всё одной командой:

```bash
./scripts/mac_status.sh
```

Что используется для стабильной локальной работы:

- `scripts/site_watch.sh`
- `~/Library/Logs/nfc_app_stats-site-watch.log`
- `~/Library/LaunchAgents/com.nepovtor.nfc-site-watch.plist`

Если нужен `tailscale` как обычная команда:

```bash
tailscale version
tailscale status
```

На macOS для `sudo tailscale ...` надёжнее использовать полный путь:

```bash
sudo /Applications/Tailscale.app/Contents/MacOS/Tailscale status
```

## Быстрый старт

### Вариант 1. Локально через Docker

```bash
cp .env.example .env
# сгенерируй реальный ADMIN_PASSWORD_HASH:
# python3 -m nfc_app.auth hash-password "StrongAdminPass123!"
docker compose up -d --build
```

`docker compose` сначала запускает отдельный one-shot migration job, а потом уже поднимает приложение. Само веб-приложение миграции не выполняет.

После первого запуска проверь:

- `http://127.0.0.1:8001/` — корневой маршрут
- `http://127.0.0.1:8001/healthz` — liveness
- `http://127.0.0.1:8001/readyz` — readiness
- `http://127.0.0.1:8001/admin/login` — вход в админку

Остановка:

```bash
docker compose down
```

Локальные значения берутся из `.env`:

```env
SESSION_SECRET=replace-with-a-long-random-secret
ADMIN_LOGIN=admin
ADMIN_PASSWORD_HASH=pbkdf2_sha256$200000$replace_me$replace_me
PUBLIC_BASE_URL=http://localhost:8001
NFC_STATS_DB_PATH=/data/nfc_stats.db
COOKIE_SECURE=0
TRUST_PROXY_HEADERS=0
TRUSTED_PROXY_NETWORKS=127.0.0.1/32,::1/128
SESSION_TOUCH_INTERVAL_MINUTES=5
LOGIN_RATE_LIMIT_ATTEMPTS=5
LOGIN_RATE_LIMIT_WINDOW_MINUTES=15
VISIT_DATA_EXPOSURE=full
VISIT_RETENTION_DAYS=180
```

Хэш пароля администратора можно сгенерировать так:

```bash
python3 -m nfc_app.auth hash-password "StrongAdminPass123!"
```

### Вариант 2. Локально через Python

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
cp .env.example .env
# подставь реальный ADMIN_PASSWORD_HASH в .env
python3 -m nfc_app migrate
python3 -m uvicorn main:app --reload --port 8001
```

Если не нужен `--reload`, можно использовать готовый bootstrap entrypoint:

```bash
python3 -m nfc_app serve
```

Если нужно осознанно обновить логин/хэш администратора из env после миграций:

```bash
python3 -m nfc_app sync-admin
```

Если нужно удалить старые визиты по retention-policy:

```bash
python3 -m nfc_app prune-data
```

### Вариант 3. Windows

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
copy .env.example .env
# подставь реальный ADMIN_PASSWORD_HASH в .env
py -m nfc_app migrate
py -m uvicorn main:app --reload --port 8001
```

Если PowerShell блокирует активацию:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Основные адреса

| Адрес | Назначение |
| --- | --- |
| `/` | Проверка, что сервис работает |
| `/healthz` | Технический liveness endpoint |
| `/readyz` | Технический readiness endpoint |
| `/admin` | Дашборд администратора |
| `/admin/login` | Вход в админку |
| `/admin/clients` | Управление клиентами |
| `/admin/tags` | Управление метками и ссылками |
| `/admin/visits` | Журнал переходов |
| `/admin/audit` | Журнал критичных admin-действий |
| `/admin/audit.csv` | CSV-экспорт audit log |
| `/admin/export.csv` | Экспорт общей статистики |
| `/client/login` | Вход клиента |
| `/client` | Кабинет клиента |
| `/client/tags` | NFC-метки клиента |
| `/client/visits` | Визиты клиента |
| `/client/export.csv` | Экспорт клиентской статистики |
| `/go/{tag_code}` | Публичная NFC-ссылка |

## Как пользоваться

### Как добавить новую метку

1. Открой `/admin/login`.
2. Войди в админку по логину и паролю администратора.
3. Перейди в раздел `Метки и ссылки`.
4. Создай метку:
   - код, например `menu7`
   - название, например `Стол 7`
   - целевую ссылку
5. Сохрани.

После этого рабочая NFC-ссылка будет такой:

`https://your-domain.com/go/menu7`

### Как дать клиенту доступ

1. Открой `/admin/clients`.
2. Создай клиента: имя, логин, пароль.
3. Открой `/admin/tags`.
4. Назначь клиенту нужные метки.
5. Передай клиенту:
   - ссылку `/client/login`
   - логин
   - пароль

После этого клиент сможет:

- видеть только свои метки
- смотреть только свою статистику
- фильтровать визиты по своим тегам
- копировать NFC-ссылку
- менять название, ссылку и статус своей метки
- экспортировать свои данные в CSV

## Как записать NFC через NFC Tools

В NFC нужно записывать полную ссылку, а не просто код.

Правильно:

`https://your-domain.com/go/menu7`

Неправильно:

- `menu7`
- `/go/menu7`
- `http://127.0.0.1:8001/go/menu7` для реальных клиентов

Как записать:

1. Открой `NFC Tools`.
2. Перейди во вкладку `Write`.
3. Нажми `Add a record`.
4. Выбери `URL / URI`.
5. Вставь полную NFC-ссылку.
6. Нажми `Write`.
7. Поднеси телефон к метке.

Где взять ссылку:

1. Открой `/client/tags`.
2. Найди поле `NFC-ссылка`.
3. Нажми `Копировать NFC-ссылку`.

## Production с доменом и HTTPS

Для production-режима используются:

- `compose.production.yaml`
- `.env.production.example`
- `deploy/Caddyfile`

Что делает production-стек:

- Caddy принимает трафик на `80/443`
- автоматически получает HTTPS-сертификат
- проксирует запросы в FastAPI
- приложение строит NFC-ссылки от домена
- админка пускает только `localhost` и Tailscale
- forwarded headers доверяются только от сетей из `TRUSTED_PROXY_NETWORKS`

Запуск:

```bash
cp .env.production.example .env.production
docker compose -f compose.production.yaml --env-file .env.production up -d --build
```

В `.env.production` нужно заполнить:

- `DOMAIN`
- `PUBLIC_BASE_URL`
- `SESSION_SECRET`
- `ADMIN_LOGIN`
- `ADMIN_PASSWORD_HASH`
- `TRUSTED_PROXY_NETWORKS`
- `SESSION_TOUCH_INTERVAL_MINUTES`
- `LOGIN_RATE_LIMIT_ATTEMPTS`
- `LOGIN_RATE_LIMIT_WINDOW_MINUTES`
- `VISIT_DATA_EXPOSURE`
- `VISIT_RETENTION_DAYS`
- `ADMIN_ALLOWED_NETWORKS`

Пароль администратора хранится в БД только в виде хэша. Хэш можно подготовить заранее:

```bash
python3 -m nfc_app.auth hash-password "StrongAdminPass123!"
```

Если после этого нужно явно синхронизировать администратора из окружения:

```bash
python3 -m nfc_app sync-admin
```

Если нужно вручную применить retention-policy к уже накопленным визитам:

```bash
python3 -m nfc_app prune-data
```

## Политика данных визитов

Сейчас в проекте есть явная privacy-policy для аналитики:

- raw-данные визитов хранятся в БД как есть
- UI и CSV-экспорты работают через `VISIT_DATA_EXPOSURE`
- `/admin/visits` и `/admin/export.csv` поддерживают фильтры `tag`, `client_login`, `limit`
- `/client/visits` и `/client/export.csv` поддерживают фильтры `tag`, `limit`
- в режиме `masked` IP маскируется до подсети, `user-agent` скрывается, а `referer` очищается от query string
- старые визиты удаляются по `VISIT_RETENTION_DAYS` через явную команду `python3 -m nfc_app prune-data`
- если `VISIT_RETENTION_DAYS=0`, автоматический cutoff отключён и prune-команда ничего не удалит

## Audit Log

Для административных изменений ведётся отдельный audit log:

- логируются успешные входы и выходы администратора
- логируются создание клиентов, создание меток, назначение владельца, toggle-операции и удаление меток
- записи доступны в `/admin/audit`
- audit log можно фильтровать по `action`, `admin_login`, `limit` и листать по страницам
- audit CSV доступен через `/admin/audit.csv`
- в лог попадают `action`, цель действия, IP, user-agent и компактные details

## Админка только через Tailscale

Production-режим рассчитан на схему:

- публичный сайт доступен по домену
- NFC-ссылки открываются у клиентов как обычные публичные ссылки
- `/admin` закрыт для публичного интернета
- владелец заходит в админку через Tailscale

Если хочешь открыть приватную HTTPS-ссылку внутри tailnet:

```bash
tailscale serve --bg 8001
tailscale serve status
```

## Перенос на сервер

Для переноса подготовлены скрипты:

- `deploy/push_to_server.sh`
- `deploy/install_on_server.sh`

Пример:

```bash
./deploy/push_to_server.sh user@your-server /opt/nfc_app_stats
```

На сервере:

```bash
cd /opt/nfc_app_stats
cp .env.production.example .env.production
nano .env.production
./deploy/install_on_server.sh /opt/nfc_app_stats
```

## Тесты

```bash
python3 -m unittest discover -s tests -v
```

Или в виртуальном окружении:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Что важно перед реальным использованием

- не оставляй плейсхолдеры из `.env.example` и `.env.production.example`
- задай реальный `SESSION_SECRET`
- используй собственный `ADMIN_LOGIN` и `ADMIN_PASSWORD_HASH`
- при необходимости меняй `ADMIN_PASSWORD_HASH` через явный `python3 -m nfc_app sync-admin`
- для HTTPS включай `COOKIE_SECURE=1`
- включай `TRUST_PROXY_HEADERS=1` только за реальным reverse proxy и вместе с корректным `TRUSTED_PROXY_NETWORKS`
- при желании увеличь `SESSION_TOUCH_INTERVAL_MINUTES`, если хочешь ещё меньше write-нагрузку от сессий
- если нужно, настрой `LOGIN_RATE_LIMIT_ATTEMPTS` и `LOGIN_RATE_LIMIT_WINDOW_MINUTES`
- для production разумный дефолт: `VISIT_DATA_EXPOSURE=masked`
- периодически запускай `python3 -m nfc_app prune-data`, если используешь `VISIT_RETENTION_DAYS`
- делай резервную копию `data/nfc_stats.db`
- не используй локальный Tailscale-режим для клиентов без Tailscale
- если сайт остаётся на Mac, отключи сон или не давай Mac засыпать
