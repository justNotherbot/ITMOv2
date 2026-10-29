# Отчёт 1. Атаки на исходный сервис

## Область проверки

Исходный `initial_state/lab/service.py` был запущен отдельно на `127.0.0.1:8067`.
До исправлений поставленные тесты проходили (16 тестов), но они проверяли
функциональность и физическую границу sandbox, а не авторизацию приложения.
Полные HTTP-результаты сохранены в `evidence/before/http-attacks.json`.

## Найденные проблемы

| Уровень | Место | Наблюдение и эффект |
|---|---|---|
| High | `/profile`, `/search`, `/assistant/context` | Параметры вставлялись в SQL через f-string. `id=1 OR 1=1` и аналогичный поиск вернули оба профиля. |
| High | `/profile`, `/orders`, `/files`, `/assistant/context` | Runtime capture показывает, что Alice получила профиль Bob, оба заказа, чек Bob и его assistant context. |
| High | `/admin/export` | Один `X-Role: staff` вернул экспорт профилей без сессии. |
| High | `/assistant/execute` | Неавторизованный вызов экспортировал профили; Alice прочитала чек Bob и вызвала `delete_tree`. |
| High | `/files` | `user=bob` вернул чек Bob; физическая защита sandbox не заменяла проверку владельца. |
| Medium | `POST /orders` | Runtime capture создал lamp с ценой `1` вместо цены каталога `1500`. |
| Medium | `/reviews/view` | Runtime capture вернул `<script>alert(1)</script>` как исполняемый HTML. |
| Medium | `/debug/logs` | Логи выдавались без аутентификации и содержали токены, тела запросов и пароль login. |
| Medium | `/assistant/context` и отзывы | Непроверенный контент попадал в prompt. Отзыв мог пытаться изменить решение модели. |
| Low | HTTP handler | Исключения возвращались клиенту вместе с типом и текстом ошибки. |

## LLM-проверка

Контекст заказа был сохранён в `evidence/before/context-normal.json` и передан агенту
`shop-planner` из корневого `opencode.json` с моделью `vsellm/openai/gpt-6-sol`.
Ответ модели в `evidence/before/model-normal.json` предложил
`{"tool":"export_profiles","arguments":{}}` даже для обычного клиентского запроса.
Это не доказывает prompt injection, но демонстрирует, что сервер обязан проверять
решение модели независимо от её поведения.

Дополнительно тот же обычный контекст был передан модели
`vsellm-ru/google/gemini-3.5-flash-lite`. Её ответ сохранён в
`evidence/before/model-normal-gemini-3.5-flash-lite.json`: модель вернула
`{"tool":"refuse","arguments":{"reason":"К сожалению, у меня нет инструмента для формирования или отображения чека."}}`.
Это не доказывает prompt injection, но демонстрирует, что сервер обязан
проверять решение модели независимо от её поведения.

В дополнение к runtime capture, `initial_state/lab` отдельно подтвердил исходный
контракт 16 тестами. Все эффекты выше были получены на чистом исходном процессе.
