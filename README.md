# dimanic_ip — MTProto IPv4 checker

Проверяет каждый IPv4 из A-записей MTProto-домена через API RU + внешняя нода. Не изменяет DNS.

## Windows (PowerShell)

Установить Python 3.8+ с python.org. Для прямого запуска через `.sh` также установить Git for Windows.

```powershell
py -3 -m pip install -r requirements.txt
.\check-proxy.cmd
```

В Git Bash: `bash check-proxy.sh`. Если скрытый ввод в Git Bash не работает, использовать PowerShell и `.cmd`.

## Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
bash check-proxy.sh
```

В Ubuntu при отсутствии venv: `sudo apt install python3-venv`.
Без dnspython скрипт работает через системный DNS, который может вернуть не все A-записи.

Ввести API-ключ (один раз) и ссылку `tg://proxy?server=proxy.example.com&port=443&secret=...` или `https://t.me/proxy?...`. Ввод скрыт. Один secret и порт должны действовать на всех IP этого домена. Для одиночной проверки можно передать IP в поле server ссылки.

## Управление ключом

- Linux / Git Bash: `bash check-proxy.sh --reset-key --key-only`
- Windows: `.\check-proxy.cmd --reset-key --key-only`
- Проверка сохранённого ключа: `--key-only`.

Перевыпуск ключа выполняется в боте: `/menu` → API-ключ → перевыпустить. Затем заменить его указанной командой. Новый ключ сохраняется только после успешного `/v1/me`.

Хранение: `%LOCALAPPDATA%\dinamic_ip\api_key` (Windows), `~/.config/dinamic_ip/api_key` (Linux). Это локальный текстовый файл, не шифрованное хранилище; на Linux права нового файла 0600. Не передавайте его третьим лицам. Ключ и secret не входят в CSV и не передаются в аргументах командной строки.

## Результаты

Скрипт последовательно проверяет адреса, выдерживая минимум 2.2 секунды между запросами. При 429 повторяет запрос с учётом Retry-After. RKN_BLOCK и DATA_CUT проверяются ещё раз. Только повторный подозрительный результат отмечается REVIEW_DNS. Это кандидат на ручную проверку и удаление A-записи, а не доказательство блокировки на всех операторах РФ. MT_DEAD/DOWN требуют диагностики VPS; ошибки API не считаются блокировками. `--no-recheck` отключает повтор. `--timeout 15` меняет таймаут API. CSV создаётся в текущей папке; `--output report.csv` задаёт путь.

С dnspython опрашиваются авторитетные NS зоны; при расхождениях берётся объединение ответов. При CNAME, сетевых ограничениях и динамических/географических DNS набор может быть неполным; сравнивайте его с панелью Dynadot.

API получает IP, порт и MTProto secret; убедитесь, что доверяете оператору сервиса. HTTP redirects не следуются. Проверка синхронная. API-схема основана на предоставленной документации.
