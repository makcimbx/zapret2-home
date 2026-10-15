# Проверки

Ни одна команда в разделах «Source», «Backend local» и «Browser» не обращается к роутеру.
Не запускайте все файлы `tests/*.py` подряд: здесь также лежат destructive remote-тесты.

## Source — доступно из обычного clone

```sh
python3 -m compileall -q build.py install.py install_live.py tests
python3 tests/build_inputs.test.py
python3 tests/local_harness.test.py
node --test tests/frontend.test.js
```

Именно этот уровень выполняет GitHub Actions. Нужны Python 3 и Node.js 22+;
это не проверка установленного OpenWrt, nftables или бинарных движков.

## Backend local — отдельные runtime-входы и Linux namespaces

Сначала подготовьте runtime по [BUILD](../docs/BUILD.md) и соберите `python3 build.py`.
Нужны Linux x86_64, busybox/ash, gcc/cc, aarch64-linux-gnu-gcc со static libc,
util-linux (flock/unshare/setpriv), iproute2, nftables и права на user/network
namespaces/NFQUEUE. HTTP3/NFQUEUE-сценарии требуют root в изолированной тестовой среде.
Правила nft создаются только внутри отдельного network namespace.

ucode должен иметь fs-модуль, libubox — настоящий jshn и jshn.sh. Проверенные исходники:

- https://github.com/jow-/ucode commit `c650fa89b771b81e0031e4d88e53b4e7d2a667a4`
- https://github.com/openwrt/libubox commit `da2d205a5cf3e877c45a2eec488218cbaf452e7d`

Их можно собрать CMake в отдельном каталоге; для libubox отключите Lua/examples,
для ucode включите fs. Укажите реальные пути (для build-tree ucode fs.so находится
в каталоге сборки, а не обязательно в подкаталоге modules):

```sh
export UCODE=/path/to/ucode-build/ucode
export UCODE_MODULE_DIR=/path/to/ucode-build
export JSHN=/path/to/libubox-build/jshn
export JSHN_SH=/path/to/libubox-source/sh/jshn.sh
# BUSYBOX по умолчанию ищется в PATH.
export BUSYBOX=/usr/bin/busybox
```

Дополнительные **не распространяемые здесь** входы, обязательные для полного gate:

- `NFQWS2_NATIVE`: x86_64 production nfqws2 v1.0.5.2, с настоящей Lua initialization;
- `NFQWS2_GSO_NATIVE`: x86_64 диагностический GSO-вариант, SHA256
  `622c1782236c2630a1c279f9c6bd0b983aced35db8034dff037a6ac5bc1c0114`;
- `HTTP3_CURL`: x86_64 static-curl 8.23.0 с HTTP3, SHA256
  `45893c2080d3f54d2428853494b9796bdc88c8d959701a7eb48c01c9b10a84e2`;
  upstream archive — `stunnel/static-curl`, `curl-linux-x86_64-musl-8.23.0.tar.xz`;
- `HTTP3_PYTHON`: Python с aioquic и cryptography. Проверены aioquic 1.6.1 и
  cryptography 50.0.2; например, установите их в отдельный venv;
- `LEGACY_IPK`: приватный старый `zapret2-home_0.2.4_aarch64_cortex-a53.ipk`,
  SHA256 `e32eef16eae42ff5673293b25facd0208f5b4ce14cd69bf81dc9f9b53b462db1`.
  Это точный архив для контрпримеров старых hooks, не разрешение миграции.

Без этих входов полный gate **должен завершаться ошибкой**, а не выдавать зелёный skip.
Точные сборки GSO и старый приватный IPK публично не предоставлены;
обычный clone пока не может самостоятельно воспроизвести весь gate.

После экспорта переменных:

```sh
python3 tests/backend_release_local.py
```

Runner замораживает хеши входов, запускает локальные suites и пишет результат
в игнорируемый `dist/backend-release-local/summary.json`. Он использует реальные
ash/ucode/jshn/flock/proc identities, но явно подменяет UCI/procd/сетевые запросы
там, где это отмечено в suite. Ни mock, ни loopback HTTP3 не доказывает работу DPI
или сохранность маршрутов конкретного роутера. `LEGACY_IPK` проверяет известные
опасные свойства старых hooks; безопасная legacy migration остаётся заблокированной.

`fixtures/protocols-status-legacy-router.json` — обезличенная legacy-форма:
документационный WAN, синтетические job_id/тайминги, сохранённые положительные
и отрицательные исходы/типы/порты. Это не публикуемый отчёт реальной сети.

## Browser — Chromium с mock RPC

Установите Node Playwright (проверен 1.64.1) и его Chromium в отдельном каталоге.
Укажите `PLAYWRIGHT_MODULE=/path/to/node_modules/playwright` либо предоставьте
обычный `playwright` в module search path. При необходимости `CHROME_PATH`
указывает на исполняемый Chromium. Скрипт поддерживает кэшированные upstream LuCI assets:
`LUCI_UI_FILE`, `LUCI_CSS_FILE`, `LUCI_MOBILE_CSS_FILE`; без них загружает текущие
файлы openwrt/luci/master (следовательно, это не закреплённый upstream snapshot).

```sh
node tests/frontend.browser.js
```

Снимки пишутся в `dist/protocol-ui-screenshots`. Проверяются layout/interaction
на настоящем Chromium, но RPC — mock: это не authenticated real-LuCI acceptance.

## Remote — не CI и не часть публикации

`*_remote.py`, `http_rpc.py`, `profiles_http.py`,
`browser_reliability.js`, а также корневые `install.py`/`install_live.py`
предназначены для ранее откалиброванной частной установки. Они используют пример
`192.168.1.1`, SSH/ubus/HTTP, могут устанавливать пакет, менять службу, конфигурацию,
тестовые session grants и правила. Не запускайте без чтения исходника, калибровки
[PORTING](../docs/PORTING.md), отдельного разрешения и проверенного восстановления.
Для подготовки этого публичного репозитория они не запускались.
