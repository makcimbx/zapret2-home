# Сборка

## Граница публикации

Git содержит исходники и метаданные, но **не** `nfqws2`, `nfqws2-quic`, `curl-http3`, собранный `stun-probe`, IPK, логи или generated-манифест `SHA256SUMS`. Чистый clone без внешних runtime-файлов намеренно завершает `build.py` с сообщением об отсутствующем файле, а не скачивает неподтверждённый executable.

## Зависимости

Linux, Python 3, Node.js, shell, `aarch64-linux-gnu-gcc` со статической libc. Например, на Debian/Ubuntu: `python3 nodejs gcc-aarch64-linux-gnu libc6-dev-arm64-cross` (набор/названия пакетов зависят от дистрибутива). Требования тестов описаны в [tests/README.md](../tests/README.md).

## Runtime

Положите в `files/usr/lib/zapret2-home/` три **локально подготовленных** файла с точными хешами из [`runtime-pins.json`](../runtime-pins.json):

- `nfqws2`: исходный AArch64-движок zapret2 v1.0.5.2, commit `6b6c63e3385fa73f8af3be4a69171e947f5a319d`. [Upstream release](https://github.com/bol-van/zapret2/releases/tag/v1.0.5.2).
- `nfqws2-quic`: отдельная локальная статическая сборка того же commit с включением `NFQA_CFG_F_GSO`. Патч: `files/usr/share/licenses/zapret2-home/quic-diagnostics/nfqa-gso.patch`; зависимости/хеши исходников: `files/usr/share/zapret2-home/quic-diagnostic-engine.json`. **Публичной загрузки точного локального ELF сейчас нет; сборка всех компонентов из одного clone ещё не автоматизирована.** Другой toolchain может дать другой ELF; не удаляйте pin ради прохождения проверки.
- `curl-http3`: [static-curl 8.23.0 AArch64 musl archive](https://github.com/stunnel/static-curl/releases/download/8.23.0/curl-linux-aarch64-musl-8.23.0.tar.xz). Хеш архива и исходники сборки — `files/usr/share/zapret2-home/http3-client.json`; проверьте архив и извлечённый ELF независимо.

Lua и маленькие fake-пакеты хранятся в Git с исходными уведомлениями. Собственный STUN-клиент компилируется из `src/stun-probe.c`. Сборщик проверяет runtime-пины, версии RPC/пакета и синтаксис shell/JS/JSON, нормализует режимы файлов и создаёт tar-based IPK с явными каталогами.

```sh
python3 build.py
python3 tests/package_protocols.test.py
```

Результаты: `dist/zapret2-home_0.4.5_aarch64_cortex-a53.ipk`, `package.sha256`, `files-manifest.json`, `file-modes.json`. `TMPDIR` управляет временным каталогом средствами Python. Повторная сборка с теми же runtime-файлами и toolchain проверяется на одинаковый SHA-256.

## Не распространять пакет автоматически

У curl и отдельного QUIC-движка ещё не подтверждён полный комплект corresponding-source/relinking-материалов статических GPL/LGPL-зависимостей. Наличие лицензий рядом с ELF само по себе не закрывает эти требования. Этот репозиторий не публикует бинарные релизы и не заявляет полностью воспроизводимую сборку сторонних ELF. См. [THIRD_PARTY.md](../THIRD_PARTY.md).
