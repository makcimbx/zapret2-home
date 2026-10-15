# Contributing

Keep runtime changes narrow and preserve fail-closed validation, ownership/cleanup, scope and rollback. Do not replace route/TLS/content proofs with process or HTTP-status checks. Profile tests must not activate whole-LAN strategies automatically.

Run `node --test tests/frontend.test.js` and `python3 tests/build_inputs.test.py` for source changes. Runtime/backend changes also need the complete [local gate](tests/README.md), a built-package check and explicit target verification where applicable. CI's source-only job does not replace those gates.

Never commit runtime ELF files, IPKs, credentials, ubus session IDs, router configuration dumps, actual WAN/VPN addresses or live logs. Use synthetic/documentation addresses for fixtures and keep private results under ignored `dist/`.
