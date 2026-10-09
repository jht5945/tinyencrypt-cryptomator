# AGENTS.md

## Project overview

Cryptomator plugin that stores vault passwords using the external `tinyencrypt`
command. It implements the Cryptomator `KeychainAccessProvider` SPI. Fork of
`purejava/keepassxc-cryptomator`.

## Build & test

Build tooling is configured in `build.json` (JDK 17, Maven 3.8.4). The `buildj`
wrapper resolves the pinned JDK/Maven automatically.

```shell
just build          # buildj package -> target/tinyencrypt-cryptomator-<version>.jar
buildj package      # same, without just
buildj test         # run JUnit 5 tests
mvn package         # if a compatible JDK 17+ / Maven 3.8.4+ is on PATH
```

The `package` phase runs the shade plugin, producing a self-contained plugin JAR.
There is no separate lint/format step.

## Architecture

- `TinyEncryptAccessProvider` (`src/main/java/.../TinyEncryptAccessProvider.java:11`)
  — SPI entry point; loads config in the constructor, reports `isSupported()`
  based on whether `tinyencrypt version` succeeds.
- `Utils` — all config loading, `tinyencrypt` process execution (stdin/stdout
  pumping in daemon threads), encrypt/decrypt, and key-file path mapping.
- `TinyEncryptConfig` — Gson-mapped JSON config (see README).
- `PasswordCache` — in-memory TTL cache for PBKDF passwords and vault passwords.
- `TinyEncryptResult` / `UtilsCommandResult` — CLI JSON/process result holders.
- SPI registration:
  `src/main/resources/META-INF/services/org.cryptomator.integrations.keychain.KeychainAccessProvider`.

Flow: Cryptomator calls `storePassphrase`/`loadPassphrase`/`deletePassphrase`.
A vault maps to one file under the encrypt key base path (vault name is
sanitized/hex-escaped in `Utils.getKeyFile`). `loadPassword` detects being called
from Cryptomator's `isPassphraseStored` via stack inspection and returns early.

## Conventions

- Java 17, package root `me.hatter.integrations.tinyencrypt`.
- Keep the dependency set minimal (Cryptomator integrations API, gson,
  commons-lang3, slf4j).
- Do not add code comments unless they clarify non-obvious behavior.
- Config files are JSON; defaults live in `Utils` as constants.

## Testing notes

Tests are JUnit 5. Most real behavior depends on the external `tinyencrypt`
binary and a valid config, so unit tests currently only cover trivial cases.
When changing process handling, verify manually against a local `tinyencrypt`
install.
