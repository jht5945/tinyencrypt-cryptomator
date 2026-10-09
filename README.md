# tinyencrypt-cryptomator

> This project is forked from https://github.com/purejava/keepassxc-cryptomator and stores vault passwords with [tinyencrypt](https://github.com/jht5945/tinyencrypt).

[![GitHub Release](https://img.shields.io/github/v/release/jht5945/tinyencrypt-cryptomator)](https://github.com/jht5945/tinyencrypt-cryptomator/releases)
[![License](https://img.shields.io/github/license/jht5945/tinyencrypt-cryptomator.svg)](https://github.com/jht5945/tinyencrypt-cryptomator/blob/main/LICENSE)

Plug-in for Cryptomator to store vault passwords with tinyencrypt encryption.

# Build Project

Requirement:

* JDK 17 or later
* Maven 3.8.4 or later

```shell
mvn package
```

Or use the bundled `buildj` wrapper, which resolves the pinned JDK/Maven for you:

```shell
just build       # or: buildj package
```

Copy the packaged plugin from `target/tinyencrypt-cryptomator-$VERSION.jar` to the Cryptomator plugins directory.

# Prerequisite

The [`tinyencrypt`](https://github.com/jht5945/tinyencrypt) command must be installed and available, and the configured key must already be initialized.

# Configuration

Config file location (first existing file wins):

* `/etc/cryptomator/tinyencrypt_config.json`
* `~/.config/cryptomator/tinyencrypt_config.json`

```json
{
  "keyId": "your-key-id",
  "tinyencryptCommand": "tinyencrypt",
  "encryptKeyBasePath": "~/.config/cryptomator/tinyencrypt_keys/",
  "enablePbkdfEncryptionPassword": false,
  "enableVaultPasswordCache": false
}
```

> `keyId` **required**, the tinyencrypt key ID used to encrypt vault passwords.<br>
> `tinyencryptCommand` optional, path to the tinyencrypt command, default `tinyencrypt`.<br>
> `encryptKeyBasePath` optional, directory where encrypted vault password files are stored, default `$USER_HOME/.config/cryptomator/tinyencrypt_keys/`.<br>
> `enablePbkdfEncryptionPassword` optional, wrap stored values with PBKDF encryption, default `false`.<br>
> `enableVaultPasswordCache` optional, cache decrypted vault passwords in memory (1 hour TTL), default `false`.

# Documentation

For documentation please take a look at the [Wiki](https://github.com/purejava/keepassxc-cryptomator/wiki).

Plugin location:

| OS | Default Dir |
| ---- | ---- |
| Mac | `~/Library/Application Support/Cryptomator/Plugins` |
| Linux | `~/.local/share/Cryptomator/plugins` |
| Windows | `%homepath%\AppData\Roaming\Cryptomator\Plugins` |

# How it works?

Cryptomator calls this plugin to store, load and delete vault passwords. The
plugin encrypts each vault password by invoking `tinyencrypt simple-encrypt`
(with the configured `keyId`) and writes the result to a file named after the
vault under `encryptKeyBasePath`. Loading decrypts that file with
`tinyencrypt simple-decrypt`, optionally caching the result in memory for
performance.

# Copyright

Copyright (C) 2021-2024 Ralph Plawetzki<br>
Copyright (C) 2024-2024 Hatter Jiang

The Cryptomator logo is Copyright (C) of https://cryptomator.org/ <br>
The KeePassXC logo is Copyright (C) of https://keepassxc.org/
