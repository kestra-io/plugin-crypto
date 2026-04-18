# Kestra Crypto Plugin

## What

- Provides plugin components under `io.kestra.plugin.crypto.openpgp`.
- Includes classes such as `Encrypt`, `Decrypt`.

## Why

- This plugin integrates Kestra with Cryptography.
- It provides tasks that secure files in Kestra pipelines using OpenPGP encryption, decryption, and signature validation.

## How

### Architecture

Single-module plugin. Source packages under `io.kestra.plugin`:

- `crypto`

### Key Plugin Classes

- `io.kestra.plugin.crypto.openpgp.Decrypt`
- `io.kestra.plugin.crypto.openpgp.Encrypt`

### Project Structure

```
plugin-crypto/
├── src/main/java/io/kestra/plugin/crypto/openpgp/
├── src/test/java/io/kestra/plugin/crypto/openpgp/
├── build.gradle
└── README.md
```

## References

- https://kestra.io/docs/plugin-developer-guide
- https://kestra.io/docs/plugin-developer-guide/contribution-guidelines
