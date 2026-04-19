# Kestra Crypto Plugin

## What

- Provides plugin components under `io.kestra.plugin.crypto.openpgp`.
- Includes classes such as `Encrypt`, `Decrypt`.

## Why

- What user problem does this solve? Teams need to secure files in Kestra pipelines using OpenPGP encryption, decryption, and signature validation from orchestrated workflows instead of relying on manual console work, ad hoc scripts, or disconnected schedulers.
- Why would a team adopt this plugin in a workflow? It keeps Cryptography steps in the same Kestra flow as upstream preparation, approvals, retries, notifications, and downstream systems.
- What operational/business outcome does it enable? It reduces manual handoffs and fragmented tooling while improving reliability, traceability, and delivery speed for processes that depend on Cryptography.

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
