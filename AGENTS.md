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
├── src/test/resources/
│   ├── sanity-checks/          # happy-path flows, also run as live QA smoke tests
│   └── flows/invalids/         # flows asserted to FAIL
├── build.gradle
└── README.md
```

### Test Flow Fixtures

Both directories hold `@ExecuteFlow` fixtures for `RunnerTest`; pick by the
execution state the test asserts.

- `src/test/resources/sanity-checks/` — flows expected to end `SUCCESS`. A
  GitHub Action auto-syncs this directory into
  [`kestra-io/sanity-checks`](https://github.com/kestra-io/sanity-checks), where
  the flows are run against release candidates as QA smoke tests. **Never put a
  flow that fails by design here**: it would turn the org-wide sanity-check
  suite red. Assert values inside such a flow with a `condition:`-guarded
  `io.kestra.plugin.core.execution.Fail` task, the way the other plugin repos do.
- `src/test/resources/flows/invalids/` — flows expected to end `FAILED`, used to
  prove an error path is actually enforced. Not synced anywhere. Assert the
  failed task's id as well as the execution state, so a flow broken for an
  unrelated reason (bad YAML, render error, missing key) cannot pass as a
  working guard.

The `flows/<intent>/` nesting mirrors Kestra core, which groups its own runner
fixtures the same way under `core/src/test/resources/flows/`.

## References

- https://kestra.io/docs/plugin-developer-guide
- https://kestra.io/docs/plugin-developer-guide/contribution-guidelines
