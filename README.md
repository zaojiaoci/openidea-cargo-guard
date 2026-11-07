# Cargo Guard

OpenIDEA plugin that flags crates.io dependencies in `Cargo.toml` that are behind
the latest stable release or have been yanked.

It is read-only: no `cargo` process runs, no lockfile is rewritten.

- Declared dependencies come from the edited `Cargo.toml`, including
  `[build-dependencies]`, target-specific tables, renames (`package = …`) and
  `workspace = true` entries resolved from the workspace root manifest.
- Locked versions come from the workspace's `Cargo.lock`; a dependency that the
  lockfile cannot satisfy is reported as unresolved instead of guessed.
- Freshness and yanked status come from the crates.io sparse index
  (`index.crates.io`), one request per crate, cached for 24 hours (setting
  `refreshHours`).
- Diagnostics sit on the line that declares the dependency; nothing is edited.
  `check-deps` re-runs on demand, `clear-cache` drops cached index answers.
- Dev-dependencies are skipped unless the `includeDev` setting is on.

```sh
cargo test                       # logic, against the SDK's mock host
openidea-plugin build            # → dist/plugin.wasm, validated like an install
openidea-plugin link             # load this folder in the IDE (Settings › Plugins)
```

Known limits: manifests above the opened project root are invisible, so inherited
dependencies are skipped when the workspace root lies outside the project; a
missing or stale `Cargo.lock` means no locked version to check. The first check
in a large workspace performs one index request per new direct dependency; later
checks hit the cache. If the index is unreachable, the last cached answer is used
rather than publishing nothing.

## License

MIT — see [LICENSE](LICENSE).

