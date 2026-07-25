# Changelog

## [2026-07-25]
- added: `scripts/scan-private-data.sh`, a check that refuses to publish personal paths or secret material. It runs as a pre-push hook, as a CI job, and as a gate before any release tag is cut. Install it with `scripts/scan-private-data.sh --install-hook`; see the Contributing section of the README.
- added: `scripts/private-data-baseline.txt`, the list of placeholder paths this repository is allowed to contain. Anything not on it blocks the push.
## [2026-07-24]
- added: Built credroute milestone 1: config/rules/vault Go packages + CLI (resolve/explain/exec/config validate/doctor/version), example config, full test suite (go build/vet/test all green, age live round-trip test included)
- added: Fable 5 review v2 of agent-native command layer milestone (commits 077db25..5f9c002): read all new files, empirical tests with real age in sandbox. Found 0 blockers, 2 HIGH (init ignores CREDROUTE_CONFIG split-brain; stale verified sidecar transfers to re-pointed vault handle), 3 MED, 7 LOW
- fixed: applied all Fable 5 review v2 findings (H1/H2, M1-M3, L1-L7): init honors CREDROUTE_CONFIG and rejects a --config/positional conflict; a re-pointed vault handle under the same slot no longer reads as verified, and UpsertCredential invalidates the stale sidecar; config edits now flock across open-to-save so concurrent editors serialize instead of losing an update; identity/route/store mutations append an audit entry; the thin store fsyncs before rename; store paths reject `#`/`?`/`%`, ids reject control characters, `store ls`/`remove` skip temp residue and refuse to delete non-regular files, an explicit `route add --index` past a trailing catch-all is clamped, and a describe/main.go dispatch-parity test closes the remaining manifest-drift gap
- added: tag-triggered release workflow (.github/workflows/release.yml) that cross-compiles static binaries for linux/amd64, linux/arm64, darwin/amd64, and darwin/arm64, packages each as a tar.gz with a sha256 checksums file, and publishes them to a GitHub release via `gh release create`; windows/amd64 is left out because internal/config/editor.go's file locking uses syscall.Flock, which does not exist there
- added: v0.1.0, the first tagged release — a stranger can now download a working binary from the GitHub releases page instead of needing a Go toolchain
- fixed: `init`'s default vault directory was hardcoded to a machine-specific path, and that value leaked into --help text, the describe manifest, examples/config.yaml, and the spec; replaced with a generic default
- added: v0.1.1, superseding v0.1.0 to ship the fix above; v0.1.0 remains published but should not be recommended for new installs
- changed: the release workflow now runs vet, the gofmt gate and the test suite before it builds anything, because pushing a tag does not trigger CI and a release could otherwise be cut from an untested commit
- fixed: `credroute version` falls back to the module build info, so a `go install` build reports its real version and commit instead of a stale hardcoded default
- removed: v0.1.0 is retracted in go.mod; `go list -m -versions` and `go get` now flag it as one to avoid
- added: concurrency groups and per-job timeouts on both workflows
- fixed: the roadmap said the age backend used a Go library; it shells out to the `age` binary, which is what the one-dependency policy requires
- added: v0.1.2, carrying the retraction and the release-gate fixes above
