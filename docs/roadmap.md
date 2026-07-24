# credroute Build Roadmap

Companion to `technical-spec.md`. Phases are vertical slices: each one ships something runnable and testable on its own, and each ends with a "done when" gate that a stranger could verify. Effort: S = about a day, M = 2-4 days, L = about a week of focused work.

---

## 1. Phasing

The suggested P0-P6 spine from the brief is kept, with one adjustment, justified here: **`exec` (secret hand-off) moves into P1 alongside the vault interface** rather than arriving with adapters in P5. Reason: the never-print-secret guarantee is architectural. If the plumbing for "secret goes from vault to child process without touching stdout" is not built and tested while the vault layer is being built, later phases will grow ad-hoc secret paths that are hard to remove. Everything else follows the suggested spine.

### P0 - Scaffold, config schema, static resolve (M)

**Goal:** a compiled `credroute` binary that loads the YAML config, runs the rule engine, and answers `resolve` and `explain` with metadata only. No vault, no verification, no network.

**Deliverables:**
- Go module scaffold (`cmd/credroute`, `internal/config`, `internal/rules`, `internal/output`), cobra or stdlib flag dispatch, cross-compile targets (linux/amd64, linux/arm64, darwin/arm64, windows/amd64) in CI from day one.
- Config loader with strict schema (`KnownFields`), `include:` support, `~` expansion.
- Rule engine: dir glob (doublestar), client sugar, platform, task; first-match-wins; fail-closed exit 2 on no match.
- `credroute resolve` (JSON contract from spec section 4.2, with `verification.status: "off"`), `credroute explain [--all] [--json]`, `credroute config validate` including shadowed-rule detection, `credroute version`.
- Golden-file test suite: a fixtures directory of (config, context, expected JSON) triples covering every match key, ordering traps, and the fail-closed cases.

**Dependencies:** none.

**Done when:** the worked example config from the spec resolves all six rules correctly under `go test`, `explain --all` output matches golden files, and an unmatched request inside a client root exits 2 with `status: no_match`.

### P1 - Vault interface, age backend, secret hand-off (M)

**Goal:** handles dereference to real secrets, safely.

**Deliverables:**
- `vault.Backend` interface + registry exactly as spec section 7.1; `Secret` type with `WithBytes`/`Zero`.
- age backend that shells out to the `age` binary, reading an existing per-file vault layout. Shipped this way to hold the one-dependency policy; the library remains an option if shelling out becomes a constraint.
- `credroute exec -- <cmd>`: resolve, retrieve, env-inject (`exec_env` placeholder until P3 profiles; interim: per-credential `env:` config key), run, zero, propagate exit code.
- `credroute handle get` with `--to-fd` / `--to-file` and the TTY-gated `--reveal-unsafe`.
- Optional thin store (`store://` backend, `store add/ls/rm`) behind `store.enabled` - it is the age backend plus `CanStore`, so the marginal cost is small and doing it now proves the interface has two implementations.
- The never-print `go vet` analyzer (Secret must not reach fmt/log) wired into CI.

**Dependencies:** P0.

**Done when:** `credroute exec --platform github -- gh api user` works against a real age-encrypted PAT; grepping a full `-v` transcript of every command finds zero secret bytes; the analyzer fails a deliberately bad build; store round-trips a secret with the vault interface only.

### P2 - Verify-identity-in-slot + sidecar (L)

**Goal:** the differentiator. Reality is recorded on every path; mismatch refuses.

**Deliverables:**
- Attestation store under `~/.local/state/credroute/attest/` with the sidecar JSON format, HMAC over canonical JSON, machine key generation.
- Fingerprint attestation (works for all four credential types with zero network) as the universal baseline.
- Probe framework: `oauth_userinfo` and `http_whoami` methods with a pluggable transport (hardcoded Google + GitHub endpoints for now; profile-driven in P3).
- Verification stage inside `resolve`/`exec` (the use guard): sidecar-fresh -> accept; stale/absent/HMAC-fail -> live probe; probe mismatch -> record + exit 3; probe unreachable under `required` -> record `unreadable` + exit 3.
- `credroute verify [--after-login]` (the login guard) and remediation hints on refusal.
- Freshness window (`sidecar_max_age`), the "mismatch never expires into validity" rule.

**Dependencies:** P1 (probes need live tokens via the vault; fingerprints need `Fingerprint`).

**Done when:** the founding bug is mechanically reproduced and caught: log a wrong account into a test slot, `resolve` exits 3 with expected-vs-observed in `detail`, the sidecar records the mismatch, and no sequence of restarts/re-runs makes the stale label come back without a fresh verified probe. Hand-editing a sidecar causes HMAC failure and a forced probe.

### P3 - Scope profiles + scope-derived access levels (M)

**Goal:** access levels mean scopes, not labels.

**Deliverables:**
- Embedded profile format (`go:embed`), user-override loading, `profiles ls/show`.
- Built-in profiles: Google (gsc/ga4/drive/gmail/gtm sub-scopes, userinfo probe, login helper template), GitHub (PAT scopes, whoami probe, scopes header). Stretch: Stripe, generic-bearer.
- Scope derivation in resolve output; observed-scope cross-check in the probe path; `scope_mismatch` refusal.
- Generic passthrough: unknown platforms resolve with `enforcement: advisory`, fingerprint-only verification.
- `exec_env` moves from per-credential config into profiles.

**Dependencies:** P2 (cross-check rides the probe framework). Can start profile file format in parallel with P2.

**Done when:** a Google credential minted read-only resolves with exactly the `.readonly` scope set; a deliberately over-scoped token is refused with `scope_mismatch`; an unknown platform (`clickup`) resolves advisory without error; the gsc-reauth flow from the prototype is reproducible via profile + `verify --fix-hint`.

### P4 - Rule engine hardening + introspection polish (S)

**Goal:** the rule engine is trustable by a stranger. (Most engine work landed in P0; this phase is the trust tooling that D5 flagged as mandatory.)

**Deliverables:**
- `explain --all` condition-by-condition MISS annotation, JSON trace schema frozen.
- Shadowed-rule analysis upgraded from warning to structured report (`config validate --strict` errors).
- `credroute status` (per-context route table + verification freshness, one screen).
- Property-based tests: random configs + contexts asserting determinism (same input, same output) and single-match semantics.

**Dependencies:** P0 (engine), P2 (status shows verification state).

**Done when:** for any fixture config, every resolve outcome is explainable by `explain --all` output alone, and the property suite runs green under `go test -count=100`.

### P5 - Harness adapters: Claude Code, Codex, agy (M)

**Goal:** two-plus harnesses drive the same core (D4, D12).

**Deliverables:**
- `credroute adapter install <name>` scaffolding.
- Claude Code: skill file + PreToolUse Bash hook (deny on exit 2/3, announce line, fail-closed inside client roots) + optional SessionStart status.
- Codex: AGENTS.md snippet + PATH shim mechanism.
- agy: GEMINI.md snippet + same shims.
- Adapter conformance doc: what an adapter may and may not do (spec 8.1), so community adapters stay thin.

**Dependencies:** P2 minimum (a blocking adapter without verification would ship the old fault F3: declared expectations no code reads). P3 desirable for platform inference.

**Done when:** on a real machine, a Claude Code session inside a client folder is blocked from a wrong-identity Google call with a readable refusal; a Codex session runs a credentialed command through the shim; the same config file drives both with zero per-harness config drift.

### P6 - Safety net, docs, dogfood, release (L)

**Goal:** v1 public release per the D12 bar.

**Deliverables:**
- `credroute doctor` (all checks from spec section 10), `credroute audit` query command, audit JSONL writer wired into every operation (the writer itself lands earlier, in P1, and grows fields per phase; the query UX lands here).
- `credroute init` wizard: vault detection, config skeleton, machine key, `.stignore`, adapter offer.
- Sync-safety enforcement: conflict-copy detection, refuse-on-newer-conflict.
- Docs: README (what/why/quickstart), install guide (binary + `go install`), example config (the spec's worked example), adapter guides, threat model page, CONTRIBUTING + profile-contribution guide, MIT LICENSE.
- Dogfood conversion: the maintainer's real multi-client setup (4+ Google identities, the client-b GSC split, GitHub PATs, ClickUp advisory) expressed as a credroute config; run both machines on it for at least a week; every refusal triaged as bug-or-correct.
- GoReleaser: tagged release with signed checksums for the four platforms.

**Dependencies:** all prior phases.

**Done when:** the D12 checklist (section 3 below) is fully green.

---

## 2. Critical path and parallelization

```
P0 ──▶ P1 ──▶ P2 ──▶ P5 ──▶ P6
              │       ▲
              └▶ P3 ──┘
P4 (starts after P0, finishes any time before P6)
```

- **Critical path: P0 -> P1 -> P2 -> P5 -> P6.** The differentiator (P2) gates adapters (P5), because an adapter that routes without verifying re-creates fault F3 and would be embarrassing to demo.
- **P3 parallelizes with late P2** (profile format and scope tables need no probe code); its probe-integration tail merges after P2.
- **P4 parallelizes with anything** after P0; it is polish plus tests.
- **Docs and the audit-log writer accrete continuously**; P6 is assembly and dogfood, not a docs-from-scratch crunch.
- Rough total: 5-7 focused weeks solo; dogfood week is wall-clock, not effort.

---

## 3. v1 release checklist (mapped to D12)

| D12 bar | Concrete check |
|---|---|
| Dogfoods on a real multi-client setup | The maintainer's full identity spread runs through credroute on WSL + VPS for 7+ days; zero unrouted credential uses in the audit log; the client-b-GSC-split resolves correctly; at least one real mismatch refusal observed or injected and handled. |
| Runs on >= 2 harnesses | Claude Code adapter blocking live; Codex or agy adapter running `exec` live; both from one shared config. |
| age vault | All dogfood secrets served from the existing age store via the `age://` backend; thin store exercised by at least one test user flow. |
| Install guide / README / example config | Quickstart takes a fresh machine from download to first verified resolve in under 15 minutes (timed test with someone who is not the author); example config in repo matches the spec's worked example; `doctor` green on a fresh install. |
| Safety fold-ins | Never-print analyzer in CI; `doctor` + `status` shipped; audit log on every resolve; `.stignore` + conflict detection shipped; `init` wizard shipped. |

---

## 4. Post-v1 / future

- **Agent-native command layer (NEXT milestone).** Two halves that ship together.
  1. *Imperative commands* so users and agents never hand-write YAML: `identity add` / `identity edit`, `route add` / `route assign` / `route ls`, and the deferred `store add` / `store ls` / `store remove`. Every write validates the result (runs the `config validate` checks) before saving, preserves comments where possible, and handles secrets only through the vault backend. Additive over the resolver; no data-model change.
  2. *Self-description / discovery* so an LLM learns the interface at runtime instead of guessing. A `credroute describe [--json] [<command>]` emits a machine-readable manifest of every command: purpose, parameters (name, type, required, allowed values, description), examples, and exit-code semantics. Intended flow: the agent asks the tool what commands exist and how to call them, then invokes the right one with the right parameters. The binary is the single source of truth for its own interface, so harness adapters and skills are generated from `describe` output and can never drift from the actual commands. This is what makes the imperative layer usable by an agent, not just a human.
- **Rotation** (the explicit v1 non-goal): key rotation and quota-aware rotation across a pool of identities; the handle indirection was designed so rotation changes vault contents, never rules.
- **Teams:** shared config repos, per-person age recipients, identity ownership metadata; the file-based model was chosen so this is additive.
- **More vaults:** SOPS and Bitwarden backends as the first community-contribution targets; the 5-method interface is the contract.
- **More harnesses:** Kimi (deferred by D4), plus whatever ships next; the adapter conformance doc is the on-ramp.
- **Community scope profiles:** a `profiles/` contribution pipeline with a required probe test; `doctor` already surfaces advisory platforms as demand signal.
- **Hard bypass prevention:** slot materialization only inside `exec` with locked-down permissions; active purge-on-mismatch (dossier B2).
- **Signed sidecars across machines:** per-machine keys today mean cross-machine sidecars force a re-probe; a future shared-keyring mode could let trusted machines accept each other's attestations.

---

## 5. Top 5 risks and mitigations

| # | Risk | Why it is real | Mitigation |
|---|---|---|---|
| R1 | **Probe fragility.** Identity endpoints change, rate-limit, or are unreachable offline; `verify: required` then blocks legitimate work and users disable verification globally, killing the differentiator. | The dossier's own audit found probe-failure fail-open precisely because probes are annoying. | Sidecar freshness window makes probes rare (once per 24h per slot, not per call); fingerprint fallback keeps *some* attestation when the network is down, honestly labeled; refusals always print a one-line fix; per-rule `verify: advisory` gives a targeted relief valve so the global setting never has to move. |
| R2 | **Rule-engine mistrust.** One surprising first-match outcome and users stop believing the router, hand-editing around it. | D5 chose expressiveness over a flat map; ordering bugs are the cost. | `explain --all` from day one (P0, not a later polish); shadowed-rule detection in `validate`; golden-file + property tests; docs teach narrow-before-broad with the worked example. |
| R3 | **Adapter bypass makes guarantees look hollow.** An agent calls `gws` directly and the router never sees it; a public reviewer demonstrates this on day two. | Dossier names out-of-wrapper bypass as an open gap; Codex/agy have no hook surface. | Threat model states detection-not-prevention plainly (no over-claiming to puncture); PATH shims raise the bypass cost mechanically; Claude Code hook gives one harness real interception; sidecar drift detection catches bypass after the fact; hard prevention is a named post-v1 item. |
| R4 | **Secret leakage through a side path.** One debug print, one error message wrapping plaintext, one argv, and the never-print guarantee is publicly false. | Highest reputational stake for a credential tool; easiest class of bug to write. | Structural containment: one `Secret` type, unexported bytes, two sanctioned exit paths only; custom vet analyzer in CI from P1; transcript-grep gate in the P1 done-when; TTY + confirm gate on reveal. |
| R5 | **Scope-profile maintenance burden.** Google scope strings and probe endpoints drift; a wrong builtin profile silently mints over- or under-scoped credentials. | Scope tables are facts about third parties, and third parties change. | Ship few profiles, deep (Google + GitHub) rather than many, shallow; profiles are data files, user-overridable without a release; probe cross-check catches scope drift at verify time (the system self-reports when a profile is stale); `doctor` flags advisory/unknown so gaps are visible, not silent. |

---

## 6. Working agreements for the build

- Every phase lands with its tests and its docs fragment; P6 assembles, it does not backfill.
- The audit-log writer exists from P1 so every later feature logs from birth.
- No phase may add a third secret-bearing code path; if one seems needed, the design is wrong.
- The spec is the contract; deviations get a one-line note in a DECISIONS.md at repo root.
