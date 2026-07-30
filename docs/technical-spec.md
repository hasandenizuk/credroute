# credroute Technical Specification

Status: draft for build. Decisions D1-D15 (brainstorm 2026-07-23) are locked and assumed. Working name: credroute.

---

## 1. Overview and non-goals

### 1.1 What credroute is

credroute is a deterministic credential router for AI-agent CLI harnesses (Claude Code, Codex, Gemini/antigravity). Given a context (working directory, platform, optional task tag), it answers one question with exactly one answer:

> For THIS client / project / task / platform: which identity, at which access level, and where is its secret?

Password managers match by host and expect a human to pick from a list. An agent cannot pick. credroute replaces the pick with an ordered rule engine (first match wins) and adds the one guarantee no manager provides: it verifies that the identity actually present in a credential slot is the identity the label claims, and refuses on mismatch (D9).

### 1.2 Route, don't store (the D1 boundary)

- **Routing is the product.** credroute maps context to an identity, an access level, and a *vault handle*: an opaque pointer into the user's own vault. In route-only mode credroute never persists a secret, never caches a secret, and never writes a secret to disk.
- **Optional thin store, off by default.** For users with no vault, `credroute store` provides a minimal age-encrypted per-secret file store. It is an implementation of the same vault backend interface every external vault uses (section 7.3). Enabling it is an explicit config action; nothing in the default path touches it.

### 1.3 Non-goals (v1)

- **No credential or quota rotation.** Explicitly deferred (brainstorm NON-GOAL). The data model reserves room (a handle can point at a new secret without rule changes) but v1 ships zero rotation logic.
- **No daemon, no server, no background process.** Every invocation is a stateless process (D6). This is a hard constraint inherited from the prototype philosophy (Syncthing-safe, identical across machines).
- **No MCP server.** Harness integration is thin adapters over the CLI (D3).
- **No teams/RBAC in v1.** Solo operator first (D2); the schema avoids anything that would preclude teams (identities and rules are files, not a user-bound database).
- **Not a secrets scanner, not a proxy, not a network policy layer.** credroute hands out the right credential; it does not intercept traffic.

---

## 2. Concepts and data model

### 2.1 Vocabulary

| Term | Definition |
|---|---|
| **Identity** | A real account you can log in as, keyed by a stable id (usually an email). Owns credentials. Prototype equivalent: an entry in `accounts` of `auth-profiles.json`. |
| **Platform** | A named service surface: `google`, `github`, `clickup`, `stripe`. One identity may hold credentials on many platforms. |
| **Credential** | One authenticator an identity holds on a platform: type (`oauth`, `api_key`, `bearer_token`, `pat`; all four per D11), an access level, a vault handle, and optionally a slot. |
| **Access level** | `read-only` or `read-write` (extensible enum). Under D7 this is scope-derived: the level selects a *different credential/scope set*, not a label on the same secret. A read-only resolution hands out a token that cannot write. |
| **Rule (route)** | One entry in an ordered list. Conditions (dir glob, platform, task tag) plus an action (identity + access level). First match wins (D5). |
| **Vault handle** | Opaque URI locating a secret in a backend, e.g. `age://google/alex-example-com/gsc-ro.json.age`. The router passes handles around; only the vault backend dereferences them. |
| **Scope profile** | Built-in (or user-supplied) per-platform knowledge: which scopes each access level implies, and how to probe "who is really in this credential" (D10). |
| **Slot** | A location where a live credential materializes for a tool: a gws config dir, a token file, an env var a CLI reads. Slots are where reality diverges from labels (dossier F1: one dir, one login, silent overwrite). |
| **Attestation sidecar** | A JSON file recording the *observed* identity in a slot: who, verified how, when, verdict. Generalizes the prototype's `identity.json`. Records reality, never intent (dossier fix L1). |

### 2.2 Relationships

```
context (cwd, platform, task tag)
   |  rule engine, first match wins
   v
rule --> identity + access level
              |  identity.platforms[platform].credentials[access level]
              v
        credential --> vault handle --> secret (vault backend, on demand)
              |
              +--> slot --> attestation sidecar (verify before hand-off)
```

### 2.3 Config format: YAML, and why

**YAML** (via `gopkg.in/yaml.v3`), not TOML:

1. Rules are an *ordered list of nested objects*. YAML expresses ordered lists of maps naturally; TOML's `[[rule]]` array-of-tables is workable but noisy at this nesting depth, and ordering-as-meaning is less visually obvious.
2. Comments are first-class and essential: a solo operator annotates why a rule exists ("client-b GSC uses the service@ account, not alex@").
3. The neighborhood standard: SOPS, kubectl, GitHub Actions, and most infra tooling the target user already touches are YAML. age itself is format-agnostic.
4. Known YAML risks (indentation errors, implicit typing) are mitigated: `credroute config validate` runs a strict schema check (`KnownFields(true)`, no implicit coercion on our enums), and the wizard generates the file.

Config lives at `~/.config/credroute/config.yaml` (override: `CREDROUTE_CONFIG` or `--config`). Split files are supported via an `include:` list so per-client rule files can live beside client folders if desired. The config directory is designed to be Syncthing-synced (section 9.5).

### 2.4 Full worked example (solo operator, 2 clients, sub-projects, Google RO/RW + GitHub PAT)

```yaml
# ~/.config/credroute/config.yaml
version: 1

defaults:
  # Behavior when cwd is inside a recognized client root but no rule matches.
  # "refuse" = fail closed (exit 2). Outside any client root: also refuse,
  # unless a catch-all rule matches. There is NO silent personal fallback
  # (this closes prototype fault F4).
  on_no_match: refuse
  verify: on              # on | off  (per-rule overridable)
  sidecar_max_age: 24h    # sidecar older than this forces a live probe

# Client roots let rules say "client: acme" instead of repeating globs,
# and define where fail-closed applies.
clients:
  acme:
    roots: ["~/Projects/client.acme/**"]
  bluesky:
    roots: ["~/Projects/client.bluesky/**"]

identities:
  alex@example.com:
    label: "Alex personal"
    platforms:
      google:
        credentials:
          read-only:
            type: oauth
            vault: age://google/alex-example-com/oauth-ro.json.age
            slot: ~/.config/gws/profiles/personal-view
          read-write:
            type: oauth
            vault: age://google/alex-example-com/oauth-rw.json.age
            slot: ~/.config/gws/profiles/personal-default
      github:
        credentials:
          read-write:
            type: pat
            vault: age://github/alex-example-com/pat-repo.age

  alex@acme-corp.com:
    label: "Acme workspace identity"
    platforms:
      google:
        credentials:
          read-only:
            type: oauth
            vault: age://google/alex-acme-corp-com/oauth-ro.json.age
            slot: ~/.config/gws/profiles/acme-view

  reports@acme-corp.com:
    label: "Acme service account for Search Console only"
    platforms:
      google:
        credentials:
          read-only:
            type: oauth
            vault: age://google/reports-acme-corp-com/gsc-ro.json.age
            slot: ~/.config/gws/profiles/acme-gsc

  bot@bluesky.io:
    label: "Bluesky deploy bot"
    platforms:
      github:
        credentials:
          read-write:
            type: pat
            vault: age://github/bot-bluesky-io/pat-deploy.age

rules:
  # Ordered. First match wins. Narrow before broad.

  # Acme: Search Console goes through the dedicated reporting account
  # (mirrors the prototype's client-b.search_console -> service@ split).
  - id: acme-gsc
    match: { client: acme, platform: google, task: gsc }
    use:   { identity: reports@acme-corp.com, access: read-only }

  # Acme: all other Google access is the workspace identity, read-only.
  - id: acme-google-ro
    match: { client: acme, platform: google }
    use:   { identity: alex@acme-corp.com, access: read-only }

  # Bluesky sub-project "webapp" may deploy: bot PAT, read-write.
  - id: bluesky-deploy
    match:
      dir: "~/Projects/client.bluesky/project.webapp/**"
      platform: github
      task: deploy
    use: { identity: bot@bluesky.io, access: read-write }

  # Bluesky anywhere else on GitHub: Alex's own PAT.
  - id: bluesky-github
    match: { client: bluesky, platform: github }
    use:   { identity: alex@example.com, access: read-write }

  # Personal projects (outside any client root): personal Google, read-write.
  - id: personal-google
    match: { dir: "~/Projects/personal/**", platform: google }
    use:   { identity: alex@example.com, access: read-write }

  - id: personal-github
    match: { dir: "~/Projects/personal/**", platform: github }
    use:   { identity: alex@example.com, access: read-write }

vault:
  backend: age
  age:
    store_dir: ~/vault    # existing vault; credroute only reads
    identity_file: ~/.config/credroute/age-identity.txt   # NOT synced (machine-local)

# Optional thin store (D1), commented out by default.
# store:
#   enabled: true
#   dir: ~/.local/share/credroute/store
```

Notes on the example:

- Two clients (`acme`, `bluesky`), each with sub-projects covered by globs; a per-platform split within one client (acme GSC vs acme Google generally); read-only vs read-write as *distinct credentials with distinct vault handles* (D7); OAuth and PAT side by side (D11).
- `slot` is present only for credential types that materialize into tool-visible locations (OAuth config dirs). Raw API keys/PATs handed via env at exec time need no slot; they get fingerprint attestation instead (section 5.3).

---

## 3. Rule engine

### 3.1 Match conditions

A rule's `match` block may contain any of:

| Key | Type | Semantics |
|---|---|---|
| `dir` | glob | Matches the resolution directory (`--dir`, default cwd), after `~` and symlink expansion. `**` crosses separators (doublestar semantics). |
| `client` | string | Sugar for "dir matches any of `clients.<name>.roots`". |
| `platform` | string or list | Exact match against the requested platform. |
| `task` | string or list | Matches the `--task` tag if provided. A rule *with* a `task` condition never matches a request *without* a task tag. |

All present conditions must hold (AND). Omitted condition = wildcard. A rule with an empty `match` is a catch-all and is only legal as the final rule (validator enforces this).

### 3.2 Ordering and precedence

- **Document order is the only precedence.** First match wins, evaluation stops. No specificity scoring, no weights: determinism and explainability beat cleverness. The trade-off (user must order narrow-before-broad) is mitigated by tooling:
- `credroute config validate` warns on **shadowed rules**: a later rule whose match set is provably a subset of an earlier rule's (same platform, glob subsumed, task subset) is dead and reported with both rule ids.
- `credroute explain` (section 3.3) makes any surprising outcome inspectable in one command.

### 3.3 Dry-run / introspection: `credroute explain`

```
credroute explain --platform google --dir ~/Projects/client.acme/project.audit --task gsc
```

Human output (default):

```
context   dir=~/Projects/client.acme/project.audit  platform=google  task=gsc
          client=acme (root ~/Projects/client.acme/**)

  1. acme-gsc          MATCH   client=acme ok, platform=google ok, task=gsc ok
  2. acme-google-ro    (not evaluated - stopped at first match)
  ...

result    identity=reports@acme-corp.com  access=read-only
          vault=age://google/reports-acme-corp-com/gsc-ro.json.age
          slot=~/.config/gws/profiles/acme-gsc  verify=on
```

With `--all`, every rule is evaluated and annotated MATCH or condition-by-condition MISS, so "why did rule 7 not fire" is answerable. With `--json`, the same trace machine-readable (array of `{rule_id, matched, conditions: [{key, expected, actual, pass}]}`). `explain` never touches the vault and never verifies: it is pure routing logic, safe to run anywhere, including in CI over a committed config.

---

## 4. `credroute resolve` - the contract

This is the multi-harness seam (D6). Stateless, one shot, JSON out.

### 4.1 Invocation

```
credroute resolve --platform <name>
                  [--dir <path>]        # default: cwd
                  [--task <tag>]
                  [--access <level>]    # request minimum level; mismatch with rule = error
                  [--verify=on|off]                  # tighten only; cannot loosen config
                  [--json | --quiet]
```

`resolve` returns *metadata only*. It never prints, copies, or writes a secret. Secret hand-off is a separate, deliberate act (section 4.4).

### 4.2 Response schema (stdout; `--json` is the default when stdout is not a TTY)

```json
{
  "version": 1,
  "status": "ok",
  "request": {
    "platform": "google",
    "dir": "/home/h/Projects/client.acme/project.audit",
    "task": "gsc"
  },
  "identity": "reports@acme-corp.com",
  "identity_label": "Acme service account for Search Console only",
  "access_level": "read-only",
  "scopes": [
    "https://www.googleapis.com/auth/webmasters.readonly"
  ],
  "credential_type": "oauth",
  "vault_handle": "age://google/reports-acme-corp-com/gsc-ro.json.age",
  "slot": "/home/h/.config/gws/profiles/acme-gsc",
  "verification": {
    "status": "verified",
    "observed_identity": "reports@acme-corp.com",
    "method": "sidecar",
    "checked_at": "2026-07-23T14:02:11Z",
    "sidecar_age_seconds": 3120
  },
  "matched_rule": { "id": "acme-gsc", "index": 1, "source": "config.yaml" },
  "enforcement": "scope-derived",
  "audit_id": "01J3ZK7Q9GN3"
}
```

On failure, `status` is one of `no_match`, `mismatch`, `vault_error`, `config_error`, and a `detail` object explains (for `mismatch`: expected vs observed identity, method, remediation hint). `scopes` is empty and `enforcement` is `"advisory"` for platforms without a scope profile (D10).

### 4.3 Exit codes

| Code | Meaning | Notes |
|---|---|---|
| 0 | Resolved (and verified, if verification required) | |
| 1 | Usage / flag error | |
| 2 | No rule matched: **fail closed** | Inside a client root this is always terminal; there is no fallback identity, ever (closes prototype F4). |
| 3 | Identity verification mismatch, or unverifiable under `verify: on` | The refuse path of D9. |
| 4 | Vault backend error (missing handle, decrypt failure) | |
| 5 | Config invalid (schema, shadowing hard-errors, unknown identity referenced by a rule) | |

Adapters treat any non-zero as "do not proceed with a credentialed action". The distinction lets them phrase the message (2 = "no route configured, add a rule"; 3 = "wrong identity in slot, re-login needed").

### 4.4 Secret hand-off: `credroute exec` and `credroute handle get`

Two sanctioned paths from handle to secret:

1. **`credroute exec`** (preferred): `credroute exec --platform google --task gsc -- gws gmail search ...` resolves, verifies, decrypts, injects the secret into the child's environment (name per scope profile, e.g. `GOOGLE_OAUTH_TOKEN_JSON`) or materializes the OAuth slot, runs the command, and scrubs. The literal `--` marks where the child command starts. `credroute exec --platform google --check` resolves and verifies without running a child command. The secret never appears in argv, never on stdout, never in the audit log.
2. **`credroute handle get <vault_handle> --to-fd 3`** (plumbing, for adapters that must place a secret themselves): refuses unless the handle maps to exactly one configured credential, then runs the same verification gate and fresh observation as `exec`. A handle claimed by multiple identities is ambiguous and refuses. A handle not modeled in config refuses unless the operator passes `--allow-unmodeled-handle`, which is a break-glass bypass recorded in the audit log. If that audit entry cannot be written, the bypass fails. Writing a secret to stdout requires `--force-reveal` AND a TTY AND an interactive `yes`. This path is designed to be unusable by an agent by accident.

---

## 5. Verify-identity-in-slot (D9, the differentiator)

### 5.1 The problem this kills

The founding bug (dossier W): routing picked the correct slot, but the slot silently held the wrong account. An expired client login had been overwritten by a personal browser login, and nothing checked. Labels described intent; nothing recorded reality (F1-F3, plus the audit finding that the old sidecar recorded *history*, so a stale "correct" label survived a wrong re-login).

### 5.2 The rule: record reality on every path

Every operation that observes or changes what is in a slot (login, probe, handle get, exec) writes the *observed* result to the attestation sidecar before doing anything else with it. Outcomes are recorded as `verified`, `accepted_baseline`, `unconfirmed`, `mismatch`, or `unreadable`. Under `verify: on`, a fresh observation that cannot be recorded is itself a refusal. A stale label therefore cannot survive its first contradiction, and probe failure is never treated as success.

### 5.3 Attestation methods per credential type

| Credential type | Method | Mechanism |
|---|---|---|
| OAuth | **Live probe** | Scope profile defines an identity endpoint (Google: `openidconnect.googleapis.com/v1/userinfo`, field `email`; GitHub OAuth: `/user`, field `login`). Probe with the slot's live token; compare to expected identity. |
| API key | **Fingerprint** (+ optional probe) | `fp = hex(sha256("credroute-fp-v1" || secret))[0:32]`. Sidecar stores the fingerprint of the *vault* secret at attest time; verification recomputes and compares, detecting a swapped or edited key without any network call. If the profile defines a whoami endpoint (e.g. Stripe `/v1/account`), an optional live probe adds identity confirmation. Without a live prober, the first run records `unconfirmed` and exits non-zero under `verify: on`; the operator must run `credroute verify --platform <platform> --force` to accept that exact secret deliberately. |
| Bearer token | **Introspection or fingerprint** | If the profile defines RFC 7662 introspection or a whoami endpoint, probe; otherwise fingerprint-only. Plain fingerprint-only observations are `unconfirmed`; explicit operator acceptance records `accepted_baseline`. |
| PAT | **Live probe** | Platform whoami (GitHub PAT: `GET /user` -> `login`; also captures `X-OAuth-Scopes` to cross-check the access-level claim). |

Generalization of the prototype: the **login guard (L1)** is `credroute login --platform <platform>`, which resolves the intended target before a platform login runs, pins the slot destination, snapshots the slot, marks the slot in-flight, then probes and records the result. The **use guard (L3)** is the `verification` stage inside every `resolve`/`exec` (assert recorded == expected, fail closed in client context). Both write the same sidecar format instead of relying on shell hook labels.

### 5.4 Sidecar format

One full file per slot (or per slotless credential, keyed by handle), stored under `~/.local/state/credroute/attest/`:

```json
{
  "version": 1,
  "slot": "/home/h/.config/gws/profiles/acme-gsc",
  "vault_handle": "age://google/reports-acme-corp-com/gsc-ro.json.age",
  "expected_identity": "reports@acme-corp.com",
  "platform": "google",
  "access_level": "read-only",
  "observed_identity": "reports@acme-corp.com",
  "status": "verified",
  "method": "oauth_probe",
  "fingerprint": "9f2c4a...",
  "observed_scopes": ["https://www.googleapis.com/auth/webmasters.readonly"],
  "checked_at": "2026-07-23T14:02:11Z",
  "checked_by": "credroute/0.3.0 host=workstation-01",
  "hmac": "b64:..."
}
```

- **Integrity**: `hmac` is HMAC-SHA256 over the canonical JSON (minus the hmac field) keyed by a machine-local key at `~/.local/state/credroute/machine.key` (0600, never synced). A hand-edited or foreign-machine sidecar fails HMAC and is treated as `unreadable`, forcing a live probe. This closes the dossier gap "sidecar has no integrity check" and defines the trust model for synced or out-of-wrapper logins: a sidecar minted elsewhere is *evidence to re-verify, never proof*.
- **Binding**: a sidecar only satisfies the credential that matches its vault handle, expected identity, platform, and access level. A record written for identity A, platform A, or access level A is treated like no usable record for identity B, platform B, or access level B.
- **Freshness**: `defaults.sidecar_max_age` (example: 24h) bounds how long a `verified` sidecar substitutes for a live probe. `mismatch` never expires into validity; only a new verified observation clears it.
- **Mismatch behavior**: `resolve`/`exec` exit 3 and refuse. Use `credroute login --platform <platform> --expect <identity>` to re-run a platform login with the slot-write guard enabled.
- **Slot mirror**: when the slot is a directory, credroute writes a reduced `.credroute-attest.json` beside it for tool visibility. The mirror carries status, platform, access level, method, and check time. It omits vault handles, slot paths, expected identities, observed identities, fingerprints, scopes, and HMAC.

---

## 6. Scope profiles (D7 + D10)

### 6.1 Format

Built-in profiles are YAML files embedded in the binary (`go:embed profiles/*.yaml`); a user file at `~/.config/credroute/profiles/<platform>.yaml` overrides or extends. Example, abridged:

```yaml
platform: google
aliases: [gmail, drive, gsc, ga4, gtm]     # sub-platform tags map here; the tag lands in `task`
credential_types: [oauth]
identity_probe:
  method: oauth_userinfo
  endpoint: https://openidconnect.googleapis.com/v1/userinfo
  identity_field: email
access_levels:
  read-only:
    scopes:
      gsc:   [https://www.googleapis.com/auth/webmasters.readonly]
      ga4:   [https://www.googleapis.com/auth/analytics.readonly]
      drive: [https://www.googleapis.com/auth/drive.readonly]
  read-write:
    scopes:
      gsc:   [https://www.googleapis.com/auth/webmasters]
      ga4:   [https://www.googleapis.com/auth/analytics.edit]
      drive: [https://www.googleapis.com/auth/drive]
login:
  helper: "gws auth login --scopes {scopes} --profile-dir {slot}"
exec_env: GOOGLE_OAUTH_TOKEN_JSON
```

```yaml
platform: github
credential_types: [pat, oauth]
identity_probe:
  method: http_whoami
  endpoint: https://api.github.com/user
  auth_header: "Authorization: Bearer {secret}"
  identity_field: login
  scopes_header: X-OAuth-Scopes
access_levels:
  read-only:  { pat_scopes: [repo:status, read:org] }
  read-write: { pat_scopes: [repo, workflow] }
exec_env: GH_TOKEN
```

### 6.2 How access levels derive scopes

For scope-capable platforms, the profile is the single source of the level-to-scopes mapping (the gsc-reauth model generalized): a `read-only` resolution yields the scope list the credential should have been minted with. Scope reporting is informational; identity matching remains the enforcement gate.

### 6.3 Generic passthrough

Unknown platform: resolution works normally (identity, handle, access level as configured), but the JSON reports `"enforcement": "advisory"` and verification is fingerprint-only. Under `verify: on`, the operator must explicitly accept the first fingerprint with `credroute verify --platform <platform> --force`; later fingerprint changes are mismatches. `credroute doctor` lists platforms running advisory so the user knows where a community profile would help.

---

## 7. Vault backend interface (D8)

### 7.1 Go interface

```go
package vault

type Handle string // URI: <backend>://<path>, e.g. age://github/me/pat.age

type Secret struct {
    bytes []byte // unexported; access via WithBytes; Zero() wipes
}
func (s *Secret) WithBytes(f func([]byte) error) error
func (s *Secret) Zero()

type Capabilities struct {
    CanStore bool
    CanList  bool
}

type Backend interface {
    Name() string
    Capabilities() Capabilities

    // Retrieve decrypts/fetches the secret for handle. Caller MUST call
    // secret.Zero() when done; exec paths do this in a defer.
    Retrieve(ctx context.Context, h Handle) (*Secret, error)

    // Exists reports whether the handle resolves, without decrypting
    // where the backend allows (age: file stat).
    Exists(ctx context.Context, h Handle) (bool, error)

    // Fingerprint returns the attestation fingerprint of the secret.
    // Backends may decrypt internally but must not retain plaintext.
    Fingerprint(ctx context.Context, h Handle) (string, error)

    // Store is optional; backends without CanStore return ErrReadOnlyBackend.
    Store(ctx context.Context, h Handle, s *Secret) error
}

// Registered by name; config `vault.backend` selects one.
func Register(name string, factory func(cfg map[string]any) (Backend, error))
```

The interface is deliberately small: SOPS (decrypt file by path) and Bitwarden CLI (`bw get`, mapping handle path to item id) both fit `Retrieve/Exists/Fingerprint` without changes, satisfying "community-addable".

### 7.2 age backend (v1)

- Handle `age://<relpath>` maps to `<vault.age.store_dir>/<relpath>` on disk. The router persists only the path, never the secret. The route-only guarantee holds structurally: no field anywhere in credroute state can hold plaintext.
- Decryption uses `filippo.io/age` as a library (no shell-out) with the identity file from config; passphrase and hardware identities supported via age's stanza mechanism.
- Per-secret files, no index, no lock file: Syncthing-safe by construction, matching the existing vault layout.

### 7.3 Optional thin store (D1)

`store.enabled: true` activates a second registered backend, `store://`, implemented as age-encrypt-on-write into `store.dir` with a recipient list from the user's age identity. `credroute store add <handle-path>` reads the secret from an fd or interactive hidden prompt (never argv), encrypts, writes, records the fingerprint in the attest state, and prints only the resulting handle. It is exactly the age backend plus `CanStore`. No special code path, which keeps the route/store boundary honest.

---

## 8. Harness adapter model (D3, D4)

### 8.1 What an adapter is

An adapter is glue, never logic: at most (a) a way to run `credroute resolve`/`exec` at the right moments, (b) a way to surface refusals in the harness's UX, (c) a snippet of harness config or prompt telling the agent the router exists. All routing, verification, and secret handling stay in the core binary. An adapter that grows logic is a bug.

### 8.2 Claude Code adapter (skill + hook)

- **Skill** (`credroute` skill): teaches the agent the protocol. Before any credentialed action, run `credroute resolve --platform <p> [--task <t>]`; act only on exit 0; run tools through `credroute exec`. Includes the announce-line format (identity + client + access level) mirroring the prototype's announce protocol.
- **PreToolUse hook** (best-effort command-name check): a short hook script pipes Claude Code's PreToolUse JSON into `credroute hook claude-code`, which scans simple shell command tokens by basename, skips URL and remote-spec tokens, infers the platform, and runs the same resolve logic as `credroute resolve`. Single-quoted strings count as literal text (`echo 'gh auth token'` is allowed) except where they sit in a command position (`eval`, `sh`/`bash`/`zsh -c`, and the command argument of `ssh`), where the quoted text is shell input and is recursed into. Exit 2/3 -> hook deny with credroute's `detail.remediation` as the block reason; exit 0 -> allow. The hook fails **closed** inside configured client roots and open elsewhere, inverting the prototype's fail-open default exactly where it mattered most (F4/F6). It is a convenience check, not a security boundary: a renamed copy of `gh`, or `X=/usr/bin/gh; $X auth token`, can defeat name-based detection. The security boundary is that the secret stays in the vault and only credroute hands it over after verifying the identity.
- **SessionStart hook** (optional): `credroute status --dir $PWD --json` one-liner into context so the agent knows the active routes for this project.

### 8.3 Codex adapter

Codex has no PreToolUse hook surface, so the adapter is wrapper-first:

- `AGENTS.md` snippet (installed by `credroute adapter install codex`) instructing: all credentialed commands run as `credroute exec --platform <p> -- <cmd>`; on non-zero exit, stop and report the refusal, never work around it.
- Thin wrapper shims (optional, per platform): `~/.credroute/shims/gws` etc., placed earlier in PATH inside Codex sessions, that delegate to `credroute exec`. Mechanical enforcement where prompt-following is not trusted.

### 8.4 Gemini / antigravity (agy) adapter

Same shape as Codex: a `GEMINI.md` block (agy reads it as default context) with the resolve/exec protocol, plus the same PATH-shim mechanism, plus `credroute status` wired into any session-start surface agy exposes. `credroute adapter install agy` writes the block and shims.

### 8.5 Bypass honesty

A harness can always call the raw platform binary with its own env and skip the router (dossier gap: out-of-wrapper bypass). A renamed binary or variable-expanded binary path can also skip the Claude Code hook's name-based detection. v1 posture: shims and the hook raise the cost, sidecars mean the *next* verified path detects the drift, and the threat model (section 9.4) states plainly that credroute constrains cooperating agents and detects, rather than prevents, determined bypass. Real prevention (e.g. slot dirs unreadable except via exec) is post-v1.

---

## 9. Security model

### 9.1 Never-print-secret

- `resolve`, `explain`, `status`, `doctor`, `verify`, `audit` are structurally secret-free: they operate on handles, fingerprints, and metadata; plaintext never enters those code paths.
- The only plaintext paths are `exec` (env/slot injection into a child) and `handle get` (explicit fd/file, TTY-gated reveal). Both zero buffers on exit (`Secret.Zero()` in defers), pass nothing via argv, and set `0600` on any materialized file.
- Log and error hygiene: a lint-level rule (custom `go vet` analyzer in CI) forbids `Secret` from reaching any `fmt`/log call; error values wrap handle names, never contents.

### 9.2 Memory handling

Secrets live in one `Secret` struct, wiped after use; bytes only, no GC-managed string copies of plaintext; no swap-out mitigation claimed (mlock is best-effort on Linux, not portable enough to promise).

### 9.3 Audit log

Append-only JSONL at `~/.local/state/credroute/audit.jsonl` (machine-local, not synced). `CREDROUTE_STATE_DIR` moves this file along with the rest of credroute's local state; commands print the effective state directory when that override is set. One line per resolve/exec/verify/store operation:

```json
{"ts":"2026-07-23T14:02:11Z","id":"01J3ZK7Q9GN3","op":"resolve","dir":"/home/h/Projects/client.acme/project.audit","platform":"google","task":"gsc","rule":"acme-gsc","identity":"reports@acme-corp.com","access":"read-only","verification":"verified:sidecar","exit":0,"caller":"claude-code-hook"}
```

No secrets, no scope contents beyond names. `credroute audit [--since 24h] [--client acme] [--failures]` queries it. Refusals (exit 2/3) are logged when the log is writable, and write failures are surfaced to stderr. The `handle get --allow-unmodeled-handle` bypass fails if its audit entry cannot be written.

The audit log is a diagnostic record, not tamper-proof evidence against an adversary who can write as the same OS user. The current design does not include chained HMAC audit entries.

### 9.4 Threat model

**Defends against** (the actual founding failures):

1. Wrong identity used for a client/platform because a human or agent picked, guessed, or fell back (routing determinism, no-fallback fail-closed).
2. Right route, wrong reality: a slot silently holding a different account than its label (verify-in-slot, record-reality, HMAC'd sidecars).
3. Over-privileged action: a read-only intent executed with a write-capable credential (scope-derived credentials, scope cross-check on probe).
4. Secret leakage through agent transcripts, shell history, argv, logs (never-print, exec-injection, audit format).
5. Config drift across synced machines producing stale trust (per-machine sidecar HMAC, freshness windows, command conflict checks).

**Explicitly does NOT defend against:**

- A hostile or root-level local process (it can read the age identity file like anything else).
- An agent that deliberately bypasses the wrapper and calls platform APIs with secrets it obtained elsewhere.
- Compromise of the vault passphrase or identity, or of the upstream platform account.
- Malicious scope profiles installed by the user (profiles can name probe endpoints; user-supplied profiles are the user's trust decision; `doctor` flags non-builtin probe hosts).

### 9.5 Config-sync safety

Synced (file-sync safe: per-file, no daemon, no locks): `config.yaml`, rule includes, user profiles. **Never synced** (machine-local, enforced by a `.stignore` the wizard writes and `doctor` checks): `machine.key`, `age-identity.txt`, `audit.jsonl`, attest state. `doctor` detects sync conflict copies such as Syncthing `*.sync-conflict-*` files and Dropbox or OneDrive `conflicted copy` files in the config dir, and `resolve` refuses to run on a config whose canonical file has a newer conflict sibling. Sync problems fail loud, not subtle.

---

## 10. Command surface

| Command | Purpose |
|---|---|
| `credroute init` | First-run wizard: detect existing vault dir, create config skeleton, write .stignore, generate machine key, offer to import identities interactively. |
| `credroute resolve` | The seam (section 4). |
| `credroute exec -- <cmd>` | Resolve + verify + inject + run (section 4.4). `--check` verifies without running a child command. |
| `credroute explain [--all]` | Rule-engine dry-run trace (section 3.3). |
| `credroute login --platform <p> [--expect <identity>] [--force]` | Guard a platform login before it writes: resolve, pin destination, snapshot, run helper, verify, and restore on unsafe outcomes. `--force` records an audited override for missing destination channels and fingerprint baseline acceptance when no live identity prober can name the account. |
| `credroute verify [--slot <s> / --platform <p>]` | Probe and attest the credential currently modeled by config. |
| `credroute status [--dir <d>]` | For this context: matched routes per known platform, verification freshness, one screen. |
| `credroute doctor` | Environment health: config validates, vault reachable, sidecar HMACs, sync conflicts, advisory platforms, adapter installs. Exit non-zero on any red. |
| `credroute config validate` | Strict schema + shadowed-rule + dangling-reference checks. |
| `credroute audit [filters]` | Query the audit log. |
| `credroute handle get` | Plumbing secret retrieval (gated, section 4.4). |
| `credroute store add/ls/rm` | Optional thin store (only when enabled). |
| `credroute profiles ls/show <platform>` | Inspect built-in and user scope profiles. |
| `credroute adapter install <claude-code/codex/agy>` | Write the harness glue (skill + hook, AGENTS.md, GEMINI.md, shims). |
| `credroute version` | Build info. |

Global flags: `--config`, `--json`, `--quiet`, `-v`. All commands are non-interactive except `init` and the TTY-gated reveal.
