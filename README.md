# credroute

**A credential router for AI coding agents.** It answers one question deterministically: for *this* client, *this* project, *this* task, on *this* platform, which identity should the agent use, at what access level, and where is its secret kept?

> Status: pre-release. The design is complete and documented; the Go implementation has not started. This repo currently holds the specification, the phased build roadmap, and this README. See [Roadmap](#roadmap).

---

## The one-sentence version

Password managers match by website and then ask a human to pick from a list. AI agents cannot pick. They need a single, correct answer, and today they usually guess wrong. credroute is the missing layer that gives them the correct answer, and refuses when it is not sure.

---

## The problem this solves

If you run more than a couple of clients through an AI coding agent, you have hit this. You ask the agent to pull a document from Google Drive, or push to a repo, or read Search Console, and it silently uses the wrong identity. Some of the concrete failures that motivated credroute:

- **Silent wrong-account use.** The agent used a personal Google login for a client task because that login happened to be the active one. Nothing warned anyone. The task "succeeded" against the wrong account.
- **Right slot, wrong identity.** A client login expired and got quietly overwritten by a personal login during a browser auth flow. Nothing checked that the account in the slot still matched the account the work required. The label said "client"; the reality was "personal".
- **No default that is correct.** When the agent runs from a folder outside any client (a temp dir, a fresh sandbox, a reset working directory), it falls back to the default identity. For a multi-client operator, there is no safe default. The only safe behavior is to refuse.
- **Identity is invisible.** The common auth tools do not print *which account* is logged in without a live API call. A wrong login is undetectable by inspection.
- **Config that does nothing.** It is easy to write a registry file that says "this client expects this account", and never have a single line of code actually read it and enforce it. Documentation posing as configuration.
- **Access level is an afterthought.** Read-only versus read-write is a first-class safety property, but almost nothing treats it as a routing input. An agent doing a read task should not be holding a write-capable credential.
- **It does not scale.** All of this is survivable at three credentials. At twenty-plus identities across a dozen clients and their sub-projects, it is unmanageable by hand.

The root cause is the same every time: **the routing decision (which identity, which level) is separate from, and unchecked against, the reality of what is actually in the credential slot.**

## Why existing tools do not cover it

- **Password managers (Bitwarden, 1Password, etc.)** route by host and present a list for a human to choose from. There is no human in an agent loop, and host is not enough context. The same host (Google) maps to many identities depending on which client and task you are on.
- **Server-based secret stores (Vault, OpenBao, Infisical)** solve storage and access policy, but they assume a daemon and a network round-trip. Agent workflows on a laptop, synced across machines, want no daemon.
- **OS keychains** store secrets. They do not decide *which* secret is correct for the current context.

None of these make the context-to-identity decision, and none of them verify the identity that is actually present before handing it over. That gap is credroute.

## Core philosophy: route, do not store

credroute's default posture is to **manage and route, not to store secrets.** Your secrets stay in the vault you already trust. credroute decides which identity and access level a task requires, points at the right vault entry, verifies the identity is genuinely what it claims to be, and hands the agent a usable handle. It never needs to become your secret store.

An optional thin local store (age-backed) exists for people who have no vault yet, but it is off by default. The trust ask stays low: you can adopt credroute without moving a single secret into it.

## How it works

Four ideas:

1. **Identities and platforms.** An identity is an account (an email, a token owner). Each identity holds credentials per platform (Google, GitHub, ...), and each credential carries an access level (read-only or read-write) and a vault handle pointing at the secret.
2. **Rules.** An ordered, first-match-wins rule set maps context (client, folder, platform, task) to an identity plus access level. Rules are plain, diffable, and explainable. A dry-run command shows exactly which rule won and why.
3. **Resolve.** A harness asks `credroute resolve --platform google` from the working directory. credroute walks the rules, picks the identity and level, and returns a small JSON object: the identity, the access level, the vault handle, the matched rule, and a verification status. If nothing matches inside a client context, it refuses (fail closed). There is no silent fallback.
4. **Verify the slot.** Before handing anything over, credroute checks that the identity actually present in the slot matches the identity the rule requires. It probes the credential (an OAuth account check, an API-key fingerprint, a token introspection) and records the real result every time, so a stale "correct" label can never survive a wrong re-login. On mismatch, it refuses. This is the piece no password manager does, and the reason credroute exists.

### The resolve flow

```
agent (any harness)
  -> credroute resolve --platform google    # cwd is implicit
     -> match rules (first win)  -> identity + access level
     -> verify identity in slot  -> ok | mismatch(refuse)
     -> map access level to scopes (read-only cannot write)
  <- JSON: { identity, access_level, vault_handle, matched_rule, verification_status }
```

### Access levels are enforced, not just reported

Read-only versus read-write is not advisory. The access level maps to the actual scopes or token handed out. A read-only resolution yields a credential that physically cannot write. For platforms credroute ships a scope profile for (Google, GitHub, and a growing set), this is exact. For platforms it does not yet know, it falls back to reporting the level without shaping scopes, so nothing breaks.

### Example configuration

A solo operator with two clients and some personal projects. Rules are ordered, narrow before broad:

```yaml
# ~/.config/credroute/config.yaml
version: 1

defaults:
  on_no_match: refuse       # inside a client root with no rule match: fail closed
  verify: required          # required | advisory | off (per-rule overridable)
  sidecar_max_age: 24h      # older attestation forces a live probe

clients:
  acme:
    roots: ["~/Projects/client.acme/**"]

identities:
  alex@example.com:
    label: "Alex personal"
    platforms:
      google:
        credentials:
          read-only:  { type: oauth, vault: "age://google/alex-example-com/oauth-ro.json.age" }
          read-write: { type: oauth, vault: "age://google/alex-example-com/oauth-rw.json.age" }
      github:
        credentials:
          read-write: { type: pat, vault: "age://github/alex-example-com/pat-repo.age" }
  reports@acme-corp.com:
    label: "Acme service account for Search Console only"
    platforms:
      google:
        credentials:
          read-only: { type: oauth, vault: "age://google/reports-acme-corp-com/gsc-ro.json.age" }

rules:
  # Acme Search Console goes through the dedicated reporting account.
  - id: acme-gsc
    match: { client: acme, platform: google, task: gsc }
    use:   { identity: reports@acme-corp.com, access: read-only }
  # Personal projects: personal Google, read-write.
  - id: personal-google
    match: { dir: "~/Projects/personal/**", platform: google }
    use:   { identity: alex@example.com, access: read-write }

vault:
  backend: age
  age:
    store_dir: ~/secrets                              # your existing vault; credroute only reads
    identity_file: ~/.config/credroute/age-identity.txt   # machine-local, never synced
```

The full worked example (more identities, the deploy-bot case, the complete schema) is in [docs/technical-spec.md](docs/technical-spec.md).

## Command surface

| Command | Purpose |
|---|---|
| `credroute init` | First-run wizard: detect an existing vault, create a config skeleton, generate a machine key, import identities interactively. |
| `credroute resolve` | The core query. Returns identity, access level, and vault handle as JSON for the current context. |
| `credroute exec -- <cmd>` | Resolve, verify, inject the credential into the environment, and run a command. |
| `credroute explain [--all]` | Dry-run trace of the rule engine: which rule matched and why. |
| `credroute verify [--slot / --platform] [--after-login]` | Probe and attest the identity in a slot now. Run it after any login. |
| `credroute status [--dir]` | One screen: matched routes per platform for this context, plus verification freshness. |
| `credroute doctor` | Health check: config validity, vault reachability, attestation integrity, sync conflicts, adapter installs. Non-zero exit on any problem. |
| `credroute config validate` | Strict schema, shadowed-rule, and dangling-reference checks. |
| `credroute audit [filters]` | Query the audit log of past resolutions. |
| `credroute handle get` | Low-level secret retrieval (gated). |
| `credroute store add/ls/rm` | The optional thin local store (only when enabled). |
| `credroute profiles ls/show <platform>` | Inspect built-in and user scope profiles. |
| `credroute adapter install <claude-code\|codex\|agy>` | Write the harness glue (skill and hook, or shims). |
| `credroute version` | Build info. |

Global flags: `--config`, `--json`, `--quiet`, `-v`. Everything is non-interactive except `init` and the terminal-gated secret reveal.

## Works with your harness

credroute's core is a single standalone binary. Each AI harness gets a thin adapter that just calls `credroute resolve`. The v1 release ships adapters for:

- **Claude Code** (a skill plus a pre-tool hook)
- **Codex** (agent instructions plus PATH shims)
- **Gemini / antigravity (agy)** (agent instructions plus shims)

Adding another harness later (for example Kimi) is a small adapter, not a rewrite. The engine never depends on any one harness.

## Security model

- **Secrets are never printed.** A single secret type flows through the code with exactly two sanctioned exit paths (inject into a child process environment, or a terminal-gated reveal). A build-time check guards against any other path.
- **Fail closed.** Inside a client context with no matching rule, or on an identity mismatch, credroute refuses. It never guesses.
- **Attestation cannot go stale.** The identity check records reality on every path (verified, mismatch, unreadable), so a wrong login cannot inherit an old "correct" label. The attestation sidecar is integrity-checked.
- **Audit trail.** Every resolution is logged (context, chosen identity, level, verification result), never the secret.
- **No daemon, sync-safe.** Config and state are plain files that survive being synced across machines. Machine-local keys are kept out of sync.

What credroute does **not** claim to defend against in v1: a determined agent calling the underlying binary directly to bypass a harness adapter. v1 treats this as detectable, not prevented, and documents it honestly. Hard prevention is post-v1.

## Roadmap

The build is planned as seven vertical slices, each independently testable:

| Phase | Goal |
|---|---|
| P0 | Project scaffold, config schema, `resolve` on a static config |
| P1 | Vault interface, age backend, real secret hand-off via `exec` (never-print baked in) |
| P2 | Verify-identity-in-slot and the attestation sidecar (the differentiator) |
| P3 | Scope-derived access levels and built-in platform profiles |
| P4 | The rule engine and `explain` dry-run tooling |
| P5 | Harness adapters (Claude Code, Codex, agy) |
| P6 | Safety, `doctor`, audit, first-run wizard, docs, and dogfooding to v1 |

Full detail, dependencies, effort estimates, per-phase "done when" tests, and risks are in [docs/roadmap.md](docs/roadmap.md).

### Non-goals for v1

- Credential or quota **rotation** (planned for later).
- **Team** features (shared seats, per-user permissions). The data model leaves room for them; v1 targets the solo operator.
- Being your **secret store**. Optional and off by default, on purpose.

## Documentation

- [Technical specification](docs/technical-spec.md): architecture, data model, the resolve contract, verification mechanism, vault interface, scope profiles, adapter model, threat model, full command surface.
- [Build roadmap](docs/roadmap.md): the phased plan, critical path, release checklist, and risks.

## License

[MIT](LICENSE).
