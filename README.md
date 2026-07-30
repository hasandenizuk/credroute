# credroute

[![CI](https://github.com/hasandenizuk/credroute/actions/workflows/ci.yml/badge.svg)](https://github.com/hasandenizuk/credroute/actions/workflows/ci.yml)

**A credential router for AI coding agents.** It answers one question, correctly, every time: for *this* client, *this* project, *this* task, on *this* platform, which identity should the agent use, at what access level? Then it checks the identity is really what it claims to be before handing it over.

> Status: pre-release, but installable and working today. `init`, `resolve`, `login`, `verify`, `doctor`, identity/route/store management, and the adapter installers are built and tested (see [Install](#install) below). See [the roadmap](docs/roadmap.md) for what is still ahead.

---

## The problem

If you run more than a couple of clients through an AI agent, you have already hit this. You ask it to pull a doc from Drive, push to a repo, or read analytics, and it quietly uses the wrong account. It usually still "works", which is the worst part, because now the wrong identity did the work and nobody noticed.

Every version of this failure has the same root: the decision about *which* identity to use is made separately from, and never checked against, the account that is actually sitting in the credential slot.

- It logs in as your personal account for a client task, because that login happened to be active.
- A client login expires and gets silently replaced by a personal one. The label still says "client". The reality is not.
- It runs from a folder outside any client and falls back to a default. For someone juggling many clients, there is no safe default.
- You cannot even tell which account is logged in without making a live API call.
- Read-only versus read-write is treated as an afterthought, so a simple read task ends up holding a credential that can delete.

It is survivable at three credentials. At twenty-plus identities across a dozen clients, doing it by hand is not a plan.

## Why your password manager does not fix this

Password managers match by website and then ask a human to pick from a list. There is no human in an agent loop, and the website is not enough: the same site (Google) maps to a different identity depending on which client and task you are on. Server-based secret stores handle storage and policy, but they want a running service and a network call. Agent work on a laptop, synced across machines, wants neither.

None of them make the decision, and none of them check the identity that is actually present before handing it over. That gap is credroute.

## What credroute does

- **Routes by context, not by host.** A small, ordered rule set maps client, folder, task, and platform to one identity and one access level. First match wins, and you can ask it to explain exactly why a rule won.
- **Verifies before it hands over.** It probes the account actually in the slot and refuses if it does not match what the task requires. A stale login can never inherit an old "correct" label. This is the part nothing else does, and the reason the tool exists.
- **Reports scope expectations where the platform has a profile.** The access level maps to the expected scope set so operators can see what should be minted.
- **Fails closed.** No match inside a client context, or any identity mismatch, and it refuses rather than guessing.

## Route, do not store

credroute does not want to be your secret store. Your secrets stay in the vault you already trust. credroute decides which identity and level a task needs, points at the right vault entry, verifies it, and hands over a usable handle. An optional local store exists for people starting from nothing, but it is off by default. You can adopt credroute without moving a single secret into it.

## Works with your agent

The core is a single standalone binary. Each AI harness gets a thin adapter that just calls it. The first release targets **Claude Code**, **Codex**, and **Gemini / antigravity**. Adding another later is a small adapter, not a rewrite.

## Install

credroute is a single static binary plus one runtime dependency: [`age`](https://github.com/FiloSottile/age) must be on PATH, because credroute shells out to it for every vault read and write instead of reimplementing encryption. Tested against age 1.1.1.

**Option 1: `go install`** (needs Go 1.26 or newer):

```
go install github.com/hasandenizuk/credroute/cmd/credroute@latest
```

This installs to `$(go env GOPATH)/bin`. Make sure that directory is on PATH.

**Option 2: download a prebuilt binary** (no Go needed):

Grab the tarball for your platform from the [latest release](https://github.com/hasandenizuk/credroute/releases/latest). Builds cover `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64` (no Windows build yet: one internal package uses a file-lock syscall Windows does not have). Check the sha256 against the release's `checksums.txt`, then:

```
tar -xzf credroute_<version>_<os>_<arch>.tar.gz
sudo mv credroute_<version>_<os>_<arch>/credroute /usr/local/bin/
```

**Option 3: build from source** (to read the code before you trust it):

```
git clone https://github.com/hasandenizuk/credroute.git
cd credroute
go build -o credroute ./cmd/credroute
```

Confirm it works:

```
$ credroute version
credroute 0.1.0-milestone1 (commit unknown, go1.26.3)
```

## Quickstart

This walks through a first identity, a first routing rule, and a first `resolve`, using a placeholder identity and a fake GitHub token. Swap in your own client, identity, and platform once you see the shape of it.

**1. Scaffold a config and a vault directory.**

```
mkdir -p ~/vault
credroute init --yes --vault-dir ~/vault
```

This writes `~/.config/credroute/config.yaml` with an empty rule set and prepares credroute's own machine key. It does not touch your secrets or generate an age key for you: that is step 2.

**2. Generate an age key, if you do not already have one.**

```
age-keygen -o ~/.config/credroute/age-identity.txt
```

Note the "Public key: age1..." line it prints; you need it for step 4.

**3. Add an identity and point it at a vault entry.**

```
credroute identity add alex@example.com --label "Alex personal"
credroute identity edit alex@example.com \
  --add-credential "github:read-only:pat:age://github/alex/token.age"
```

Credential types are `oauth`, `api_key`, `bearer_token`, `pat`. The `vault-handle` here (`age://github/alex/token.age`) is a path relative to the vault dir you gave `init`, resolved by credroute's own age backend, not a URL it fetches.

**4. Encrypt the actual secret to that path.**

credroute does not write your secrets for you when you route to an existing vault entry (that is the point: route, do not store). Encrypt it yourself with age, to your own public key from step 2:

```
mkdir -p ~/vault/github/alex
echo -n "ghp_your_real_token" | age -r age1yourpublickeyfromstep2 -o ~/vault/github/alex/token.age
```

**5. Add a routing rule.**

```
credroute route add github-default --platform github --identity alex@example.com --access read-only
```

`--client` and `--dir` are also available to scope a rule to one client folder; a bare `--platform` match is enough to get started. Note that there is currently no `credroute client add` command: client-scoped rules (`--client acme`) require an `acme:` entry to already exist under `clients:` in `config.yaml`, which you add by hand.

**6. Ask credroute for the credential.**

```
$ credroute resolve --platform github
{
  "status": "mismatch",
  ...
  "verification": { "status": "unverified", "identity_confirmed": false },
  "detail": "verification status \"unverified\" under verify=on; refusing (run `credroute verify --platform github` to re-attest)"
}
$ echo $?
3
```

This refusal is the point of the tool, not a bug in the quickstart: the default `verify: on` mode means credroute will not hand over a credential until it has actually probed the account sitting in that slot and confirmed it matches. To clear it for real, run:

```
credroute verify --platform github
```

This performs a live check against the actual platform (it needs network access and a real token) and records the result. Once it reports `"status": "verified"`, `resolve` returns `"status": "ok"`.

For a platform that has no live identity prober yet, `verify` reports `"status": "unconfirmed"` and exits non-zero under the default `verify: on` mode. To use that platform anyway, the operator must deliberately accept the exact current secret as the baseline:

```
credroute verify --platform stripe --force
```

That records `"status": "accepted_baseline"`. Later changes to the secret fingerprint refuse as a mismatch.

To try the rest of this walkthrough offline, without a live token, turn verification off for just this one rule instead of the whole config:

```
$ credroute route assign github-default --verify off
$ credroute resolve --platform github
{
  "status": "ok",
  "identity": "alex@example.com",
  "access_level": "read-only",
  "verification": { "status": "unverified", "identity_confirmed": false },
  ...
}
```

`off` skips the identity check. Set it back to `on` (`credroute route assign github-default --verify on`) once you have run a real `credroute verify`.

**7. Check the environment.**

```
$ credroute doctor
[OK  ] config parses                ~/.config/credroute/config.yaml
[OK  ] config validates             0 warning(s)
[OK  ] vault backend supported      age
[OK  ] vault store_dir exists       ~/vault
[OK  ] age identity_file readable   ~/.config/credroute/age-identity.txt
[OK  ] age binary on PATH           /usr/bin/age
[OK  ] attestation sidecars         none recorded yet
[OK  ] sync-conflict files          none found
```

**8. Wire it into your agent harness.**

```
credroute adapter install claude-code
```

This writes a skill (`~/.claude/skills/credroute/SKILL.md`) and a PreToolUse hook (`~/.claude/hooks/credroute-resolve-hook.sh`) that call credroute automatically. The hook is a best-effort convenience check, not a security boundary: renamed binaries and variable-expanded paths can avoid name-based detection. The security boundary is that secrets stay in the vault and credroute hands them over only after verifying the identity. `credroute adapter install codex` and `credroute adapter install agy` do the same for those harnesses. Add `--dry-run` first if you want to see the file list before anything is written, and `--dir <path>` to install somewhere other than the harness's usual location.

From here: `credroute explain --platform github --all` traces which rule matched and why (or why each one missed), and `credroute --help` lists every command and every global flag (`--config`, `--json`, `--quiet`, `-v`).

Use a literal `--` before the child command with `credroute exec`, for example `credroute exec --platform github -- gh api user`. `credroute exec --platform github --check` resolves and verifies without running a child command.

`CREDROUTE_STATE_DIR` moves the local state directory. That also moves `audit.jsonl`, so `resolve`, `exec`, and `handle get` print the effective state directory when this override is set.

The audit log is a diagnostic record. It is useful for seeing what credroute allowed or refused, including break-glass use. It is not tamper-proof evidence against someone who has the same OS user account.

## Documentation

- [Technical specification](docs/technical-spec.md): the full architecture, data model, config format, resolve contract, verification mechanism, vault interface, command surface, and threat model.
- [Build roadmap](docs/roadmap.md): the phased plan, what ships in v1, and the known risks.

## Contributing

Before you push, install the guard that keeps private data out of this repository:

```bash
scripts/scan-private-data.sh --install-hook
```

It refuses any push containing a key, a token, a home directory, or a path into someone's own files, unless that exact string is listed in [`scripts/private-data-baseline.txt`](scripts/private-data-baseline.txt). CI runs the same check on every pull request and every release tag. The check exists because v0.1.0 of this project published a personal filesystem path, and a published version cannot be recalled: module proxies keep their copy permanently.

Your own identifiers, such as a username or an employer's name, should never be written into this repository, not even into the scanner. Put them in a file outside it and point `CREDROUTE_PRIVACY_PATTERNS` at it. Without that file the check only recognises paths that start with a tilde or a home directory.

Some of those patterns will match something legitimate: a project published under a personal account carries that account name in every import path. Rather than weakening the pattern, list the accepted lines in a second private file at `CREDROUTE_PRIVACY_ALLOW`. Keep each entry narrow, because each one is a hole.

It is a guardrail, not a cage. A secret split across two lines is invisible to it, and anyone can pass `--no-verify`. It raises the floor.


## Author

Built by [Hasan Deniz](https://hasandeniz.com). Part of the [micro-tools](https://github.com/hasandenizuk) collection - small, focused utilities for web development and SEO.

- Website: [hasandeniz.com](https://hasandeniz.com)
- GitHub: [github.com/hasandenizuk](https://github.com/hasandenizuk)
- LinkedIn: [linkedin.com/in/hasandeniz](https://www.linkedin.com/in/hasandeniz/)

## License

[MIT](LICENSE). Copyright (c) 2026 Hasan Deniz.
