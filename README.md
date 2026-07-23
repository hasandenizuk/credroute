# credroute

**A credential router for AI coding agents.** It answers one question, correctly, every time: for *this* client, *this* project, *this* task, on *this* platform, which identity should the agent use, at what access level? Then it checks the identity is really what it claims to be before handing it over.

> Status: pre-release. The design is complete and documented. The Go build is in progress. See [the roadmap](docs/roadmap.md).

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
- **Treats read-only as real.** The access level maps to the actual scopes handed out, so a read task cannot get a write-capable credential.
- **Fails closed.** No match inside a client context, or any identity mismatch, and it refuses rather than guessing.

## Route, do not store

credroute does not want to be your secret store. Your secrets stay in the vault you already trust. credroute decides which identity and level a task needs, points at the right vault entry, verifies it, and hands over a usable handle. An optional local store exists for people starting from nothing, but it is off by default. You can adopt credroute without moving a single secret into it.

## Works with your agent

The core is a single standalone binary. Each AI harness gets a thin adapter that just calls it. The first release targets **Claude Code**, **Codex**, and **Gemini / antigravity**. Adding another later is a small adapter, not a rewrite.

## Documentation

- [Technical specification](docs/technical-spec.md): the full architecture, data model, config format, resolve contract, verification mechanism, vault interface, command surface, and threat model.
- [Build roadmap](docs/roadmap.md): the phased plan, what ships in v1, and the known risks.

## License

[MIT](LICENSE). Copyright (c) 2026 Hasan Deniz.
