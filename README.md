# a2a-card-drift

**Audit Agent Card protocol version drift + snapshot diff for breaking changes. Offline, deterministic, zero dependencies.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)]()

Part of the [a2a-doctor](https://github.com/ZidoCode/a2a-doctor) suite.

A2A 1.0 has been stable since March 2026 — and the public agent web is a version swamp:

- [Agenstry crawl](https://agenstry.com/blog/state-of-the-agent-card): of 1,910 version-declaring cards, **65.5% still declare 0.3**, **41 put an MCP spec revision date** (`2025-06-18`) in `protocolVersion`, 9 declare versions that never existed (`1.1`, `2.0`, `9.2.9`)
- [LiteLLM#30795](https://github.com/BerriAI/litellm/issues/30795): gateway advertises `protocolVersion: "1.0"` in the card but speaks 0.3 on the wire — 1.0 clients fail
- [Apicurio#9455](https://github.com/Apicurio/apicurio-registry/issues/9455): compatibility checkers miss top-level version bumps, dropped interface `protocolVersion`s, and security-scheme definition changes
- [TestMu](https://www.testmuai.com/blog/a2a-protocol-testing/): live public cards missing `supportedInterfaces` entirely (pre-1.0 shape)

## Install

```bash
pip install a2a-card-drift   # or: copy the .py file
```

## Usage

```bash
$ a2a-card-drift check agent-card.json
a2a-card-drift check — agent-card.json
  [CRITICAL] protocolVersion '2025-06-18' is an MCP spec revision date, not an A2A version
  [CRITICAL] card claims protocolVersion 1.0 but uses pre-1.0 shape — 1.0 clients will fail discovery

  verdict: 2 CRITICAL — card drift will break clients at negotiation.
$ a2a-card-drift diff old-card.json new-card.json && echo safe   # CI gate: exit 2 on breaking change
```

## What it catches

**`check` — one card:**

| Finding | Severity |
|---|---|
| `protocolVersion` missing / MCP-date / non-semver / never-existed version | **CRITICAL** |
| 1.0 card using pre-1.0 shape (no `supportedInterfaces[]`) | **CRITICAL** |
| Interface drops `protocolVersion` | **CRITICAL** |
| Card-level vs interface-level version drift (LiteLLM#30795 class) | **CRITICAL** |
| Security scheme type not OpenAPI | warning |

**`diff` — two snapshots (CI gate for card updates):**

| Finding | Severity |
|---|---|
| Top-level `protocolVersion` changed | **CRITICAL** |
| Interface `protocolVersion` changed or dropped | **CRITICAL** |
| Security-scheme definition changed behind the same name | **CRITICAL** |
| Interface removed | warning |
| Capability flipped off | warning |

Exit codes: 0 clean, 1 warnings, 2 critical. Same stream of bytes in, same findings out. MIT license.
