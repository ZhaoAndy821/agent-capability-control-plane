# Architecture

## 1. Goal

Build a long-lived personal Agent Capability Registry rather than a folder full of Skills.

The control plane must remain usable when the catalog grows from dozens to hundreds of candidates, without exposing the whole catalog to Codex at once.

## 2. Layers

```text
Private Git repository
  ├─ Registry / conflict groups / trust policy
  ├─ Task modes / project templates
  ├─ Custom control-plane agents
  ├─ Version locks
  └─ Deterministic scripts
             │
             ▼
Local runtime (~/.agent-capability-control-plane)
  ├─ sources/      cloned upstreams, never executed during curation
  ├─ vault/skills  dormant selected Skill snapshots
  ├─ install-manifest.json
  └─ active-state.json
             │
             ▼
Minimal task Active Set
  ~/.agents/skills/<1..5 task skills>
             │
             ▼
Codex project execution
```

The explicit `capability-control-plane` management Skill is installed separately and has implicit invocation disabled.

### Runtime ownership and uninstall boundary

Each runtime is registered only when a validated, previously absent root is
created by an ACCP runtime session. Registration writes an immutable
`.accp-runtime-owner.json` marker in the root and an authoritative receipt at
`<control-plane>/.local/runtime-owners/<sha256(canonical-runtime-path)>.json`.
The receipt binds the root to the checkout, OS principal, canonical path, UUID,
and filesystem identities for the fixed owned components. The receipt store is
administrative state outside the candidate runtime; it is not a configurable
ownership authority.

Runtime commands share strict path and ownership validation. Environment
overrides select a candidate path but cannot authorize an existing directory,
protected root, ancestor overlap, or link/reparse redirection. Repository,
project, home/profile, Active Set, receipt-store, drive/filesystem, system, and
UNC/device roots are protected. Legacy or moved runtimes are rebuilt at a fresh
absent path rather than adopted.

Uninstall never removes the runtime root recursively. After validation and
`--yes` confirmation, it may remove only the fixed `sources`, `vault`,
`install-manifest.json`, and `active-state.json` components whose identities
match the receipt. Unknown
top-level content, the runtime root, marker, and retired receipt are preserved.
`--dry-run` produces the same bounded plan without mutation. Partial failure
leaves a `deleting` receipt for an explicit retry; successful completion marks
the receipt `retired`.

## 3. Why a Registry instead of profiles

Profiles are useful shortcuts but too coarse as the primary abstraction.

The durable abstractions are:

1. **Capability** — what the user needs.
2. **Task mode** — a small predefined combination for a task class.
3. **Project policy** — which modes/capabilities a project allows, includes, or forbids.
4. **Resolver** — computes a deterministic, conservative valid active set.
5. **Conflict policy** — prevents competing behavior/context/runtime stacks.
6. **Trust/dependency policy** — blocks risky or unresolved candidates.

A profile can be added later as a UI preset that expands into task modes.

## 4. Global Control Team vs Project Agents

The global team owns meta-work:

- upstream discovery;
- catalog classification;
- trust/security review;
- conflict/routing policy;
- minimal capability resolution;
- registry integration.

Project agents own actual project work:

- explore project;
- implement bounded change;
- review change.

This avoids every project agent independently rediscovering, installing, or debating global Skills.

## 5. Scripts vs agents

### Scripts own deterministic operations

- clone/fetch upstream source;
- pin commits;
- copy reviewed Skill trees to Vault;
- resolve declared modes/policy mechanically;
- enforce hard conflict rules;
- project active Skills;
- generate index;
- validate JSON.

### Agents own judgment

- "Which of three similarly named repositories is probably the intended upstream?"
- "Is this Skill actually a Skill or a full runtime?"
- "Does this broad router overlap the currently adopted stack?"
- "Should this be explicit-only?"
- "Which minimal capability set best fits this project's intent?"
- "Does an upstream diff materially change behavior or risk?"

Agents do not replace hard safety checks, and scripts do not pretend to perform semantic judgment.

The resolver applies one eligibility gate to seeds, includes, required and
preferred candidates, and the final selection. Exclusions win over includes;
forbidden capabilities and required coverage are hard constraints. A required
capability not already covered must have exactly one eligible provider or resolution refuses, while
optional preferences can only be added when they remain conflict-safe and do
not invalidate the required plan. Returned provider IDs and covered
capabilities are unique and sorted. This is deterministic unique-candidate
selection, not a global-optimal set-cover or backtracking solver.
The project constraint gate delegates operational eligibility to one shared
policy for explicit catalog domains, deployability, literal approval booleans,
evidence and supported dependencies. Known inactive records remain valid catalog
data. Materialize preflights all requested providers before its runtime session
and rechecks records before source work and publication. Activation compares its
actual selection with fresh resolution, including under the existing held locks.
See SECURITY.md for the exact policy, bounded drift checks and binding limits.

## 6. Deployment strategy

Current deployment projects task Skills to USER scope so the control plane does not depend on repo-local discovery.

Project isolation is therefore **policy isolation**, not duplicate installation.

If Windows/Desktop repo-local Skill discovery becomes fully reliable for the user's environment, deployment can later change to repo-local projection without changing the Registry, task modes, or agents.

## 7. Invocation states

Treat every capability as one of:

- `dormant` — stored/indexed, not visible to Codex.
- `explicit` — visible only in a selected task mode and should not trigger implicitly.
- `implicit` — narrow, low-risk, selected for the current task, and allowed to trigger naturally.

Broad suites, behavioral layers, network-heavy research, installers, and control-plane management should default to dormant/explicit.

## 8. Catalog kinds

The registry deliberately contains more than Skills:

- `skill`
- `skill-suite`
- `mcp`
- `cli`
- `tool`
- `application`
- `agent-runtime`
- `orchestrator`
- `infrastructure`
- `reference`
- `quarantine`

This prevents the architecture mistake of forcing every useful GitHub project into `~/.agents/skills`.

## 9. Versioning

Third-party source should normally be represented as:

```text
registry metadata + source URL + pinned commit + optional local override
```

not as copied vendor repositories committed into this control-plane repo.

`sync-vault.ps1 -WriteLock` records reviewed commits into `lock/sources.lock.json`.
A scheduled GitHub Action compares interesting upstream HEADs to locks but does not auto-merge behavior changes.

## 10. Scaling rule

The registry can contain hundreds of candidates.
The Vault can contain dozens of reviewed Skills.
The current Active Set should usually contain **1–5 third-party task Skills**.

The central catalog grows; the Codex routing surface does not.
