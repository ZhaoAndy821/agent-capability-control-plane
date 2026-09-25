# Agent Capability Control Plane V2

A Git-backed control plane for Codex Skills, custom agents, external tools, and project capability policy.

## Core idea

- **GitHub repo** = source of truth: registry, policies, task modes, locks, custom agents, docs.
- **Local runtime** = third-party source cache + dormant Skill Vault.
- **Runtime ownership** = a newly registered runtime root with an immutable
  `.accp-runtime-owner.json` marker and an authoritative receipt in the
  checkout-local `.local/runtime-owners` store.
- **Active set** = only the smallest task-specific set projected into `~/.agents/skills`.
- **Global Control Team** = decides what capabilities should exist and how they should be governed.
- **Project Agents** = execute the project; they do not curate the global capability stack.
- **Scripts** = deterministic state/sync/resolve/deploy.
- **Agents** = research, judgment, architecture, risk review, semantic selection.

## First run

```powershell
.\scripts\bootstrap.ps1
```

Then resolve a task mode. This platform ships with an **empty registry**, so no
mode exists until you add one; substitute a mode from your own
`modes/operational-modes.json`. `examples/minimal-instance/` shows the shape.

```powershell
.\scripts\resolve.ps1 -Mode <your-mode>
```

Fetch only the required upstream Skills and activate them:

```powershell
.\scripts\activate.ps1 -Mode <your-mode> -FetchMissing
```

Uninstall is bounded to registered runtimes. It requires a valid ownership
receipt and `--yes`; `--dry-run` validates and prints the plan without changing
anything. Only the fixed `sources`, `vault`, `install-manifest.json`, and
`active-state.json` runtime components are eligible for removal. The runtime root, ownership metadata,
unknown top-level content, project Active Sets, and personal agents are
preserved. Existing or legacy directories are never adopted; rebuild them at a
fresh path through the normal lock-first lifecycle.

Create lightweight policy + project agents in a project:

```powershell
.\scripts\new-project.ps1 -Target D:\Projects\MyProject
```

## Worked example

`examples/minimal-instance/` is a small, fully synthetic instance: a catalog with
two providers, a lock, an operational mode and a project policy. One provider is
admissible; the other exists and is locked but is not operationally eligible, so
resolving the mode that seeds it is refused with a reason that names it. Nothing in
it is a real provider or a real selection. Use it as the shape to copy when
building your own registry.

## Detailed docs

- `docs/ARCHITECTURE.md`
- `docs/PROJECT-MODEL.md`
- `docs/JOURNAL-DIGEST-VERSIONS.md`
- `docs/SOURCES.md`
- `docs/SECURITY.md`
- `docs/INDEX.html`

V1 profile-based manager should be treated as a prototype. V2 makes task modes and project policy first-class and keeps the global third-party Skill default close to zero.
