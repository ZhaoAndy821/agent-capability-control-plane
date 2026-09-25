# Project Model

## Minimal project footprint

A project only needs:

```text
project/
  .codex-skillset.json
  AGENTS.md
  .codex/
    agents/
      project-explorer.toml
      project-worker.toml
      project-reviewer.toml
```

No third-party Skill copies are committed into the project.

## `.codex-skillset.json`

It declares:
- informational project type;
- allowed operational modes;
- default operational mode;
- explicit includes/excludes;
- required/preferred/forbidden capability hints.

The deterministic resolver enforces the declared operational modes and hard
project constraints. `project_type` is informational metadata. The canonical
policy keys are `allowed_operational_modes` and `default_operational_mode`;
legacy aliases and unknown or fallback keys are rejected.

## Example

```json
{
  "schema_version": 1,
  "project_type": ["example"],
  "allowed_operational_modes": ["dev-build", "dev-review"],
  "default_operational_mode": "dev-build",
  "include": [],
  "exclude": ["legacy-unreviewed"],
  "capabilities": {
    "require": ["code-review"],
    "prefer": ["unit-testing"],
    "forbid": ["persistent-memory"]
  }
}
```

An absent `allowed_operational_modes` places no project mode restriction. An
explicit empty array permits no operational modes. An explicit `exclude` wins
over `include`, including when both name the same provider. `forbid` is a
hard constraint across mode seeds, includes, requirements, preferences, and
the final capability union; `require` is hard as well, and a contradiction
between `require` and `forbid` refuses resolution. Every still-uncovered required capability
must have exactly one eligible provider after exclusions, forbids, conflicts,
deployment, lock/evidence, approval, and supported dependency checks. More or
fewer eligible providers refuse the requirement. Preferences are optional and
conflict-safe: they never evict or invalidate a valid required selection, and
conflicting optional choices use sorted capability order.

Resolver `runtime.requires` checks are limited to the supported executable names
`python`, `git`, `bash`, `ffmpeg`, and `yt-dlp`, matched case-insensitively and
verified with `which`. Unsupported expressions are refused operationally.
Resolution does not install dependencies or validate credentials; credential
names may produce warnings only. Results contain unique provider IDs and
sorted capability lists and use deterministic ordering. The resolver is
conservative unique-candidate selection, not a global-optimal set-cover
solver. Final evidence or dependency revalidation can abort resolution if the
environment changes during planning; no weaker fallback is returned.

Provider admission uses the shared operational policy in SECURITY.md: explicit
deployability and known eligible adoption/trust states, both partial/conditional
approval keys when applicable, literal high-risk authorization, and explicit or
low-risk implicit invocation. Project includes and preferences cannot override
these requirements. Activation revalidates the actual IDs against fresh project
constraints and current eligibility before staging; changed selection refuses
instead of silently activating an alternative.

## Workflow

1. Open project.
2. Main project thread reads project policy.
3. Use `resolve.ps1` or the explicit control-plane Skill if semantic planning is needed.
4. Activate only the chosen task mode.
5. Project explorer/worker/reviewer do project work.
6. Missing global capability => escalate to Control Team.
7. Do not let project agents mutate the global Registry.

## Why policy isolation

The same Skill may serve many projects. Copying it into every repository creates divergent versions and destroys provenance.

The project should declare **requirements**, while the central Registry owns **providers**.

This is dependency injection for Agent capabilities.
