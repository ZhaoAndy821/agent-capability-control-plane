---
name: capability-control-plane
description: Explicitly coordinate the personal Agent Capability Control Plane: investigate upstream Skills/tools, audit trust, resolve minimal task capability sets, review routing conflicts, and plan registry changes. Use only when the user explicitly asks to manage, research, audit, select, update, or restructure the capability stack.
---

# Capability Control Plane

This is the explicit entry point for **global capability management**. It is not a general-purpose project Skill.

## Operating model

The main Codex thread is the chief architect. Use the custom control-plane agents for independent analysis:

- `accp_upstream_scout`: upstream/repository discovery.
- `accp_trust_auditor`: security, privacy, dependency and execution-boundary audit.
- `accp_capability_resolver`: minimal active-set resolution.
- `accp_routing_evaluator`: Skill-trigger overlap and implicit-routing audit.
- `accp_portfolio_architect`: long-term architecture/policy decisions.
- `accp_registry_integrator`: write an already-approved synthesized decision.

## Delegation rules

1. Parallelize independent **read-heavy** investigations.
2. Keep write-heavy work serial.
3. Never let multiple agents edit registry files concurrently.
4. The main thread must wait for the relevant read-only agents, compare disagreements, and own the final decision.
5. Spawn `accp_registry_integrator` only after the decision is explicit.
6. Third-party repositories may be cloned/read by deterministic scripts, but no third-party install or runtime script is executed as part of curation.
7. Project implementation agents must not independently modify the global capability portfolio.

## Typical workflows

### Evaluate a new GitHub candidate
Delegate upstream identity to scout, trust/execution review to auditor, overlap to routing evaluator, then ask the portfolio architect for placement. Synthesize before any write.

### Resolve capabilities for a task/project
Have the resolver inspect the project policy and task modes. If the proposed set touches conflict groups or a broad suite, ask the routing evaluator. Prefer 1–5 third-party Skills.

### Update a pinned upstream
Scout the upstream change and auditor the changed execution surface. Only after approval ask the integrator to update lock/registry metadata.

## Never do this

- Activate every installed Skill.
- Treat an MCP/CLI/application/runtime as a Skill merely to unify installation.
- Guess the upstream of an ambiguous name.
- Auto-merge upstream behavior changes without review.
- Store API keys or personal secrets in the control-plane repository.
