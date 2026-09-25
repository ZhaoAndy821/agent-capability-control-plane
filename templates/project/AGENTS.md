# Project Agent Policy

This repository uses project-scoped execution agents plus a separate global capability control plane.

## Project agents

- `project_explorer`: read-only repository exploration and evidence collection.
- `project_worker`: bounded implementation in the current worktree.
- `project_reviewer`: read-only review/testing analysis after implementation.

Use project agents for project work only.

## Global capability boundary

Do not let project agents independently:
- install or research new global Skills;
- choose competing MCP/context/memory backends;
- change the global capability registry;
- modify trust/conflict policies.

When the project lacks a capability, return a concise escalation request to the global `capability-control-plane`.

## Concurrency

Parallelize independent read-heavy exploration.
Avoid parallel write-heavy tasks touching the same files.
The main project thread owns final integration.
