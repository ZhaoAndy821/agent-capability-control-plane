# Sources and upstream references

## Codex platform

- Codex Skills: https://developers.openai.com/codex/skills
- Codex Subagents / custom agents: https://developers.openai.com/codex/subagents
- OpenAI Skills catalog: https://github.com/openai/skills
- Codex repository: https://github.com/openai/codex
- Windows repo-local Skill discovery issue referenced during design:
  https://github.com/openai/codex/issues/40458

## Existing candidate list

This platform ships with an empty `registry/catalog.json`. Your own providers and their classifications go there; `schemas/catalog.schema.json` is the authoritative data model.

## Discovery references

Useful upstream discovery catalogs are kept as `reference` entries rather than deployed Skills, so the scout agent can consult them without expanding Codex's active Skill surface.
