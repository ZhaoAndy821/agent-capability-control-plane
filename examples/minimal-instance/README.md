# Minimal instance (synthetic)

A worked, fully synthetic example of the data this control plane reads: a catalog,
a lock, an operational mode and a project policy. Nothing here is a real provider,
a real selection, or a real source; the URLs use the reserved `example.invalid`
domain and every digest is a placeholder.

## Layout

```text
registry/catalog.json          two providers
registry/conflict-groups.json  empty
modes/operational-modes.json   one mode, "example-denied"
lock/sources.lock.json         a lock entry for both providers
```

| provider | state | what it demonstrates |
|---|---|---|
| `example-eligible` | `adoption: adopted`, `trust: reviewed`, deployable | the shape an admissible provider must have |
| `example-ineligible` | `adoption: candidate` | a provider that exists **and is locked**, yet operational admission refuses it |

`modes/operational-modes.json` seeds `example-ineligible`, so resolving that mode
must fail and say why:

```text
operational eligibility denied: example-ineligible: adoption=candidate is not operationally eligible
```

That refusal is the point of this example: it exercises the same admission path a
real registry uses, without shipping anyone's real data.

## Using it

Copy the directories over a checkout and resolve:

```powershell
Copy-Item -Recurse -Force examples/minimal-instance/registry, examples/minimal-instance/modes, examples/minimal-instance/lock .
python -B scripts/accp.py resolve --mode example-denied --project <your-project>
```

To build your own instance, replace these files with your own providers. The
authoritative data model is `schemas/catalog.schema.json`, `schemas/lock.schema.json`,
`schemas/evidence.schema.json`, `schemas/project-policy.schema.json` and
`schemas/vault-manifest.schema.json`.
