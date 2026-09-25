# Journal Digest Versioning

Two persisted digest domains in the activation journal cross a process and build
boundary: they are written by one build and recomputed from live filesystem data
by a later one. Both are therefore explicitly versioned, and the two versions are
independent of each other.

This document is the normative description of that protocol. It exists because an
earlier change versioned only the first domain and silently broke the second.

## 1. Why the domains are versioned

A filesystem stamp is observed as seven values: `st_dev`, `st_ino`, `st_mode`,
`st_nlink`, `st_size`, `st_mtime_ns`, `st_ctime_ns`. Four of them cannot be
assumed to fit the signed 64-bit range that `canonical_json()` accepts, so the
serialized observation encodes `st_dev`, `st_ino`, `st_mtime_ns` and `st_ctime_ns`
as canonical decimal text, while `st_mode`, `st_nlink` and `st_size` remain
integers.

That is the **version 2** stamp encoding. Before it, the whole stamp was a list of
raw integers, which is the **version 1** encoding. The two encode the same
observation differently, so any digest computed over an observation differs
between them for every file.

## 2. The two versioned domains

| domain | digest | marker |
|---|---|---|
| unmanaged | `activation.unmanaged_sha256` | `activation.unmanaged_digest_version` |
| child observation | `children[].observation_sha256` in `old_children` / `new_children` | `observation_digest_version` (journal level) |

The child-observation marker is journal level rather than per child because every
persisted child observation in one transaction is produced together by a single
observation pass; the schema never carries independently-versioned child entries.

**The markers are independent.** Neither version is ever inferred from the other.
A record may legitimately declare version 1 for one domain and version 2 for the
other.

## 3. Migration rules

For both domains:

* **Absence of the marker means version 1, and only version 1.** There is no
  "try the current version, then fall back" behaviour anywhere.
* **A version-2 mismatch must never be retried as version 1.** A version-1
  mismatch must never be retried as version 2. Retrying either way would turn a
  digest mismatch into an accepted downgrade.
* **Unknown or malformed versions fail closed.** The value must satisfy
  `type(version) is int`; `bool` is rejected even though `True == 1`, and the
  value must be a member of the known set. `0`, negative numbers, strings and
  floats are refused.
* **New journals always declare version 2 for both domains.** No new transaction
  ever emits a version-1 digest.
* The version is always read from the record being validated, never from the
  build's own default, so a journal written by an older build is recomputed with
  the encoding it was written under.

## 4. Where the versions are used

Unmanaged digest:

* written at `scripts/active_transaction.py:1293` (new journal, version 2) and
  `:1680` (snapshot)
* selected at `:297` (`unmanaged_digest_version`) and compared at `:1956`

Child-observation digest (`scripts/active_transaction.py`):

| site | line | version used |
|---|---|---|
| accessor | `:309` (`observation_digest_version`) | reads the record |
| forward / apply — write staged child | `:1330` | version 2 (current writer) |
| forward / apply — recompute before move | `:1347`, `:1356` | the record's version |
| rollback / restore — recompute before move | `:1467`, `:1479` | the record's version |
| terminal classification | `:1938`, `:1975` | the record's version |
| non-terminal classification | `:1938`, `:1998` | the record's version |
| `activation_snapshot` — old children | `:1671` | version 2 (current writer) |
| record validation | `:1693` | validates the marker |

`_activation_child(path, version)` (`:1602`) takes the version explicitly.
Write sites rely on its version-2 default; every comparison site passes the
version taken from the record under validation.

## 5. Recomputed persisted digests: the full inventory

Every persisted digest was audited and classified. Only the two domains above
cross a version boundary.

| persisted value | recomputed across runs | encoding changed | versioned |
|---|---|---|---|
| `activation.unmanaged_sha256` | yes (`:1956`) | yes | **yes** |
| `children[].observation_sha256` | yes (`:1356`, `:1479`, `:1975`, `:1998`) | yes | **yes** |
| `activation.context_sha256` | no — format check only (`:1768`) | yes | not required |
| `activation.old_metadata_identity` | yes (`:2025`, `:2032`) | no — built with `str()` | not required |
| `activation.providers[].*_sha256` (4 fields) | no — format check only (`:1796`) | no | not required |
| `old_manifest` / `old_state` / `new_manifest` / `new_state` `sha256` | yes, but recomputed from the stored bytes (`:250`) | no | not required |
| `cleanup_entries[].sha256` | yes, from file bytes (`:999`, `:1909`) | no | not required |
| `cleanup_entries[].identity` | yes (`:999`) | no — built with `str()` | not required |
| `children[].identity` and `children[].sha256` | yes | no — `observed_tree` hashes path, mode, attributes and content only | not required |
| `workspace_identity`, `skills_before`, `skills_created_identity`, `*_identity` | yes | no — `directory_identity()` already returned text | not required |
| `runtime_binding.root_identity` / `vault_identity` | yes | no | not required |
| `binding.digest('accp-lock-record-v1', ...)`, drift probes, `_file_digest` | call-local | — | not required |

## 6. Current protocol constraint: the 40-digit canonical identity boundary

Canonical decimal text for a filesystem identity is matched by
`IDENTITY_TEXT = [1-9][0-9]{0,39}`: non-zero, no sign, no leading zero, and **at
most 40 decimal digits**. Timestamps use `TIMESTAMP_TEXT =
(?:0|-?[1-9][0-9]{0,39})`, the same width with an optional leading minus.

This is an explicit, current limit of the protocol: a value of 10**40 or larger is
refused, as is an alternate spelling such as `01`, `+1`, `1_0`, `0x10` or a
Unicode digit. The bound is not a uint64 ceiling — values above `2**64-1`,
including exactly `2**64`, are accepted, and timestamps are signed.

The width is far above any real filesystem value: `st_dev` and `st_ino` are
64-bit (20 digits) on Windows and POSIX, and epoch-nanosecond timestamps are
approximately 19 digits. The same `[1-9][0-9]{0,39}` rule is used by
`validate_identity()` in both `scripts/artifact_binding.py` and
`scripts/active_transaction.py`.

Changing this boundary is a protocol change and is deliberately out of scope for
the digest-versioning work.
