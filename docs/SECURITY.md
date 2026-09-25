# Security and Trust Model

## F06 binding proof (M1/M2/M3; independent final review pending)

`scripts/artifact_binding.py` defines the shared versioned provenance contract.
Resolve and materialize require its reviewed-record proof through the existing
F05 eligibility core and F04 selection gates. Review/pin produce modern records;
materialize and the existing activation Vault checks use reviewed expected
artifact proof. M3 binds activation to a fresh call-local context and verifies the
complete staged artifact before switching. F06 stays open for independent final review.

The contract binds the complete catalog entry, canonical origin, exact Git commit
and subtree, explicit deploy path, source inventory, projected artifact inventory
and invocation policy. Evidence v2 records are strict canonical UTF-8 JSON plus
one LF. The lock's raw evidence SHA-256 and candidate digest anchor the expected
artifact outside the Vault. Vault v2 metadata is only a consistency assertion;
changing its content and local digest cannot authorize a different artifact.

The module rejects duplicate/unknown fields, noncanonical records, floats,
unsupported versions, path aliases, links/reparse points, hard-linked files and
Windows named streams. JSON depth is capped at 32; inventories at 10,000 entries,
32 MiB/file and 256 MiB total. Inventory paths are limited to 1,024 UTF-8 bytes
and 32 components. Evidence/lock/catalog records are capped at 8 MiB, manifests
at 64 KiB and catalog entries at 256 KiB. Canonical/schema domain checks do not
replace physical identity checks or F05 eligibility/approval checks.

A record read binds the opened descriptor to the object the path inspection just
validated using exactly the fields that the path APIs and the descriptor APIs
report identically (`st_dev`, `st_ino`, `st_mode`, `st_nlink`, `st_size`,
`st_mtime_ns`). `st_ctime_ns` is excluded from that cross-API comparison because
the two APIs do not report the same quantity: on Windows with CPython 3.12+ the
path APIs expose CreationTime while the descriptor APIs expose ChangeTime, so a
wholesale stamp comparison compares two different clocks and refuses any file
whose ChangeTime has moved — including every file published through
`os.replace()`. `st_ctime_ns` is retained, and remains load-bearing, in the
descriptor-versus-descriptor comparison that covers the read window, where both
sides come from the same API and the field is meaningful. It is not compared
path-to-descriptor anywhere.

The field's resolution is the filesystem's change-time granularity — on the order
of a millisecond on NTFS — so a modification that completes inside a single tick
of the pre-read observation is not distinguishable through `st_ctime_ns` alone.
Size, mtime and the identity fields are compared in the same window and are not
subject to that granularity.

Raw Git export accepts a validated plain bare object store and exact SHA-1 object
IDs. It checks object types/sizes and recomputes object hashes, reads loose and
packed objects without checkout/filters/hooks, and rejects symlinks, gitlinks,
alternate stores, unsafe configuration and ambiguous names. Export performs no
fetch or writes. Materialization builds from the complete `Export.inventory`,
including empty directories, and preserves Git executable paths on POSIX.

Source acquisition uses an origin-digest immediate child of the F02-owned sources
directory. Fresh bare caches are constructed without templates; reuse validates
plain paths and a strict local configuration before invoking Git. Includes,
helpers, alternates, replacement refs and worktrees are refused. Ambient Git
configuration is excluded, hooks/fsmonitor/automatic maintenance are disabled,
and only the chosen HTTPS or local-file transport is enabled. HTTPS redirects
are refused and TLS verification stays enabled; no credential helper is set up.
Local sources additionally need a plain Git administrative tree and constrained
core/user configuration: unsafe source-side upload-pack configuration is refused
before runtime creation. This conservative offline-source profile may reject
otherwise ordinary configurations, including quoted or whitespace-bearing values.
Cache/export limits may also refuse large object stores; there is no weak fallback.

`accp-invocation-v1` replaces `agents/openai.yaml` with a fixed two-line policy:
`allow_implicit_invocation: false` for explicit invocation, `true` for implicit.
Upstream YAML is bound as source bytes; the replacement is bound as artifact
bytes. Extra upstream YAML/UI fields are deliberately not merged. Review reports
the exact replacement alongside the candidate evidence. The pure projection helper
does not authorize implicit invocation; F05 still restricts it to low risk.

Historical six-field lock records and unresolved catalog entries remain
representable. The new operational proof loader refuses legacy locks and evidence
with missing digests; it never adopts a legacy Vault. Lint emits explicit legacy
non-admissible diagnostics. Migration requires an explicit catalog path, a fresh
exact-commit review and pin, then a fresh owned runtime or a valid same-binding
destination. Actual registry/evidence data has not been migrated. Schema shape alone
is not proof: canonical byte encoding,
UTF-8 byte limits, inventory ordering/topology/digest relationships, native path
semantics and current filesystem identities are enforced by runtime validators.

Materialize preflights the entire batch before runtime creation, rechecks current
records before source work and publication, and supplies fresh ready F02 receipt
fields. It builds a private stage from raw blobs, verifies the projected inventory
and publishes a canonical manifest. A current valid destination is an idempotent
no-op; an unprovable, legacy or different binding is refused without recursive
replacement. Failed publication leaves uniquely named temporary/stage data for
inspection; M2 introduces no cleanup/adoption mechanism or batch transaction.
New evidence, lock and Vault records use C1 plus LF and UTC-Z audit timestamps.

`activation_context.py` captures canonical checkout/project identities, scope,
target paths, mode, literal flags, candidate/evidence identities and the same
catalog/lock/mode/conflict/project-policy snapshots consumed by fresh resolution.
Only `cmd_activate` registers a live attempt; a cached plan, artifact manifest,
standalone proof object or expired attempt cannot authorize `activate_plan`.
Attempts are consumed before the first live rename and retired on every exit.
This is an in-process call boundary, not a sandbox against arbitrary Python code.

Nonempty activation keeps the runtime-mutex-then-legacy-lock order. It rechecks
the current ready ownership receipt, complete Vault trees, live metadata and
ancestor identities, and retained external F03 authority. Immediately before
switching it revalidates context, full staged artifacts (including invocation
policy and manifest consistency), and preservation of unmanaged bytes. Live
and staged observations refuse links, reparse points, hard links, named streams
and unavailable identities. The full Active Set, including unmanaged content,
is subject to the same 10,000-entry/32-MiB-file/256-MiB-total observation bounds;
oversized or unsupported trees are refused, never partially observed.

Refusal releases only the observed legacy lock and removes only the attempt's
plain, identity-matching stage. A replaced or unsafe stage is retained for
inspection. Empty plans require current context/F01/FR01 checks but no Vault.
Dry-run uses the authoritative reader contract below. It validates current
admission and reviewed Vault inputs under existing lifecycle coordination, but
does not reserve the runtime or authorize a staged artifact/live switch.
Activation's existing switch/rollback implementation is not a durable transaction;
the separate F03 activation/readers follow-ups remain outside this profile.
Trusted control-plane code/records and cooperating filesystem writers remain
assumptions: path rechecks do not provide handle-based exclusion of a hostile
concurrent same-account writer between the final check and a filesystem syscall.

A manifest cannot supply runtime authority. M3 must capture fresh activation
context, retain runtime-then-legacy locking and FR01 refusal, verify activation
staged bytes and revalidate at the live mutation boundary. Checks detect observed
drift; they do not defeat a concurrent
hostile writer of trusted ancestors. No signatures, reviewer authentication,
ACL/xattr attestation, credential authorization or downstream consumer execution
guarantee is claimed. Unsupported native identity/stream operations fail closed.

## Hard rules

1. Curation/sync may clone and read third-party repositories.
2. Curation/sync does **not** execute third-party scripts/installers.
3. No API keys or secrets belong in the Git repository.
4. Ambiguous upstream identity remains quarantined.
5. High-risk entries require explicit review.
6. Parallel agents are read-only by default.
7. Only the registry integrator writes global catalog/policy files after synthesis.
8. Active-set deployment refuses to overwrite unmanaged Skill directories.

## Active-set manifest deletion boundary

Activation and deactivation validate an existing install manifest before creating
the mutex or staging content, then validate again while holding the mutex. A
missing manifest claims no managed skills. An existing malformed manifest is an
error, including duplicate JSON fields, unsupported schema, missing or mismatched
control-plane/project/scope bindings, and invalid or duplicate managed IDs.

Managed IDs must be lowercase single directory names under the skills directory.
Absolute, drive-relative, UNC, device, traversal and separator-containing paths,
Windows reserved device names, and trailing dots/spaces are refused. Deletion is
restricted to resolved immediate children of the staging directory. Missing
managed directories are tolerated; other deletion failures are reported.

Existing project/active-root ancestors, metadata paths and the entire skills tree
must be free of symlinks and Windows reparse points (including junctions and
dangling links). This includes unmanaged descendants because the complete tree is
copied and its backup removed. An installation containing such links is refused
before mutation, rather than followed. Valid schema-1 manifests remain supported;
foreign or malformed manifests require operator review instead of silent repair.

The project-local manifest is a bounded deletion request, not authenticated proof
of ownership. Its author can claim names inside that project's skills directory;
the binding fields do not protect an unmanaged child against a writer who can
forge the manifest itself. They cannot authorize deletion outside the skills
boundary. The operator must prevent concurrent untrusted filesystem writers during
the operation. The mutex serializes cooperating ACCP commands; path checks do not
provide handle-based protection against hostile concurrent ancestor replacement.
That TOCTOU work and deactivation transaction rollback remain separate audit items.

## Trust is not binary

- `reviewed`: identity and relevant behavior were reviewed enough for controlled use.
- `partial`: source/use case identified, but executable/dependency surface is not fully audited.
- `unreviewed`: do not auto-activate.
- `quarantine`: source or safety boundary is unresolved.

A GitHub star count is not a trust decision.

## Operational eligibility

Catalog representation and permission to operate are separate. Known candidate,
quarantine, reference and other inactive records remain valid inventory. Unknown
or malformed adoption, trust, risk and invocation values are errors; values are
not converted or inferred from a lock, approval timestamp or existing Vault.

The shared eligibility policy requires `deploy.deployable` to be boolean `true`,
adoption to be `adopted` or `conditional`, and trust to be `reviewed` or `partial`.
Partial trust or conditional adoption requires both literal boolean approvals:
the call-time `allow_partial` flag and the lock's `partial_or_conditional` key.
High risk additionally requires the lock's `high_risk` to be literal `true`.
Missing authorization keys grant nothing; present nonboolean or unknown approval
fields are rejected. `approved_at` is informational only.

Only `explicit` and low-risk `implicit` invocation can operate. `dormant` entries
remain unavailable, regardless of approval flags. Existing approved evidence and
lock/hash checks still apply. Declared executable requirements must be supported
(`python`, `git`, `bash`, `ffmpeg`, `yt-dlp`) and available; matching is case
normalized. Unsupported expressions deny operation, without installation or
execution. Credential names remain unverified warnings.

Resolver admission and materialization share this policy. Activation validates
the actual requested IDs against a fresh resolution before runtime access and
again under the existing runtime-then-legacy lock order before staging. Supplied
coverage or warnings grant no authority. A changed selection refuses; it is never
silently replaced. Current validated locks are used for the final Vault check.
Gate refusal releases the legacy lock without switching Active Set content.

Materialize preflights the complete batch before runtime creation, then rechecks
eligibility and exact selected catalog/lock/evidence records inside the runtime
session before source work and before Vault publication. Late drift refuses
publication; owned scratch may remain and earlier published batch members are
not rolled back. Pin consumes strict JSON and literal boolean approval flags.
These are bounded rechecks under the existing trusted-writer assumption, not
atomic policy snapshots or transactional activation. FR01 retained-authority
refusal remains in force. F05 remains subject to its separate final review.
Invocation-artifact and broader catalog/lock/Vault binding remain F06; accepting
a declared invocation value does not prove an old Vault enforces that declaration.

## Risk dimensions

Audit:
- shell/process execution;
- package managers;
- network destinations;
- credentials;
- filesystem breadth;
- sensitive local data;
- subprocesses and native binaries;
- copied/vendor code;
- licenses;
- Windows-specific assumptions.

## Behavior updates are code changes

A modified `SKILL.md` can change Agent behavior even when no Python/JS code changed.

Therefore upstream updates should be:
1. detected;
2. diffed;
3. reviewed;
4. pinned;
5. then activated.

Never blindly follow latest `main` for a stable personal workflow.

## Privacy-sensitive capabilities

Mentor/persona distillation and persistent-memory systems deserve elevated scrutiny because they may ingest long-lived personal or project material.

Such systems are intentionally deferred or quarantined in the initial Registry.

## Runtime ownership and uninstall boundary

Recursive runtime deletion requires two independently validated records:

- `<runtime>/.accp-runtime-owner.json` is the immutable marker inside the
  runtime.
- `<ROOT>/.local/runtime-owners/<sha256(canonical-runtime-path)>.json` is the
  authoritative receipt. The receipt store is checkout-local administration
  data, not Registry policy and not a user-selectable authority location.

The marker and receipt bind the runtime to the control-plane checkout, the
executing OS principal, the canonical runtime path, a UUID4 runtime identity,
the runtime root directory identity, and the identities of the two owned
component directories. The two metadata filenames are fixed owned slots. Records
use strict schema-1 parsing: UTF-8 JSON, duplicate-key
rejection, exact keys and types, bounded size, and no symlink, reparse-point,
hard-link, or special-file metadata. A marker alone, a copied marker/receipt,
or matching JSON at another path is not ownership proof.

The runtime path is validated before any mutation. Relative, drive-relative,
root-relative, UNC, device, ADS/extra-colon, traversal, reserved-device-name,
and trailing-dot/space paths are rejected on Windows. Existing ancestors and
the candidate root must be ordinary directories with no symlink, junction, or
other reparse point. Repository and project roots/ancestors, both relevant
home/profile roots, the Active Set base, receipt-store overlap, filesystem and
drive roots, and protected system/program-data roots are rejected. Environment
overrides select a candidate only; they cannot waive these checks. An optional
`--project` adds a protected path and cannot reduce the other protections.

Only a genuinely absent, validated path may be freshly registered, using
exclusive directory creation and publishing the receipt last. Existing
directories, including empty or marker-shaped unrelated directories, are never
adopted. Legacy runtimes are left untouched and must be rebuilt at a fresh path
through fetch/materialize/bootstrap and the lock-first review flow.

Uninstall requires a fully valid receipt and `--yes`; `--dry-run` performs the
same validation and reports the exact plan without creating locks or changing
records. It derives deletion targets from constants, never from metadata or
runtime content, and recursively removes only `sources` and `vault`, then unlinks
`install-manifest.json` and `active-state.json` after immediate-child
containment, type, identity, and link/reparse checks. The runtime root, marker,
receipt tombstone, unknown top-level entries,
and all project Active Sets/personal agents remain. A failed deletion stops,
leaves a retryable `deleting` receipt, and reports completed and pending
components; it never retargets paths or marks completion. A successful run
marks the receipt `retired` and retains the root, marker, and receipt. Retired
runtimes are not automatically reused.

The receipt store and control-plane code are trusted administrative inputs, and
cooperating ACCP operations are serialized by a path-keyed mutex. This design
does not claim protection from an attacker who can rewrite both the checkout
and receipt store, from privileged same-account filesystem writers, or from
hostile concurrent ancestor replacement between checks. Such races must fail
closed where detected; handle-based TOCTOU resistance and receipt-store ACL
hardening are separate work.

An OS principal/profile lookup failure stops ownership operations; an environment
username or home value cannot replace the OS identity. Read-only cached Git files
can be retried only after regular-file, single-link and containment checks. Owned
subtrees containing multiply linked files are refused rather than changing shared
file permissions.

## Authoritative command readers (READERS R1)

`status` and activate/deactivate/recover/cleanup previews use one
`JournalAuthority.reader_report` boundary. It consults the derived external
journal/locator before interpreting metadata, takes only an existing plain OS
lifecycle lock (`create=False`), uses the existing exact v1/v2 classifiers, and
rechecks complete bounded live/evidence/workspace observations. The detached
response is prepared under ownership and emitted only after successful release.
No reader enrolls, creates a lock/store, issues an activation attempt, stages,
recovers, finalizes, or deletes anything. OS access timestamps are not promised
unchanged.

| Lifecycle | Meaning | Status exit |
|---|---|---|
| `SETTLED` | Coordinated, verified current metadata/tree; no retained transaction | 0 |
| `UNCOORDINATED` | No existing lifecycle lock and no retained authority/residue; no installed-generation claim | 2 |
| `BUSY_OR_UNAVAILABLE` | OS ownership unavailable; no inferred writer PID/phase | 2 |
| `RECOVERY_REQUIRED` | Legal incomplete transaction; old/new IDs are intent only | 2 |
| `TERMINAL_RETAINED` | Verified COMMITTED new generation or ROLLED_BACK old generation; evidence remains | 0 |
| `FINALIZATION_REQUIRED` | Verified CLEANING/DONE outcome; explicit cleanup remains | 0 |
| `UNKNOWN` | Unsafe, unreadable, pending, ambiguous, mismatched or malformed state | 2 |

A zero status exit does not mean providers remain eligible, that no cleanup is
needed, or that an installation's historical commit has been re-proven. Read
`lifecycle`, `transaction`, and `current_generation.basis`; the removed legacy
`activation_locked` boolean is not a health signal. Incomplete/unknown reports
withhold `current_generation`. All reports carry `admission_authority=false`, a
bounded diagnostic `detail`, and an observation time, never a reusable proof.

Previews return 0 only for a validated proposed action; otherwise 2. Activation
preview accepts only SETTLED/no retained transaction, validates the actual plan,
same-document F04/F05/F06 inputs, F01 collisions, fresh project-aware F02 receipt,
and full reviewed Vault artifact, with current-record and identity rechecks.
Empty selection does not access runtime. Runtime-mutex presence or observed drift
blocks admission; the preview neither acquires that creating mutex nor reverses
runtime-then-lifecycle writer order. `reservation=false` is explicit: current
inputs are not a reservation or proof that later staging/mutation will succeed.
An unenrolled installation must first use the real writer's existing enrollment;
use `resolve` for a hypothetical plan before enrollment.

Recovery/cleanup previews use recorded authority without current policy, review,
or runtime access. Recovery previews rollback before commit and retain verified
terminal outcomes; CLEANING/DONE require cleanup. Cleanup previews validate the
bounded terminal inventory. Deactivate refuses retained authority except the
existing v1 COMMITTED no-op. No preview auto-recovers or consumes evidence.

`resolve` reports `resolution_only`; `doctor`/Control-Center report
`configuration_only`. Python `audit` is a nonmutating `runtime_audit`, validates
current review/Vault bindings and F02 state without creating a mutex, and returns
2 for invalid diagnostic rows. It does not attest eligibility or Active Set
health. `audit.ps1` defaults to authoritative status (`-Project`, `-Scope`);
`-Vault` delegates runtime audit and rejects project/scope options. Wrapper exit
codes propagate. Bootstrap/uninstall previews remain unreserved, runtime/personal
agent proposals with their existing F02 checks, not Active Set health reports.

Proof limits remain cooperating writers, trusted control-plane/review stores,
existing path-based identity checks and bounded whole-tree reads. A reader can
refuse oversized installations/workspaces even when a historical writer accepted
them. Runtime input observations are not an atomic runtime snapshot. Results are
point-in-time and can become stale after release; external unlocked readers,
hostile administrative processes, native POSIX acceptance and unsupported Windows
power-loss directory durability are not claimed.
