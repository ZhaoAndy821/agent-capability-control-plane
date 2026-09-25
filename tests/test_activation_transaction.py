"""A1 model fixtures: records/layouts only, never a forward activation engine."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import active_transaction as txn
import artifact_binding as binding
import activation_context as observation


class ActivationFixture(unittest.TestCase):
    def setUp(self):
        folder = ROOT / '.local' / 'audit-temp'; folder.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=folder); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cp = self.root / 'checkout'; self.project = self.root / 'project'
        self.cp.mkdir(); self.project.mkdir()
        self.base = self.project / '.agents'; self.base.mkdir()
        self.owner = txn.JournalAuthority(self.cp, self.project)
        self.skills = self.base / 'skills'
        self.im = self.base / 'install-manifest.json'; self.state = self.base / 'active-state.json'
        self.runtime = self.root / 'runtime'; self.runtime.mkdir(); (self.runtime / 'vault').mkdir()
        self.owner.store.mkdir(parents=True)
        self.owner.lock_path.write_bytes(b'')

    def metadata(self, values):
        return [json.dumps(dict(schema_version=1, control_plane_path=str(self.owner.checkout),
                    project=str(self.owner.project), scope=self.owner.scope, managed_ids=values,
                    mode='fixture', extra='preserve old bytes'), indent=2).encode() + b'\n',
                json.dumps(dict(schema_version=1, control_plane_path=str(self.owner.checkout),
                    active_ids=values, mode='fixture'), indent=2).encode() + b'\n']

    def build(self, old=('alpha', 'beta'), new=('alpha', 'gamma'), prepared=True,
              absent=False, missing_metadata=False):
        old, new = list(old), list(new)
        if not absent:
            self.skills.mkdir()
            for ident in old:
                path = self.skills / ident; path.mkdir(); (path / 'SKILL.md').write_bytes(('old-' + ident).encode())
            (self.skills / 'user.txt').write_bytes(b'untouched user content')
        if not missing_metadata:
            for path, data in zip((self.im, self.state), self.metadata(old)): path.write_bytes(data)
        snap = self.owner.activation_snapshot(old, new)
        new_meta = self.metadata(new)
        rb = dict(runtime_id=str(uuid.uuid4()), runtime_path=os.path.normcase(str(self.runtime)),
                  control_plane_path=str(self.owner.checkout), principal='sid:S-1-5-21-1234',
                  root_identity=binding.directory_identity(self.runtime),
                  vault_identity=binding.directory_identity(self.runtime / 'vault'))
        ident = str(uuid.uuid4())
        self.record = dict(self.owner.bindings(), schema_version=2, kind='accp-active-txn',
            transaction_id=ident, operation='activate', phase='PREPARING', prepared=False,
            skills_before=snap['skills_before'], skills_created_identity=None, workspace_identity=None,
            # A record written by this code declares the current encoding of both
            # digest domains. An absent child-observation marker means the legacy
            # encoding, exactly as an absent unmanaged marker does.
            observation_digest_version=observation.OBSERVATION_DIGEST_V2,
            old_ids=old, new_ids=new, old_children=snap['old_children'],
            new_children={i: {'prepared': False} for i in new},
            old_manifest=snap['old_manifest'], old_state=snap['old_state'],
            new_manifest=txn.snapshot(new_meta[0]), new_state=txn.snapshot(new_meta[1]),
            activation=dict(attempt_id=ident, context_sha256='1'*64, runtime_binding=rb if new else None,
                providers={i: dict(candidate_sha256='2'*64, evidence_sha256='3'*64,
                    lock_sha256='4'*64, artifact_tree_sha256='5'*64,
                    invocation='explicit', projection=binding.PROJECTION) for i in new},
                unmanaged_sha256=snap['unmanaged_sha256'], old_metadata_identity=snap['old_metadata_identity'],
                # A record written by this code always declares its unmanaged digest
                # version; an absent marker means the legacy encoding, and the digest
                # above is computed with the current one.
                unmanaged_digest_version=observation.UNMANAGED_DIGEST_V2,
                skills_mode_before=snap['skills_mode_before']))
        self.workspace = self.owner.workspace(ident)
        if prepared: self.prepare()
        self.persist()
        return self.record

    def prepare(self):
        self.workspace.mkdir()
        for area in ('old', 'new', 'discard'): (self.workspace / area).mkdir()
        self.record['workspace_identity'] = {area: txn.directory_identity(
            self.workspace if area == 'root' else self.workspace / area) for area in ('root','old','new','discard')}
        for ident in self.record['new_ids']:
            path = self.workspace / 'new' / ident; path.mkdir()
            (path / 'SKILL.md').write_bytes(('new-' + ident).encode())
            self.record['new_children'][ident] = self.owner._activation_child(path)
        self.record.update(phase='PREPARED', prepared=True)

    def persist(self, locator=True):
        self.owner.journal.write_bytes(self.owner.serialize(self.record))
        if locator:
            self.owner.locator.write_bytes((json.dumps(self.owner.locator_record(self.record),
                sort_keys=True, separators=(',', ':')) + '\n').encode())

    # A version-1 digest can only ever have been written on a volume whose
    # filesystem identity fits signed 64-bit, because that is what the legacy
    # integer encoding required. A runner whose volume reports st_dev/st_ino >=
    # 2**63 can therefore never produce or validate one, and the legacy path is
    # simply not representable there. Pinning the identity keeps every
    # legacy-encoding test independent of how the runner volume is provisioned.
    IN_RANGE_STAMP = (647463021274208632, 74590868828351668, 33206, 1, 16,
                      1790228341134964700, 1790228341134964700)

    def in_range_identity(self):
        """Pin a signed-64-representable identity, distinct per path.

        Two details matter. Distinctness: the journal refuses two objects sharing a
        filesystem identity, so one constant stamp would be rejected as an identity
        alias rather than exercising the legacy digest path. And the key must be
        path-normalised: the same file reaches this function under different
        spellings (the fixture's own path and JournalAuthority's canonicalised one,
        which can differ in case on Windows), and keying on the raw string would
        hand the same file two different identities.

        The pin must span BOTH the write and the read of a test: it supplies the
        live identity the digest is recomputed from, so pinning only one side makes
        the two sides disagree for reasons unrelated to versioning.
        """
        real = binding._read_file
        assigned = {}

        def fake(path, limit, _assigned=assigned):
            data, _ = real(path, limit)
            key = os.path.normcase(os.path.abspath(str(path)))
            if key not in _assigned:
                _assigned[key] = len(_assigned) + 1
            dev, ino, mode, nlink, _, mtime, ctime = self.IN_RANGE_STAMP
            return data, (dev, ino + _assigned[key], mode, nlink, len(data), mtime, ctime)

        return mock.patch.object(binding, '_read_file', fake)

    def union(self):
        return set(self.record['old_ids']) | set(self.record['new_ids'])

    def live_digest(self, version):
        rows = observation.tree_observation(self.skills)
        return observation.unmanaged_observation(rows, self.union(), version)

    def locate(self, ident, generation):
        """Locate one generation's object; its area depends on the phase.

        A child id can exist in both generations at once (for example 'alpha' may
        be both an old and a new child), so the search order follows the
        generation and the phase. Searching naively would silently compare a new
        child's digest against the old child's object.
        """
        phase = self.record['phase']
        if generation == 'new':
            order = (self.workspace / 'new', self.skills, self.workspace / 'discard')
        else:
            order = (self.skills, self.workspace / 'old')
        if phase in ('CLEANING', 'DONE'):
            order = tuple(reversed(order))
        for base in order:
            path = base / ident
            if path.exists():
                return path
        return None

    def observe(self):
        return {path.relative_to(self.root).as_posix(): (path.lstat().st_ino, stat.S_IMODE(path.lstat().st_mode),
                path.read_bytes() if path.is_file() else None) for path in self.root.rglob('*')}

    def classify(self):
        before = self.observe()
        with self.owner.lifecycle_lock(create=False): result = self.owner.classify_activation()
        self.assertEqual(before, self.observe(), 'read-only classifier mutated the fixture')
        return result

    def refuse(self):
        before = self.observe()
        with self.assertRaises((txn.JournalError, OSError)):
            with self.owner.lifecycle_lock(create=False): self.owner.classify_activation()
        self.assertEqual(before, self.observe())

    def move_old(self, ident): os.replace(self.skills / ident, self.workspace / 'old' / ident)
    def move_new(self, ident): os.replace(self.workspace / 'new' / ident, self.skills / ident)

    def applying(self):
        self.record['phase'] = 'APPLYING'; self.persist()

    def committed(self):
        self.applying()
        if not self.skills.exists():
            self.skills.mkdir(); self.record['skills_created_identity'] = txn.directory_identity(self.skills)
        for ident in self.record['old_ids']: self.move_old(ident)
        for ident in self.record['new_ids']: self.move_new(ident)
        for key, path in (('manifest', self.im), ('state', self.state)):
            path.write_bytes(txn.snapshot_bytes(self.record['new_' + key]))
        self.record['phase'] = 'COMMITTED'; self.persist()

    def cleanup_record(self, outcome='committed'):
        self.record.update(phase='CLEANING', outcome=outcome)
        entries = []
        for area in ('old',) if outcome == 'committed' else ('new', 'discard'):
            for child in (self.workspace / area).iterdir():
                for path in [child, *child.rglob('*')]:
                    entry = dict(area=area, id=child.name, relative=path.relative_to(child).as_posix(),
                        type='directory' if path.is_dir() else 'file',
                        identity={'device': str(path.stat().st_dev), 'inode': str(path.stat().st_ino)})
                    if path.is_file(): entry.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                        readonly=bool(getattr(path.stat(), 'st_file_attributes', 0) & 1))
                    entries.append(entry)
        self.record['cleanup_entries'] = entries; self.persist()


class ActivationContract(ActivationFixture):
    def test_exact_roundtrip_and_read_only_snapshot(self):
        record = self.build()
        raw = self.owner.serialize(record)
        self.assertEqual(raw, (json.dumps(record, sort_keys=True, ensure_ascii=False,
            allow_nan=False, separators=(',', ':'))+'\n').encode())
        self.assertEqual(record, self.owner.parse(raw))
        before = self.observe(); self.owner.activation_snapshot(record['old_ids'], record['new_ids'])
        self.assertEqual(before, self.observe())
        self.assertEqual('PREPARED', self.classify()['phase'])

    def test_strict_fields_types_domains_and_bindings(self):
        original = self.build()
        cases = [('schema_version', True), ('schema_version', 3), ('operation', 'deactivate'),
                 ('phase', 'COMMIT'), ('prepared', 1), ('transaction_id', '../escape'),
                 ('project_path', str(self.cp)), ('base_identity', {'device':'1','inode':'2'}),
                 ('old_ids', ['beta','alpha']), ('new_ids', ['alpha','alpha']), ('extra', None)]
        for key, value in cases:
            record = copy.deepcopy(original); record[key] = value
            with self.subTest(key=key), self.assertRaises(txn.JournalError): self.owner.serialize(record)
        for field in original:
            # The child-observation digest marker is deliberately optional: its
            # absence is the legacy V1 encoding, so deleting it is accepted rather
            # than refused. Every other field is mandatory.
            if field == 'observation_digest_version': continue
            record = copy.deepcopy(original); del record[field]
            with self.subTest(missing=field), self.assertRaises(txn.JournalError): self.owner.serialize(record)
        for key, value in [('attempt_id', str(uuid.uuid4())), ('context_sha256', 'ABC'),
                           ('unmanaged_sha256', 0), ('skills_mode_before', True),
                           ('runtime_binding', None), ('providers', {})]:
            record = copy.deepcopy(original); record['activation'][key] = value
            with self.subTest(activation=key), self.assertRaises(txn.JournalError): self.owner.serialize(record)
        for key, value in [('invocation', 'dormant'), ('projection', 'unknown'), ('candidate_sha256', 'A'*64)]:
            record = copy.deepcopy(original); record['activation']['providers']['alpha'][key] = value
            with self.subTest(provider=key), self.assertRaises(txn.JournalError): self.owner.serialize(record)

    def test_json_duplicates_utf8_truncation_and_limits(self):
        raw = self.owner.serialize(self.build())
        for value in (b'{', raw[:-2], b'\xef\xbb\xbf'+raw, b'\xff', raw.replace(b'"activation":', b'"phase":"APPLYING","activation":'),
                      b'{"x":NaN}', b'[]'):
            with self.subTest(raw=value[:20]), self.assertRaises(txn.JournalError): self.owner.parse(value)
        with mock.patch.object(txn, 'MAX_JOURNAL', len(raw)-1), self.assertRaises(txn.JournalError):
            self.owner.serialize(self.record)
        with mock.patch.object(txn, 'MAX_IDS', 1), self.assertRaises(txn.JournalError): self.owner.validate(self.record)
        with mock.patch.object(binding, 'MAX_ENTRIES', 1), self.assertRaises(txn.JournalError):
            self.owner.activation_snapshot(self.record['old_ids'], self.record['new_ids'])

    def test_digest_identity_and_unprepared_conflicts(self):
        original = self.build()
        for key in ('sha256', 'observation_sha256', 'identity'):
            record = copy.deepcopy(original); record['old_children']['alpha'][key] = None
            with self.subTest(key=key), self.assertRaises(txn.JournalError): self.owner.validate(record)
        record = copy.deepcopy(original); record['new_children']['alpha'] = record['old_children']['alpha']
        with self.assertRaises(txn.JournalError): self.owner.validate(record)
        record = copy.deepcopy(original); record['old_children']['alpha'] = {'prepared':False}
        with self.assertRaises(txn.JournalError): self.owner.validate(record)
        record = copy.deepcopy(original); record.update(phase='PREPARING', prepared=False)
        record['new_children']['alpha'] = {'prepared':False}
        with self.assertRaises(txn.JournalError): self.owner.validate(record)

    def test_transitions_freeze_proofs_and_known_objects(self):
        original = self.build()
        for key in ('activation', 'old_manifest', 'new_state', 'new_children'):
            next_record = copy.deepcopy(original); next_record[key] = {}
            with self.subTest(key=key), self.assertRaises(txn.JournalError):
                self.owner._validate_transition(original, next_record)
        for phase in ('PREPARING', 'COMMITTED', 'DONE'):
            next_record = dict(original, phase=phase)
            with self.subTest(phase=phase), self.assertRaises(txn.JournalError):
                self.owner._validate_transition(original, next_record)
        self.owner._validate_transition(original, dict(original, phase='APPLYING'))

    def test_preparing_cannot_register_objects_while_rolling_back(self):
        old=self.build(prepared=False); new=copy.deepcopy(old)
        new['phase']='ROLLING_BACK'; new['workspace_identity']={}
        with self.assertRaises(txn.JournalError): self.owner._validate_transition(old,new)

    def test_digest_domains_match_c1_and_preserve_artifact_allowlist(self):
        value={'a': 1}
        for label in ('accp-activation-child-v1','accp-activation-unmanaged-v1','accp-activation-context-v1'):
            self.assertEqual(hashlib.sha256(label.encode()+b'\0'+binding.canonical_json(value)).hexdigest(),
                             observation.transaction_digest(label,value))
            with self.assertRaises(binding.BindingError): binding.digest(label,value)
        with self.assertRaises(binding.BindingError): observation.transaction_digest('foreign',value)

    def test_snapshot_hash_and_runtime_overlap_refused(self):
        original=self.build()
        record=copy.deepcopy(original); record['old_manifest']['sha256']='0'*64
        with self.assertRaises(txn.JournalError): self.owner.validate(record)
        for path in (self.base,self.owner.store,self.base/'runtime'):
            record=copy.deepcopy(original)
            record['activation']['runtime_binding']['runtime_path']=os.path.normcase(str(path))
            with self.subTest(path=path), self.assertRaises(txn.JournalError): self.owner.validate(record)
        for name in ('MAX_FILE','MAX_PAYLOAD'):
            with mock.patch.object(binding,name,1), self.assertRaises(txn.JournalError):
                self.owner.activation_snapshot(self.record['old_ids'],self.record['new_ids'])

    def test_snapshot_collision_pair_and_identity_refusals(self):
        self.build()
        before = self.observe()
        with self.assertRaises(txn.JournalError): self.owner.activation_snapshot(['alpha','beta'], ['user.txt'])
        (self.skills/'Other').mkdir()
        with self.assertRaises(txn.JournalError): self.owner.activation_snapshot(['alpha','beta'], ['other'])
        self.state.unlink()
        with self.assertRaises(txn.JournalError): self.owner.activation_snapshot(['alpha','beta'], ['alpha'])
        self.state.write_bytes(b'{}')
        with self.assertRaises(txn.JournalError): self.owner.activation_snapshot(['alpha','beta'], ['alpha'])
        self.assertEqual(before['project/.agents/skills/user.txt'], self.observe()['project/.agents/skills/user.txt'])

    def test_forward_mutators_remain_disabled_and_missing_lock_is_not_created(self):
        self.build(); before = self.observe()
        result = self.owner.recover(lambda: self.fail('v1 preflight reached'),
                                    lambda: self.fail('v1 path reached'), dry_run=True)
        # R1 dry-runs return the reader envelope; the action sits in the payload.
        self.assertEqual('RECOVERY_REQUIRED', result['lifecycle'])
        self.assertEqual('rollback', result['preview']['action'])
        self.assertEqual('validated_inputs', result['preview']['admission'])
        self.assertFalse(result['preview']['reservation'])
        self.assertFalse(result['admission_authority'])
        with self.assertRaises(txn.JournalError): self.owner.cleanup(lambda: None, lambda: None)
        with self.owner.lifecycle_lock(create=False):
            for method in (self.owner.publish_journal, self.owner.publish_locator):
                with self.assertRaises(txn.JournalError): method(self.record)
        self.assertEqual(before, self.observe())
        # A missing lifecycle lock must not be created merely to reject a record.
        self.owner.lock_path.unlink(); before = self.observe()
        with self.assertRaises((txn.JournalError, OSError)): self.owner.recover(lambda: None, lambda: None)
        with self.assertRaises((txn.JournalError, OSError)): self.owner.cleanup(lambda: None, lambda: None)
        with self.assertRaisesRegex(txn.JournalError, 'A1 v2'): self.owner.deactivate(lambda: None, b'', b'')
        self.assertEqual(before, self.observe())

    def test_v1_canonical_bytes_and_activation_execution_refusal(self):
        self.build(new=())
        record = copy.deepcopy(self.record); record.update(schema_version=1, operation='deactivate')
        del record['activation']
        # A schema-1 record predates both digest version markers, so neither may
        # survive the downgrade: an unexpected field is refused, not ignored.
        del record['observation_digest_version']
        for value in record['old_children'].values(): del value['observation_sha256']
        raw = (json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(',', ':'))+'\n').encode()
        self.assertEqual(raw, self.owner.serialize(record)); self.assertEqual(record, self.owner.parse(raw))
        record['operation'] = 'activate'; self.record = record; self.persist()
        with self.assertRaises(txn.JournalError): self.owner.recover(lambda: None, lambda: None)

    def test_authority_paths_and_id_escape_refuse(self):
        original = self.build()
        for ident in ('../x', '/x', 'C:relative', 'C:\\root', '//server/share', '\\\\?\\C:\\x', 'con', 'alpha.'):
            record = copy.deepcopy(original); record['new_ids'] = [ident]
            with self.subTest(ident=ident), self.assertRaises(txn.JournalError): self.owner.serialize(record)
        for root in (self.cp, self.cp/'.local'/'active-transactions', self.project):
            with self.assertRaises(txn.JournalError): txn.JournalAuthority(self.cp,self.project,'user',root)
        with self.assertRaises(txn.JournalError): txn.JournalAuthority(str(self.cp/'..'/'checkout'),self.project)


class ActivationDigestVersionTests(ActivationFixture):
    """The unmanaged digest is explicitly versioned, with no fallback between versions.

    Version 1 is the legacy integer observation encoding; version 2 is the canonical
    decimal-string encoding that tolerates unsigned-64 filesystem identities. A
    journal written before the change carries no marker and is validated as version 1.
    A journal written now declares version 2 and is validated ONLY as version 2 -- a
    version-2 mismatch must never be retried as version 1, or a downgrade attack
    becomes possible.
    """

    def persist_raw(self):
        """Write the journal WITHOUT writer-side validation, to exercise the reader.

        A journal on disk may have been produced by an older build or altered
        outside this writer, so the reader's own refusal must be tested directly
        rather than only through serialize(). The locator is left as written by the
        fixture: classification reads the journal.
        """
        self.owner.journal.write_bytes((json.dumps(self.record, sort_keys=True,
            ensure_ascii=False, allow_nan=False, separators=(',', ':')) + '\n').encode())

    def rewrite_activation(self, **updates):
        self.record['activation'] = dict(self.record['activation'], **updates)
        self.persist()
        return self.record

    def test_10_v2_journal_round_trip(self):
        self.build()
        self.assertEqual(observation.UNMANAGED_DIGEST_V2,
                         self.record['activation']['unmanaged_digest_version'])
        self.assertEqual('PREPARED', self.classify()['phase'])

    def test_09_legacy_v1_journal_remains_recoverable(self):
        """The legacy version-1 *unmanaged* digest is accepted without a marker.

        This covers the unmanaged domain only: it varies the unmanaged marker and
        digest while the child observations stay current. A journal that is legacy
        in BOTH domains is covered by ObservationDigestVersionTests, which is where
        the child-observation encoding is versioned.
        """
        with self.in_range_identity():
            self.build()
            activation = dict(self.record['activation'])
            del activation['unmanaged_digest_version']
            activation['unmanaged_sha256'] = self.live_digest(observation.UNMANAGED_DIGEST_V1)
            self.record['activation'] = activation
            self.persist()
            self.assertEqual('PREPARED', self.classify()['phase'])

    def test_09b_v1_and_v2_digests_actually_differ(self):
        """Guards the downgrade test below from being vacuous."""
        with self.in_range_identity():
            self.build()
            self.assertNotEqual(self.live_digest(observation.UNMANAGED_DIGEST_V1),
                                self.live_digest(observation.UNMANAGED_DIGEST_V2))

    def test_11_v1_tamper_rejected(self):
        self.build()
        activation = dict(self.record['activation'])
        del activation['unmanaged_digest_version']
        activation['unmanaged_sha256'] = 'a' * 64
        self.record['activation'] = activation
        self.persist()
        with self.assertRaises(txn.JournalError):
            self.classify()

    def test_12_v2_tamper_rejected(self):
        self.build()
        self.rewrite_activation(unmanaged_sha256='a' * 64)
        with self.assertRaises(txn.JournalError):
            self.classify()

    def test_13_unknown_version_rejected(self):
        """Refused by the writer, and independently refused by the reader."""
        self.build()
        with self.assertRaises(txn.JournalError):
            self.rewrite_activation(unmanaged_digest_version=3)
        # reader side: a journal already on disk carrying an unknown marker
        self.record['activation'] = dict(self.record['activation'],
                                         unmanaged_digest_version=3)
        self.persist_raw()
        with self.assertRaises(txn.JournalError):
            self.classify()

    def test_13b_boolean_version_marker_rejected(self):
        """True == 1 in Python, so the marker must be type-checked, not just compared."""
        self.build()
        with self.assertRaises(txn.JournalError):
            self.rewrite_activation(unmanaged_digest_version=True)
        self.record['activation'] = dict(self.record['activation'],
                                         unmanaged_digest_version=True)
        self.persist_raw()
        with self.assertRaises(txn.JournalError):
            self.classify()

    def test_13c_string_version_marker_rejected(self):
        self.build()
        self.record['activation'] = dict(self.record['activation'],
                                         unmanaged_digest_version='2')
        self.persist_raw()
        with self.assertRaises(txn.JournalError):
            self.classify()

    def test_14_v2_mismatch_cannot_downgrade_to_v1(self):
        """The security rule: a version-2 record carrying a version-1 digest.

        A naive implementation that tried version 2 and then fell back to version 1
        would accept this. It must refuse.
        """
        with self.in_range_identity():
            self.build()
            self.rewrite_activation(
                unmanaged_sha256=self.live_digest(observation.UNMANAGED_DIGEST_V1))
            with self.assertRaises(txn.JournalError) as caught:
                self.classify()
            self.assertIn('unmanaged state changed', str(caught.exception))

    def test_14b_dropping_the_marker_does_not_validate_a_v2_digest(self):
        """Stripping the marker must not turn a version-2 digest into a valid one."""
        self.build()
        activation = dict(self.record['activation'])
        del activation['unmanaged_digest_version']
        self.record['activation'] = activation
        self.persist()
        with self.assertRaises(txn.JournalError):
            self.classify()

    def test_10b_v2_ignores_a_legacy_digest_domain_swap(self):
        """Marker and digest must agree; swapping only the marker is refused."""
        with self.in_range_identity():
            self.build()
            activation = dict(self.record['activation'])
            activation['unmanaged_sha256'] = self.live_digest(observation.UNMANAGED_DIGEST_V1)
            activation['unmanaged_digest_version'] = 1
            self.record['activation'] = activation
            self.persist()
            # A record that declares version 1 is validated as version 1, so this one
            # is internally consistent and must be accepted; the refusal case is 14.
            self.assertEqual('PREPARED', self.classify()['phase'])


def independent_legacy_rows(root):
    """Reproduce the pre-versioning observation rows of a live tree.

    Before the stamp encoding was versioned, `file_observation` put the raw
    seven-integer stamp into the row identity. This rebuilds those rows directly
    -- `_read_file` for the file stamp, `directory_identity` for a directory,
    `plain_path` for the mode -- rather than calling
    `tree_observation`/`child_observation`/`legacy_file_identities`.
    """
    rows = []

    def visit(path):
        _, info = binding.plain_path(path)
        relative = '.' if path == root else path.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):
            rows.append({'path': relative, 'mode': stat.S_IMODE(info.st_mode),
                         'type': 'directory', 'identity': binding.directory_identity(path)})
            for child in sorted(path.iterdir(), key=lambda item: item.name.encode('utf-8')):
                visit(child)
        else:
            data, identity = binding._read_file(path, binding.MAX_FILE)
            rows.append({'path': relative, 'mode': stat.S_IMODE(info.st_mode), 'type': 'file',
                         'identity': list(identity),
                         'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)})

    visit(root)
    return rows


def independent_legacy_child_digest(root):
    """Recompute the pre-versioning child digest without the versioning code."""
    return hashlib.sha256(b'accp-activation-child-v1\x00'
                          + binding.canonical_json(independent_legacy_rows(root))).hexdigest()


def independent_legacy_unmanaged_digest(root, owned):
    """Recompute the pre-versioning unmanaged digest without the versioning code.

    Same exclusion rule as `unmanaged_observation`: drop the root row and every
    row whose first path segment is an owned child.
    """
    selected = [row for row in independent_legacy_rows(root)
                if row['path'] != '.' and row['path'].split('/')[0] not in owned]
    return hashlib.sha256(b'accp-activation-unmanaged-v1\x00'
                          + binding.canonical_json(selected)).hexdigest()


class ObservationDigestVersionTests(ActivationFixture):
    """The child-observation digest is versioned separately from the unmanaged digest.

    Every persisted `observation_sha256` is recomputed from live data -- on the
    forward/apply path, the rollback path, terminal classification and
    non-terminal classification -- and the version-2 stamp encoding changed its
    value for every file. A journal written before that change carries legacy
    child digests and must stay readable.

    The two digest domains are versioned independently: neither marker is
    inferred from the other, and neither encoding is ever retried as the other.
    """

    def legacy_child(self, path):
        return independent_legacy_child_digest(path)

    def as_legacy_journal(self):
        """Rewrite the record into what the pre-versioning writer persisted.

        Both domains become legacy: children are digested with the raw-integer
        encoding and the unmanaged digest is recomputed as version 1, with both
        markers absent.
        """
        self.record.pop('observation_digest_version', None)
        for key, generation in (('old_children', 'old'), ('new_children', 'new')):
            for ident, value in self.record[key].items():
                if value == {'prepared': False}:
                    continue
                path = self.locate(ident, generation)
                self.assertIsNotNone(path, f'{key}[{ident}] has no live object')
                value['observation_sha256'] = independent_legacy_child_digest(path)
        activation = dict(self.record['activation'])
        activation.pop('unmanaged_digest_version', None)
        activation['unmanaged_sha256'] = independent_legacy_unmanaged_digest(
            self.skills, self.union())
        self.record['activation'] = activation
        self.persist()
        return self.record

    def pin_cleanup_identities(self):
        """Align file cleanup entries with the pinned stamp source.

        The fixture builds cleanup entries from Path.stat(), while the classifier
        re-reads them through binding._read_file, which in_range_identity() pins.
        Under the pin the two disagree, so a CLEANING record would be refused for
        a reason unrelated to versioning. Only file entries are affected:
        directory entries are verified through directory_identity(), which the pin
        does not touch. Cleanup identities are not a versioned digest domain.
        """
        for entry in self.record.get('cleanup_entries', []):
            if entry['type'] != 'file':
                continue
            path = self.workspace / entry['area'] / entry['id']
            if entry['relative'] != '.':
                path = path / entry['relative']
            _, stamp = binding._read_file(path, binding.MAX_FILE)
            entry['identity'] = {'device': str(stamp[0]), 'inode': str(stamp[1])}

    def legacy_then_prepared(self):
        self.build(prepared=True)
        self.as_legacy_journal()
        return self.record

    def legacy_then_cleaning(self):
        self.build(prepared=True)
        self.committed()
        self.cleanup_record('committed')
        self.pin_cleanup_identities()
        self.as_legacy_journal()
        return self.record

    # --- CONTROL -----------------------------------------------------------

    def test_01_legacy_encoding_round_trips_on_both_sides(self):
        """Control: a journal written AND read under the legacy encoding is valid."""
        with self.in_range_identity():
            record = self.legacy_then_prepared()
            self.assertNotIn('observation_digest_version', record)
            self.assertEqual(observation.OBSERVATION_DIGEST_V1,
                             txn.observation_digest_version(record))
            self.assertEqual('PREPARED', self.classify()['phase'])

    def test_02_current_writer_and_reader_round_trip(self):
        """Control: the current encoding round-trips."""
        self.build(prepared=True)
        self.assertEqual(observation.OBSERVATION_DIGEST_V2,
                         txn.observation_digest_version(self.record))
        self.assertEqual('PREPARED', self.classify()['phase'])

    # --- CROSS-VERSION -----------------------------------------------------

    def test_03_faithful_legacy_prepared_journal_is_accepted(self):
        """A legacy PREPARED journal must classify, not merely validate."""
        with self.in_range_identity():
            self.legacy_then_prepared()
            result = self.classify()
            self.assertEqual('PREPARED', result['phase'])
            self.assertEqual('rollback', result['action'])

    def test_04_faithful_legacy_cleaning_journal_is_accepted(self):
        """A legacy terminal journal must classify."""
        with self.in_range_identity():
            self.legacy_then_cleaning()
            result = self.classify()
            self.assertEqual('CLEANING', result['phase'])
            self.assertEqual('committed', result['outcome'])

    def test_05_legacy_journal_forward_recomputation_is_accepted(self):
        """The forward/apply predicate accepts a legacy record.

        The forward path evaluates `_activation_child(source, version) ==
        record[generation + '_children'][ident]`. This asserts exactly that
        expression against the version the record declares.
        """
        with self.in_range_identity():
            record = self.legacy_then_prepared()
            version = txn.observation_digest_version(record)
            self.assertEqual(observation.OBSERVATION_DIGEST_V1, version)
            for generation in ('old', 'new'):
                for ident in record[generation + '_ids']:
                    source = self.locate(ident, generation)
                    self.assertIsNotNone(source)
                    self.assertEqual(record[generation + '_children'][ident],
                                     self.owner._activation_child(source, version),
                                     f'forward recomputation refused {generation}/{ident}')

    def test_06_legacy_journal_terminal_classification_is_accepted(self):
        with self.in_range_identity():
            self.legacy_then_cleaning()
            self.assertEqual('CLEANING', self.classify()['phase'])

    def test_07_legacy_journal_non_terminal_classification_is_accepted(self):
        with self.in_range_identity():
            self.legacy_then_prepared()
            self.assertEqual('PREPARED', self.classify()['phase'])

    # --- V2 ----------------------------------------------------------------

    def test_08_v2_round_trip_succeeds(self):
        self.build(prepared=True)
        self.assertEqual('PREPARED', self.classify()['phase'])

    def test_09_v2_child_digest_tamper_is_rejected(self):
        self.build(prepared=True)
        ident = self.record['new_ids'][0]
        self.record['new_children'][ident]['observation_sha256'] = 'a' * 64
        self.persist()
        self.refuse()

    def test_10_removing_the_v2_child_marker_does_not_downgrade(self):
        """Absence means legacy, so a version-2 digest must not validate as it."""
        self.build(prepared=True)
        del self.record['observation_digest_version']
        self.persist()
        self.refuse()

    def test_11_v2_child_digest_with_v1_marker_is_rejected(self):
        with self.in_range_identity():
            self.build(prepared=True)
            self.record['observation_digest_version'] = observation.OBSERVATION_DIGEST_V1
            self.persist()
            self.refuse()

    def test_12_v1_child_digest_with_v2_marker_is_rejected(self):
        with self.in_range_identity():
            self.legacy_then_prepared()
            self.record['observation_digest_version'] = observation.OBSERVATION_DIGEST_V2
            self.persist()
            self.refuse()

    # --- VERSION INPUT -----------------------------------------------------

    def test_13_unknown_child_version_is_rejected(self):
        for bad in (0, 3, -1, 99):
            with self.subTest(version=bad):
                with self.assertRaises(txn.JournalError):
                    txn.observation_digest_version({'observation_digest_version': bad})

    def test_14_string_child_version_is_rejected(self):
        with self.assertRaises(txn.JournalError):
            txn.observation_digest_version({'observation_digest_version': '2'})

    def test_15_float_child_version_is_rejected(self):
        with self.assertRaises(txn.JournalError):
            txn.observation_digest_version({'observation_digest_version': 2.0})

    def test_16_bool_child_version_is_rejected(self):
        """`True == 1` in Python, so a bool must never satisfy an int version test."""
        with self.assertRaises(txn.JournalError):
            txn.observation_digest_version({'observation_digest_version': True})

    def test_17_zero_and_negative_child_versions_refused_at_serialize(self):
        self.build(prepared=True)
        for bad in (0, -1):
            with self.subTest(version=bad):
                self.record['observation_digest_version'] = bad
                with self.assertRaises(txn.JournalError):
                    self.owner.serialize(self.record)

    # --- INDEPENDENCE ------------------------------------------------------

    def test_18_unmanaged_v2_does_not_force_the_child_domain_to_v2(self):
        """Correct unmanaged V2 must not drag the child domain to V2.

        The child marker is absent, so the child domain is version 1 and the
        legacy child digests are correct: the record must be accepted. Inferring
        the child version from the unmanaged version would refuse it.
        """
        with self.in_range_identity():
            self.legacy_then_prepared()
            self.record['activation'] = dict(
                self.record['activation'],
                unmanaged_digest_version=observation.UNMANAGED_DIGEST_V2,
                unmanaged_sha256=self.live_digest(observation.UNMANAGED_DIGEST_V2))
            self.persist()
            self.assertEqual('PREPARED', self.classify()['phase'])

    def test_18b_unmanaged_v2_with_v2_child_marker_over_legacy_children_is_rejected(self):
        with self.in_range_identity():
            self.legacy_then_prepared()
            self.record['activation'] = dict(
                self.record['activation'],
                unmanaged_digest_version=observation.UNMANAGED_DIGEST_V2,
                unmanaged_sha256=self.live_digest(observation.UNMANAGED_DIGEST_V2))
            self.record['observation_digest_version'] = observation.OBSERVATION_DIGEST_V2
            self.persist()
            self.refuse()

    def test_19_legacy_unmanaged_compatibility_still_works(self):
        with self.in_range_identity():
            self.legacy_then_prepared()
            self.assertEqual(1, txn.unmanaged_digest_version(self.record['activation']))
            self.assertEqual('PREPARED', self.classify()['phase'])

    def test_20_the_two_domains_are_independently_versioned(self):
        """Each domain's version selects only its own encoding."""
        with self.in_range_identity():
            self.build(prepared=True)
            rows = observation.tree_observation(self.skills)
            owned = self.union()
            child_v1 = observation.child_observation(rows, observation.OBSERVATION_DIGEST_V1)
            child_v2 = observation.child_observation(rows, observation.OBSERVATION_DIGEST_V2)
            unmanaged_v1 = observation.unmanaged_observation(rows, owned,
                                                             observation.UNMANAGED_DIGEST_V1)
            unmanaged_v2 = observation.unmanaged_observation(rows, owned,
                                                             observation.UNMANAGED_DIGEST_V2)
            # Each domain is genuinely version-sensitive ...
            self.assertNotEqual(child_v1, child_v2)
            self.assertNotEqual(unmanaged_v1, unmanaged_v2)
            # ... and the domains do not collide with one another.
            self.assertNotEqual(child_v1, unmanaged_v1)
            self.assertNotEqual(child_v2, unmanaged_v2)
            # Each function refuses the other domain's marker rather than
            # silently interpreting it.
            with self.assertRaises(binding.BindingError):
                observation.child_observation(rows, 3)
            with self.assertRaises(binding.BindingError):
                observation.unmanaged_observation(rows, owned, 3)
            # Both markers may coexist on one record and are read separately.
            self.assertEqual('PREPARED', self.classify()['phase'])
            self.assertEqual(observation.OBSERVATION_DIGEST_V2,
                             txn.observation_digest_version(self.record))
            self.assertEqual(observation.UNMANAGED_DIGEST_V2,
                             txn.unmanaged_digest_version(self.record['activation']))


if __name__ == '__main__': unittest.main()
