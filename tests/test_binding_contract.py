"""F06 M1 cross-record and boundary oracles; no CLI admission integration."""
import copy
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import artifact_binding as ab


class BindingContract(unittest.TestCase):
    def setUp(self):
        local = pathlib.Path(__file__).resolve().parents[1] / '.local' / 'audit-temp'
        local.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='f06-contract-', dir=local)
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.catalog = {'id': 'demo', 'source_url': 'https://example.invalid/Source',
                        'deploy': {'path': 'skill'}, 'invocation': 'explicit', 'notes': 'reviewed'}
        self.payload = {'SKILL.md': b'approved\n', 'agents/openai.yaml': b'policy: {}\n'}
        source = ab.payload_inventory(self.payload)
        artifact = ab.projected_inventory(source, 'explicit')
        b = {'binding_version': 1, 'source_id': 'demo', 'catalog_sha256': ab.catalog_digest(self.catalog),
             'origin': ab.canonical_origin(self.catalog['source_url']), 'commit': '1' * 40,
             'source_tree_oid': '2' * 40, 'deploy_path': 'skill', 'invocation': 'explicit',
             'projection': ab.PROJECTION, 'source_tree_sha256': ab.digest('accp-source-tree-v1', source),
             'artifact_tree_sha256': ab.digest('accp-artifact-tree-v1', artifact)}
        self.evidence = {'schema_version': 2, 'candidate': b, 'candidate_sha256': ab.digest('accp-candidate-v1', b),
             'source_inventory': source, 'artifact_inventory': artifact, 'status': 'approved',
             'reviewer': 'fixture', 'reviewed_at': '2026-09-16T00:00:00Z', 'notes': '', 'executable_surface': []}
        ep = self.root / 'audit/evidence/demo.json'
        ep.parent.mkdir(parents=True)
        self.raw = ab.encode_evidence(self.evidence)
        ep.write_bytes(self.raw)
        self.lock = {'repo': self.catalog['source_url'], 'commit': b['commit'], 'deploy_path': 'skill',
                     'evidence': 'audit/evidence/demo.json', 'evidence_sha256': hashlib.sha256(self.raw).hexdigest(),
                     'approval': {'partial_or_conditional': False, 'high_risk': False},
                     'binding': {'schema_version': 1, 'candidate_sha256': self.evidence['candidate_sha256']}}

    def make_vault(self):
        runtime = self.root / 'runtime'
        provider = runtime / 'vault/skills/demo'
        provider.mkdir(parents=True)
        rb = {'runtime_id': '12345678-1234-4234-8234-123456789abc',
              'runtime_path': os.path.normcase(str(runtime)), 'control_plane_path': os.path.normcase(str(self.root)),
              'principal': 'uid:0', 'root_identity': ab.directory_identity(runtime),
              'vault_identity': ab.directory_identity(runtime / 'vault')}
        for name, data in ab.project_invocation(self.payload, 'explicit').items():
            path = provider / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        manifest = {'schema_version': 2, 'source_id': 'demo', 'candidate_sha256': self.evidence['candidate_sha256'],
                    'evidence_sha256': self.lock['evidence_sha256'],
                    'artifact_tree_sha256': self.evidence['candidate']['artifact_tree_sha256'],
                    'invocation': 'explicit', 'projection': ab.PROJECTION, 'runtime_binding': rb,
                    'materialized_at': '2026-09-16T00:00:00Z'}
        (provider / ab.MANIFEST).write_bytes(ab.canonical_json(manifest) + b'\n')
        return provider, rb, manifest

    def test_record_proof_uses_exact_bytes_and_current_complete_catalog(self):
        snapshot = ab.load_review_binding(self.root, 'demo', self.catalog, self.lock)
        self.assertEqual(snapshot.data, self.raw)
        self.assertEqual(snapshot.sha256, self.lock['evidence_sha256'])
        for field, value in [('id', 'other'), ('source_url', 'https://example.invalid/source'),
                             ('deploy', {'path': 'different'}), ('invocation', 'implicit'), ('notes', 'changed')]:
            entry = dict(self.catalog, **{field: value})
            with self.subTest(field=field), self.assertRaises(ab.BindingError):
                ab.load_review_binding(self.root, 'demo', entry, self.lock)

    def test_each_lock_binding_substitution_and_legacy_are_denied(self):
        changes = {'repo': 'https://example.invalid/Other', 'commit': '3' * 40, 'deploy_path': 'other',
                   'evidence': 'audit/evidence/other.json', 'evidence_sha256': '4' * 64,
                   'binding': {'schema_version': 1, 'candidate_sha256': '5' * 64}}
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaises((ab.BindingError, FileNotFoundError)):
                ab.load_review_binding(self.root, 'demo', self.catalog, dict(self.lock, **{field: value}))
        legacy = dict(self.lock); del legacy['binding']
        self.assertEqual(ab.validate_lock_record(legacy), legacy)
        with self.assertRaisesRegex(ab.BindingError, 'legacy'):
            ab.load_review_binding(self.root, 'demo', self.catalog, legacy)

    def test_pending_and_noncanonical_rehashed_evidence_never_grant_authority(self):
        pending = dict(self.evidence, status='pending')
        ep = self.root / self.lock['evidence']
        data = ab.encode_evidence(pending); ep.write_bytes(data)
        lock = dict(self.lock, evidence_sha256=hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(ab.BindingError, 'not approved'):
            ab.load_review_binding(self.root, 'demo', self.catalog, lock)
        data = json.dumps(self.evidence, indent=2).encode() + b'\n'; ep.write_bytes(data)
        lock['evidence_sha256'] = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(ab.BindingError, 'noncanonical'):
            ab.load_review_binding(self.root, 'demo', self.catalog, lock)

    def test_unknown_missing_wrong_version_and_type_fields(self):
        for original, validator in [(self.evidence, ab.validate_evidence),
                (self.evidence['candidate'], ab.validate_candidate), (self.lock, ab.validate_lock_record)]:
            for key in original:
                bad = copy.deepcopy(original); del bad[key]
                # The only intentionally representable omission is legacy binding.
                if original is self.lock and key == 'binding':
                    continue
                with self.subTest(key=key), self.assertRaises(ab.BindingError): validator(bad)
            with self.assertRaises(ab.BindingError): validator(dict(original, unknown=True))
        for value in (None, True, 1, '2', 3):
            with self.subTest(version=value), self.assertRaises(ab.BindingError):
                ab.validate_evidence(dict(self.evidence, schema_version=value))
        for value in (None, 1, 'true', [], {}):
            bad = copy.deepcopy(self.lock); bad['approval']['high_risk'] = value
            with self.subTest(approval=value), self.assertRaises(ab.BindingError): ab.validate_lock_record(bad)

    def test_vault_expected_digest_is_external_not_self_rehashed(self):
        provider, rb, manifest = self.make_vault()
        self.assertEqual(ab.validate_vault_binding(provider, self.evidence, self.lock['evidence_sha256'], rb), manifest)
        (provider / 'SKILL.md').write_bytes(b'forged')
        manifest['artifact_tree_sha256'] = ab.digest('accp-artifact-tree-v1', ab.inventory_tree(provider, vault=True))
        (provider / ab.MANIFEST).write_bytes(ab.canonical_json(manifest) + b'\n')
        with self.assertRaisesRegex(ab.BindingError, 'artifact_tree_sha256'):
            ab.validate_vault_binding(provider, self.evidence, self.lock['evidence_sha256'], rb)

    def test_vault_parsed_evidence_cannot_drift_from_authoritative_bytes(self):
        provider, rb, _ = self.make_vault()
        changed = dict(self.evidence, notes='changed after read')
        with self.assertRaisesRegex(ab.BindingError, 'bound bytes'):
            ab.validate_vault_binding(provider, changed, self.lock['evidence_sha256'], rb)

    def test_vault_manifest_replacement_after_inventory_is_refused(self):
        provider, rb, manifest = self.make_vault()
        original = ab.inventory_tree
        def replace_after_inventory(*args, **kwargs):
            inventory = original(*args, **kwargs)
            replacement = dict(manifest, materialized_at='2026-09-16T00:00:01Z')
            path = provider / ab.MANIFEST
            path.rename(provider / 'retained-original')
            path.write_bytes(ab.canonical_json(replacement) + b'\n')
            return inventory
        with mock.patch.object(ab, 'inventory_tree', side_effect=replace_after_inventory):
            with self.assertRaisesRegex(ab.BindingError, 'manifest changed'):
                ab.validate_vault_binding(provider, self.evidence, self.lock['evidence_sha256'], rb)
        self.assertEqual((provider / 'retained-original').read_bytes(), ab.canonical_json(manifest) + b'\n')

    def test_vault_foreign_runtime_identity_and_missing_unknown_fields(self):
        provider, rb, manifest = self.make_vault()
        wrong = copy.deepcopy(rb); wrong['vault_identity']['inode'] = '999999999'
        with self.assertRaisesRegex(ab.BindingError, 'identity'):
            ab.validate_vault_binding(provider, self.evidence, self.lock['evidence_sha256'], wrong)
        for key in manifest:
            bad = dict(manifest); del bad[key]
            with self.subTest(key=key), self.assertRaises(ab.BindingError): ab.validate_vault_manifest(bad)
        with self.assertRaises(ab.BindingError): ab.validate_vault_manifest(dict(manifest, unknown=True))

    def test_evidence_path_overlap_absolute_and_hardlink(self):
        with self.assertRaisesRegex(ab.BindingError, 'overlap'):
            ab.evidence_path(self.root, 'demo', [self.root / 'audit'])
        for value in (str(self.root / self.lock['evidence']), '../outside', 'audit/evidence/../demo.json'):
            with self.subTest(value=value), self.assertRaises(ab.BindingError):
                ab.load_review_binding(self.root, 'demo', self.catalog, dict(self.lock, evidence=value))
        alias = self.root / 'alias'; os.link(self.root / self.lock['evidence'], alias)
        with self.assertRaisesRegex(ab.BindingError, 'hard-linked'):
            ab.load_review_binding(self.root, 'demo', self.catalog, self.lock)

    def test_inventory_topology_collision_extras_and_projection_only_changes_policy(self):
        for payload in ({'a': b'x', 'a/b': b'y'}, {'A': b'x', 'a': b'y'}, {'\u00e9': b'x', 'e\u0301': b'y'}):
            with self.subTest(payload=payload), self.assertRaises(ab.BindingError): ab.payload_inventory(payload)
        for path in ('CONIN$', 'COM\u00b9', 'x/.GIT/config', 'x/.accp-vault-manifest.json'):
            with self.subTest(path=path), self.assertRaises(ab.BindingError): ab.canonical_relative_path(path)
        bad = copy.deepcopy(self.evidence)
        bad['artifact_inventory'][0]['sha256'] = '0' * 64
        bad['candidate']['artifact_tree_sha256'] = ab.digest('accp-artifact-tree-v1', bad['artifact_inventory'])
        bad['candidate_sha256'] = ab.digest('accp-candidate-v1', bad['candidate'])
        with self.assertRaisesRegex(ab.BindingError, 'projection'): ab.validate_evidence(bad)
        source = ab.payload_inventory(self.payload) + [{'path': 'empty', 'type': 'directory'}]
        self.assertIn({'path': 'empty', 'type': 'directory'}, ab.projected_inventory(source, 'explicit'))

    def test_hash_consistent_but_incomplete_source_is_not_review_evidence(self):
        record = copy.deepcopy(self.evidence)
        record['source_inventory'] = []
        record['artifact_inventory'] = ab.projected_inventory([], 'explicit')
        record['candidate']['source_tree_sha256'] = ab.digest('accp-source-tree-v1', [])
        record['candidate']['artifact_tree_sha256'] = ab.digest('accp-artifact-tree-v1', record['artifact_inventory'])
        record['candidate_sha256'] = ab.digest('accp-candidate-v1', record['candidate'])
        with self.assertRaisesRegex(ab.BindingError, 'SKILL.md'): ab.validate_evidence(record)

    def test_json_and_path_exact_limits_without_large_disk_fixtures(self):
        self.assertEqual(ab.parse_json(b'{}', limit=2), {})
        with self.assertRaises(ab.BindingError): ab.parse_json(b'{} ', limit=2)
        self.assertEqual(ab.parse_json(b'[' * 32 + b'0' + b']' * 32), self.nested(32))
        with self.assertRaises(ab.BindingError): ab.parse_json(b'[' * 33 + b'0' + b']' * 33)
        self.assertEqual(ab.canonical_relative_path('/'.join(['a'] * 32)), '/'.join(['a'] * 32))
        with self.assertRaises(ab.BindingError): ab.canonical_relative_path('/'.join(['a'] * 33))
        ab.canonical_relative_path('x' * 1024)
        with self.assertRaises(ab.BindingError): ab.canonical_relative_path('x' * 1025)
        with self.assertRaises(ab.BindingError): ab.parse_json(b'9223372036854775808')
        self.assertEqual(ab.parse_json(b'9223372036854775807'), 2**63 - 1)
        for raw in (b'{"x":{"id":1,"id":2}}', b'{"x":NaN}', b'{"x":1e999}', b'{"x":1.0}', b'{"x":"\\ud800"}'):
            with self.subTest(raw=raw), self.assertRaises(ab.BindingError): ab.parse_json(raw)
        # Test the real encoded byte cap, not just a mocked tiny equivalent.
        data = b'"' + b'x' * (ab.MAX_RECORD - 2) + b'"'
        self.assertEqual(len(ab.parse_json(data)), ab.MAX_RECORD - 2)
        with self.assertRaises(ab.BindingError): ab.parse_json(data + b' ')
        with self.assertRaises(ab.BindingError): ab.parse_json(b'{}', canonical='yes')
        entry = {'x': ''}; overhead = len(ab.canonical_json(entry))
        entry['x'] = 'x' * (ab.MAX_ENTRY - overhead)
        ab.catalog_digest(entry)
        entry['x'] += 'x'
        with self.assertRaises(ab.BindingError): ab.catalog_digest(entry)

    def test_origin_and_native_absolute_spelling_matrix(self):
        for url in ('https://EXAMPLE.invalid/a', 'https://example.invalid:443/a',
                    'https://example.invalid:01/a', 'https://example.invalid/a/../b',
                    'https://example.invalid/a"b', 'https://example.invalid/a%2fb',
                    'file://server/share', 'file:///C:relative', 'file:///C:/a/../b'):
            with self.subTest(url=url), self.assertRaises(ab.BindingError): ab.canonical_origin(url)
        self.assertNotEqual(ab.canonical_origin('https://example.invalid/A'),
                            ab.canonical_origin('https://example.invalid/a'))
        self.assertNotEqual(ab.canonical_origin('https://example.invalid/a.git'),
                            ab.canonical_origin('https://example.invalid/a'))
        for path in ('C:relative', r'\\server\share\x', r'\\?\C:\x', r'\\.\C:\x'):
            with self.subTest(path=path), self.assertRaises(ab.BindingError): ab.plain_path(path)

    @staticmethod
    def nested(count):
        result = 0
        for _ in range(count): result = [result]
        return result

    def test_inventory_size_and_count_boundaries(self):
        def files(count, size):
            return [{'path': f'f{i:05}', 'type': 'file', 'size': size, 'sha256': '0' * 64} for i in range(count)]
        ab.validate_inventory(files(8, ab.MAX_FILE))
        with self.assertRaises(ab.BindingError): ab.validate_inventory(files(9, ab.MAX_FILE))
        with self.assertRaises(ab.BindingError): ab.validate_inventory(files(1, ab.MAX_FILE + 1))
        ab.validate_inventory(files(ab.MAX_ENTRIES, 0))
        with self.assertRaises(ab.BindingError): ab.validate_inventory(files(ab.MAX_ENTRIES + 1, 0))
        with self.assertRaises(ab.BindingError): ab.validate_inventory(files(1, True))

    def test_file_origin_identity_replacement_and_native_stream_api_failure(self):
        origin = self.root / 'origin'; origin.mkdir()
        binding = ab.file_origin(origin)
        origin.rename(self.root / 'old-origin'); origin.mkdir()
        with self.assertRaisesRegex(ab.BindingError, 'changed'): ab.validate_origin(binding, observe=True)
        if os.name == 'nt':
            with mock.patch.object(ab, '_streams', side_effect=ab.BindingError('unavailable')):
                with self.assertRaises(ab.BindingError): ab.inventory_tree(origin)

    def test_schema_field_sets_and_local_references_resolve(self):
        base = pathlib.Path(__file__).resolve().parents[1] / 'schemas'
        evidence = json.loads((base / 'evidence.schema.json').read_text())
        vault = json.loads((base / 'vault-manifest.schema.json').read_text())
        self.assertEqual(set(evidence['required']), ab.EVIDENCE_FIELDS)
        self.assertEqual(set(evidence['$defs']['candidate']['required']), ab.CANDIDATE_FIELDS)
        self.assertEqual(set(vault['required']), ab.VAULT_FIELDS)
        self.assertEqual(set(evidence['$defs']['runtimeBinding']['required']), ab.RUNTIME_FIELDS)
        def visit(value, document):
            if isinstance(value, dict):
                if '$ref' in value:
                    filename, fragment = value['$ref'].split('#', 1)
                    target = json.loads((base / filename).read_text()) if filename else document
                    for part in fragment.lstrip('/').split('/'): target = target[part]
                for child in value.values(): visit(child, document)
            elif isinstance(value, list):
                for child in value: visit(child, document)
        visit(evidence, evidence); visit(vault, vault)


if __name__ == '__main__':
    unittest.main()
