"""A4 deterministic faults against the real forward producer; local fixtures only.

Each generated case asserts its hook fires. Expected inspection cuts are declared
in the matrix, never inferred from an exception. No production fault switches.
"""
import io
import json
import os
from pathlib import Path
from contextlib import contextmanager, ExitStack
import sys
import unittest
from unittest import mock

# Discovery imports this module before any sibling has put scripts/ on sys.path.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import accp
import active_transaction as txn
import artifact_binding as ab
import test_activation_forward as forward


def publication_name(record):
    phase = record['phase']
    if phase == 'PREPARING':
        if record['workspace_identity'] is None: return 'begin'
        prepared = [i for i in record['new_ids'] if record['new_children'][i] != {'prepared': False}]
        return 'prefix-' + prepared[-1] if prepared else 'workspace-register'
    if phase == 'APPLYING' and record['skills_created_identity'] is not None:
        return 'skills-register'
    return phase.lower()


class ActivationFaults(unittest.TestCase):
    setUp = forward.ActivationForward.setUp
    activate = forward.ActivationForward.activate
    recover = forward.ActivationForward.recover
    live = forward.ActivationForward.live
    old = forward.ActivationForward.old

    def second_provider(self):
        self.f.write_resolver_fixture([self.f.entry(), self.f.entry('other')],
                                      seed=['other', 'fixture'])
        # Rewrite both manifests after producing fresh (independently valid) reviews.
        for ident in ('fixture', 'other'):
            root = accp.VAULT / ident; root.mkdir(exist_ok=True)
            payload = {'SKILL.md': ('---\nname: %s\ndescription: fixture\n---\n' % ident).encode()}
            for rel, raw in ab.project_invocation(payload, 'explicit').items():
                path = root / rel; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            evidence = ab.decode_evidence((self.f.evidence_dir / (ident + '.json')).read_bytes())
            lock = accp.lock_index(strict=True)[ident]
            manifest = dict(schema_version=2, source_id=ident,
                candidate_sha256=evidence['candidate_sha256'], evidence_sha256=lock['evidence_sha256'],
                artifact_tree_sha256=evidence['candidate']['artifact_tree_sha256'], invocation='explicit',
                projection=ab.PROJECTION, runtime_binding=self.f.fixture_rb,
                materialized_at='2026-09-16T00:00:00Z')
            (root / '.accp-vault-manifest.json').write_bytes(ab.canonical_json(manifest) + b'\n')

    def snapshot(self):
        return self.f.tree(self.f.root)

    def assert_original(self, before):
        after = self.live()
        self.assertEqual(before['tree'], after['tree'])  # directory/file objects, bytes, modes
        for key in ('manifest', 'state'):
            self.assertEqual(before[key] is None, after[key] is None)
            if before[key] is not None: self.assertEqual(before[key]['sha256'], after[key]['sha256'])

    @contextmanager
    def fault(self, target, after, fired):
        def hit():
            fired.append(target)
            raise KeyboardInterrupt('A4 deterministic cut ' + target)
        def around(original, label, *args, **kwargs):
            match = label == target
            if match and not after: hit()
            result = original(*args, **kwargs)
            if match and after: hit()
            return result
        mkdir = Path.mkdir; replace = os.replace; copy = accp.shutil.copytree
        journal = txn.JournalAuthority.publish_journal
        locator = txn.JournalAuthority.publish_locator
        bounds = txn.JournalAuthority._project_activation_cleanup
        lock = txn.JournalAuthority.lifecycle_lock
        def make(path, *args, **kwargs):
            if path == self.paths[0]: label = 'enroll'
            elif path == self.paths[1]: label = 'skills-create'
            elif path.name.startswith('.accp-txn-'): label = 'allocate-root'
            elif path.parent.name.startswith('.accp-txn-'): label = 'allocate-' + path.name
            else: label = ''
            return around(mkdir, label, path, *args, **kwargs)
        def publish(owner, record, previous=None):
            return around(journal, publication_name(record), owner, record, previous)
        def locate(owner, record): return around(locator, 'locator', owner, record)
        def project(owner, record): return around(bounds, 'bounds', owner, record)
        def copying(source, target_path, *args, **kwargs):
            path = Path(target_path)
            label = 'copy-' + path.name if path.parent.name == 'new' else ''
            return around(copy, label, source, target_path, *args, **kwargs)
        def move(source, target_path):
            path = Path(target_path)
            if path.parent.name == 'old': label = 'old-' + path.name
            elif path.parent == self.paths[1]: label = 'new-' + path.name
            else: label = ''
            return around(replace, label, source, target_path)
        @contextmanager
        def locking(owner, create=True):
            if target == 'lock' and not after: hit()
            with lock(owner, create):
                if target == 'lock' and after: hit()
                yield owner
        with ExitStack() as stack:
            for obj, name, fn in ((Path, 'mkdir', make), (os, 'replace', move),
                    (accp.shutil, 'copytree', copying), (txn.JournalAuthority, 'publish_journal', publish),
                    (txn.JournalAuthority, 'publish_locator', locate),
                    (txn.JournalAuthority, '_project_activation_cleanup', project),
                    (txn.JournalAuthority, 'lifecycle_lock', locking)):
                stack.enter_context(mock.patch.object(obj, name, fn))
            yield

    def outcome(self, before, expected):
        self.assertFalse(accp._activation_attempts)
        if self.owner.lock_path.exists():
            with self.owner.lifecycle_lock(create=False): pass  # no leaked OS ownership
        if expected == 'untouched':
            self.assert_original(before); self.assertFalse(self.owner.journal.exists()); return
        if expected == 'inspection':
            evidence = self.snapshot()
            for cleanup in (False, True, False):
                with self.assertRaises((txn.JournalError, ab.BindingError)): self.recover(cleanup)
                self.assertEqual(evidence, self.snapshot())
            # Every original child object is still present exactly once, even in ambiguous state.
            for row in before['tree'] or []:
                if row['path'] and row['type'] == 'directory':
                    matches = [p for p in self.paths[0].rglob('*') if p.is_dir()
                               and ab.directory_identity(p) == row['identity']]
                    self.assertEqual(1, len(matches), row['path'])
            return
        if expected == 'commit':
            committed = self.live()
            self.assertTrue(self.recover()['committed']); self.assertTrue(self.recover()['committed'])
            self.recover(True); self.recover(True); self.assertEqual(committed, self.live())
        else:
            self.assertTrue(self.recover()['rolled_back']); self.assertTrue(self.recover()['rolled_back'])
            self.assert_original(before); self.recover(True); self.recover(True); self.assert_original(before)
        self.assertFalse(self.owner.journal.exists()); self.assertFalse(self.owner.locator.exists())
        self.assertTrue(self.owner.lock_path.exists())


def forward_fault(target, after, initial=False, expected='rollback'):
    def test(self):
        self.second_provider()
        if not initial: self.old()
        before = self.live(); vault = self.f.tree(accp.VAULT)
        unrelated = self.f.root / 'unrelated'; unrelated.mkdir(); (unrelated / 'keep').write_bytes(b'\x00\xffpersonal')
        sentinel = self.f.tree(unrelated); fired = []
        with self.fault(target, after, fired), self.assertRaises(KeyboardInterrupt): self.activate()
        self.assertEqual([target], fired)
        self.outcome(before, expected)
        self.assertEqual(vault, self.f.tree(accp.VAULT)); self.assertEqual(sentinel, self.f.tree(unrelated))
    return test


for _target in ('lock', 'begin', 'locator', 'allocate-root', 'allocate-old', 'allocate-new',
        'allocate-discard', 'workspace-register', 'copy-fixture', 'prefix-fixture', 'copy-other',
        'prefix-other', 'prepared', 'bounds', 'applying', 'old-fixture', 'old-retired',
        'new-fixture', 'new-other', 'committed'):
    for _after in (False, True):
        _expected = 'rollback'
        if _target == 'lock' or (_target == 'begin' and not _after): _expected = 'untouched'
        if ((_target.startswith('allocate-') and (_after or _target != 'allocate-root'))
                or (_target == 'workspace-register' and not _after)
                or (_target.startswith('copy-') and _after)
                or (_target.startswith('prefix-') and not _after)): _expected = 'inspection'
        if _target == 'committed' and _after: _expected = 'commit'
        setattr(ActivationFaults, 'test_forward_%s_%s' % (_target.replace('-', '_'), 'after' if _after else 'before'),
                forward_fault(_target, _after, expected=_expected))

for _target in ('enroll', 'skills-create', 'skills-register'):
    for _after in (False, True):
        _expected = ('untouched' if _target == 'enroll' else
                     'inspection' if (_target == 'skills-create' and _after) or
                        (_target == 'skills-register' and not _after) else 'rollback')
        setattr(ActivationFaults, 'test_initial_%s_%s' % (_target.replace('-', '_'), 'after' if _after else 'before'),
                forward_fault(_target, _after, initial=True, expected=_expected))


def publication_fault(slot, step, after):
    def test(self):
        self.old(); before = self.live(); fired = []
        publish = txn.JournalAuthority._publish
        def injecting(owner, target, pending, raw, previous, metadata_record=None):
            label = ('manifest' if target == self.paths[2] else 'state' if target == self.paths[3]
                     else 'locator' if target == owner.locator else publication_name(json.loads(raw)))
            if label != slot: return publish(owner, target, pending, raw, previous, metadata_record)
            original_open = Path.open; original_replace = os.replace; original_sync = txn.sync_directory
            original_fsync = os.fsync; fd = []
            def hit():
                fired.append((slot, step, after)); raise OSError('A4 publication ' + slot + '/' + step)
            def around(fn, *args, **kwargs):
                if not after: hit()
                value = fn(*args, **kwargs)
                if after: hit()
                return value
            class Stream:
                def __init__(self, stream): self.stream = stream
                def __enter__(self): self.stream.__enter__(); return self
                def __exit__(self, *args): return self.stream.__exit__(*args)
                def fileno(self): fd[:] = [self.stream.fileno()]; return fd[0]
                def write(self, data):
                    return around(self.stream.write, data) if step == 'write' else self.stream.write(data)
                def flush(self):
                    return around(self.stream.flush) if step == 'flush' else self.stream.flush()
            def opening(path, *args, **kwargs):
                if path == pending and args == ('xb',):
                    if step == 'open' and not after: hit()
                    stream = original_open(path, *args, **kwargs)
                    if step == 'open' and after:
                        stream.close(); hit()
                    return Stream(stream)
                return original_open(path, *args, **kwargs)
            def replacing(source, destination):
                return around(original_replace, source, destination) if step == 'replace' else original_replace(source, destination)
            def syncing(path): return around(original_sync, path) if step == 'sync' else original_sync(path)
            def fsync(value):
                return around(original_fsync, value) if step == 'fsync' and fd == [value] else original_fsync(value)
            with mock.patch.object(Path, 'open', opening), mock.patch.object(os, 'replace', replacing), \
                    mock.patch.object(txn, 'sync_directory', syncing), mock.patch.object(os, 'fsync', fsync):
                return publish(owner, target, pending, raw, previous, metadata_record)
        with mock.patch.object(txn.JournalAuthority, '_publish', injecting), self.assertRaises(txn.JournalError): self.activate()
        self.assertEqual([(slot, step, after)], fired)
        if step == 'open' and not after: expected = 'untouched' if slot == 'begin' else 'rollback'
        elif step == 'sync' or (step == 'replace' and after): expected = 'commit' if slot == 'committed' else 'rollback'
        else: expected = 'inspection'
        self.outcome(before, expected)
    return test


for _slot in ('begin', 'locator', 'workspace-register', 'prefix-fixture', 'prepared', 'applying', 'committed', 'manifest', 'state'):
    # Every durable publication: pending-before-replace and authoritative-after-replace.
    for _after in (False, True):
        setattr(ActivationFaults, 'test_publication_%s_replace_%s' % (_slot.replace('-', '_'), _after),
                publication_fault(_slot, 'replace', _after))
for _slot in ('manifest', 'state'):
    for _step in ('open', 'write', 'flush', 'fsync', 'sync'):
        for _after in (False, True):
            setattr(ActivationFaults, 'test_publication_%s_%s_%s' % (_slot, _step, _after),
                    publication_fault(_slot, _step, _after))


if __name__ == '__main__': unittest.main()
