"""M3 deterministic lifecycle faults; all artifacts remain in disposable fixtures."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
import uuid
from unittest import mock

import test_deactivate_recovery as fixtures
import active_transaction as txn


class AdversarialLifecycle(unittest.TestCase):
    call = fixtures.DeactivateRecovery.call
    interrupt = fixtures.DeactivateRecovery.interrupt

    def setUp(self):
        fixtures.DeactivateRecovery.setUp(self)
        for name in ('alpha', 'beta'):
            git = self.skills / name / '.git'; git.mkdir()
            (git / 'evidence').write_bytes(b'non-excluded original bytes\x00\xff')
        self.generations = {name: txn.observed_tree(self.skills / name) for name in ('alpha', 'beta')}
        for name in ('other-project', 'runtime'):
            (self.root / name).mkdir(); (self.root / name / 'keep').write_bytes(name.encode())
        loose = self.skills / 'personal-file'; loose.write_bytes(b'unmanaged hardlink')
        os.link(loose, self.root / 'other-project' / 'alias')
        self.sentinels = {path: self.tree(path) for path in
                          (self.skills / 'personal', loose, self.root / 'other-project', self.root / 'runtime')}

    @staticmethod
    def tree(root):
        paths = [root] + (list(root.rglob('*')) if root.is_dir() else [])
        return {str(p.relative_to(root)): (p.stat().st_dev, p.stat().st_ino,
                p.stat().st_nlink, p.read_bytes() if p.is_file() else None) for p in paths}

    def unchanged(self):
        for path, expected in self.sentinels.items(): self.assertEqual(expected, self.tree(path))

    def record(self):
        return self.owner.parse(self.owner.journal.read_bytes()) if self.owner.journal.exists() else None

    def copies_preserved(self):
        for name, expected in self.generations.items():
            candidates = [self.skills / name] + list(self.base.glob('.accp-txn-*/old/' + name))
            existing = [p for p in candidates if p.exists()]
            self.assertEqual(1, len(existing), name)
            self.assertEqual(expected, txn.observed_tree(existing[0]))
        self.unchanged()

    def restored(self):
        self.assertEqual(self.old_im, self.im.read_bytes()); self.assertEqual(self.old_state, self.state.read_bytes())
        for name, expected in self.generations.items():
            self.assertEqual(expected, txn.observed_tree(self.skills / name))
        self.copies_preserved()

    def refuse_unchanged(self):
        """Every variant refuses without mutating; writers raise, previews report.

        R1 routes dry-runs through the nonmutating reader boundary, so a preview
        returns a blocked envelope with exit 2 instead of raising. The writer
        paths (plain and --cleanup) still raise. Both are asserted explicitly,
        including the exit code and the absence of any authority or generation
        claim, so the refusal contract cannot silently weaken.
        """
        before = self.tree(self.root)
        for _ in range(2):
            for extra in ([], ['--cleanup'], ['--dry-run'], ['--cleanup', '--dry-run']):
                if '--dry-run' in extra:
                    report = self.call(extra=extra)
                    preview = report['preview']
                    self.assertEqual('cleanup' if '--cleanup' in extra else 'recover',
                                     preview['operation'], report)
                    self.assertEqual('blocked', preview['admission'], report)
                    self.assertIsNone(preview['action'], report)
                    self.assertFalse(preview['reservation'], report)
                    self.assertFalse(report['admission_authority'], report)
                    self.assertIsNone(report['current_generation'], report)
                    self.assertIsNone(report['transaction'], report)
                    self.assertIn(report['lifecycle'], ('UNKNOWN', 'BUSY_OR_UNAVAILABLE'), report)
                    self.assertEqual(2, txn.JournalAuthority.reader_exit(report), report)
                else:
                    with self.assertRaises((txn.JournalError, OSError)): self.call(extra=extra)
                self.assertEqual(before, self.tree(self.root))

    def finish(self, committed=False):
        self.call(); self.assertTrue(self.call()['noop'])
        record = self.record()
        self.assertEqual('COMMITTED' if committed else 'ROLLED_BACK', record['phase'])
        if committed:
            self.copies_preserved()
            for name in self.generations: self.assertFalse((self.skills / name).exists())
            self.assertEqual(txn.snapshot_bytes(record['new_manifest']), self.im.read_bytes())
            self.assertEqual(txn.snapshot_bytes(record['new_state']), self.state.read_bytes())
        else:
            self.restored()
        self.call(extra=['--cleanup']); self.assertTrue(self.call(extra=['--cleanup'])['noop'])
        self.assertFalse(self.owner.journal.exists()); self.assertFalse(self.owner.locator.exists())
        self.assertFalse(any(self.base.glob('.accp-txn-*')))
        if not committed: self.restored()
        self.unchanged()

    def publication_fault(self, action, target, failure):
        if action == 'recover': self.interrupt()
        if action == 'cleanup': self.call('deactivate')
        if action == 'cleanup_rolled_back': self.interrupt(); self.call()
        cleanup = action.startswith('cleanup')
        original = txn.os.replace; sync = txn.sync_directory; hit = []
        last = [None]
        def label(source, destination):
            if Path(destination) == self.owner.journal:
                return 'journal:' + txn.strict_json(Path(source).read_bytes())['phase']
            if Path(destination) == self.owner.locator: return 'locator'
            if Path(destination) == self.im: return 'manifest'
            if Path(destination) == self.state: return 'state'
            return None
        def replace(source, destination):
            tag = label(source, destination)
            if tag == target and failure == 'before':
                hit.append(tag); raise OSError('before replacement')
            result = original(source, destination)
            last[0] = (tag, Path(destination).parent)
            if tag == target and failure == 'after':
                hit.append(tag); raise OSError('replacement completed then raised')
            return result
        def flush(path):
            if last[0] == (target, path) and failure == 'sync':
                hit.append(target); raise OSError('post-replace directory sync failed')
            return sync(path)
        extra = ['--cleanup'] if cleanup else []
        with mock.patch.object(txn.os, 'replace', side_effect=replace), \
                mock.patch.object(txn, 'sync_directory', side_effect=flush):
            with self.assertRaises(txn.JournalError):
                self.call('recover' if cleanup else action, extra)
        self.assertEqual([target], hit)
        record = self.record()
        if target != 'journal:DONE' or action == 'cleanup_rolled_back': self.copies_preserved()
        else: self.unchanged()
        if failure == 'before':
            # A pending slot remains even when its JSON is complete and valid.
            self.refuse_unchanged()
        elif cleanup:
            self.call(extra=['--cleanup']); self.assertTrue(self.call(extra=['--cleanup'])['noop'])
            self.assertFalse(self.owner.journal.exists()); self.assertFalse(self.owner.locator.exists())
            self.assertFalse(any(self.base.glob('.accp-txn-*'))); self.unchanged()
            if action == 'cleanup_rolled_back': self.restored()
        else:
            self.finish(committed=record['phase'] == 'COMMITTED')

    def move_fault(self, action, name, after):
        if action == 'recover': self.interrupt()
        original = txn.os.replace; hit = []
        def replace(source, destination):
            matched = Path(source).name == name and Path(source).parent.name == (
                'skills' if action == 'deactivate' else 'old')
            if matched:
                hit.append(name)
                if not after: raise OSError('move denied')
            result = original(source, destination)
            if matched: raise OSError('move completed then raised')
            return result
        with mock.patch.object(txn.os, 'replace', side_effect=replace):
            with self.assertRaises(txn.JournalError): self.call(action)
        self.assertEqual([name], hit); self.copies_preserved()
        self.assertTrue(self.owner.journal.exists()); self.assertTrue(self.owner.locator.exists())
        self.finish()

    def test_malformed_truncated_journal_and_locator_are_nonmutating(self):
        self.interrupt()
        for path in (self.owner.journal, self.owner.locator):
            original = path.read_bytes()
            for raw in (b'', b'{', original[:-3], b'\xff', b'null', b'[]',
                        b'{"schema_version":1,"schema_version":1}'):
                with self.subTest(slot=path.name, raw=raw[:20]):
                    path.write_bytes(raw); self.refuse_unchanged()
                    self.copies_preserved()
            path.write_bytes(original)
        self.finish()

    def test_foreign_locator_fields_and_transaction_are_nonmutating(self):
        self.interrupt(); raw = self.owner.locator.read_bytes()
        for key, value in (('transaction_id', str(uuid.uuid4())), ('control_plane_path', str(self.root)),
                           ('base_path', str(self.root)), ('key', 'f' * 64), ('schema_version', True)):
            changed = json.loads(raw); changed[key] = value
            with self.subTest(key=key):
                self.owner.locator.write_bytes(json.dumps(changed).encode()); self.refuse_unchanged()
                self.copies_preserved()
        self.owner.locator.write_bytes(raw); self.finish()

    def test_identity_records_and_stale_transaction_refuse(self):
        record = self.interrupt(); original = self.owner.journal.read_bytes()
        for key in ('control_plane_identity', 'project_identity', 'base_identity', 'skills_before'):
            altered = dict(record); altered[key] = {'device': '1', 'inode': '2'}
            with self.subTest(key=key):
                self.owner.journal.write_bytes((json.dumps(altered, sort_keys=True, separators=(',', ':')) + '\n').encode())
                self.refuse_unchanged(); self.copies_preserved()
        self.owner.journal.write_bytes(original)
        altered = dict(record, transaction_id=str(uuid.uuid4()))
        self.owner.journal.write_bytes(self.owner.serialize(altered))
        self.owner.locator.write_bytes((json.dumps(self.owner.locator_record(altered), sort_keys=True,
                                                   separators=(',', ':')) + '\n').encode())
        self.refuse_unchanged(); self.copies_preserved()

    def test_actual_repository_project_base_and_skills_replacements(self):
        self.interrupt()
        for path in (self.cp, self.project, self.base, self.skills):
            with self.subTest(path=path.name):
                saved = self.root / ('saved-' + path.name)
                path.rename(saved); shutil.copytree(saved, path)
                try: self.refuse_unchanged()
                finally:
                    # Retain both fixture generations; never delete the replacement.
                    path.rename(self.root / ('replacement-' + path.name)); saved.rename(path)
        self.finish()

    def test_unknown_workspace_content_and_missing_original_refuse(self):
        record = self.interrupt(); workspace = self.owner.workspace(record['transaction_id'])
        for area in ('old', 'new', 'discard'):
            rogue = workspace / area / 'unowned'; rogue.write_bytes(b'keep')
            self.refuse_unchanged(); rogue.rename(self.root / ('saved-rogue-' + area))
        backup = self.owner.child_path(record['transaction_id'], 'old', 'alpha')
        backup.rename(self.root / 'saved-original')
        self.refuse_unchanged()
        self.assertEqual(self.generations['alpha'], txn.observed_tree(self.root / 'saved-original'))

    def test_subprocess_cli_contention_preserves_all_evidence(self):
        self.call('deactivate'); before = self.tree(self.root)
        code = ('import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); '
                'import accp; accp.ROOT=Path(sys.argv[2]); '
                'a=accp.parser().parse_args(["recover","--project",sys.argv[3],*sys.argv[4:]]); a.fn(a)')
        for extra in ([], ['--cleanup']):
            with self.owner.lifecycle_lock():
                result = subprocess.run([sys.executable, '-B', '-c', code, str(fixtures.ROOT / 'scripts'),
                    str(self.cp), str(self.project), *extra], capture_output=True, timeout=20)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(b'lock busy or unavailable', result.stderr)
            # Windows byte-range locking also blocks reads through a second handle.
            # Compare all bytes/identities after releasing only our own test lock.
            self.assertEqual(before, self.tree(self.root))
        self.finish(committed=True)

    def terminal_metadata_conflict(self, outcome, phase):
        if outcome == 'rolled_back': self.interrupt(); self.call()
        else: self.call('deactivate')
        publish = txn.JournalAuthority.publish_journal
        def stop(owner, record, previous=None):
            result = publish(owner, record, previous)
            if record['phase'] == phase: raise OSError('after terminal publication')
            return result
        with mock.patch.object(txn.JournalAuthority, 'publish_journal', autospec=True, side_effect=stop):
            with self.assertRaises(txn.JournalError): self.call(extra=['--cleanup'])
        original = self.state.read_bytes(); self.state.write_bytes(b'foreign terminal state')
        self.refuse_unchanged()
        self.assertTrue(self.owner.journal.exists()); self.assertTrue(self.owner.locator.exists())
        self.unchanged()
        self.state.write_bytes(original)  # restore only the bytes changed by this fixture
        self.call(extra=['--cleanup']); self.assertTrue(self.call(extra=['--cleanup'])['noop'])
        if outcome == 'rolled_back': self.restored()


def publication_case(action, target, failure):
    def test(self): self.publication_fault(action, target, failure)
    return test


for action, targets in (
        ('deactivate', ('journal:PREPARING', 'locator', 'journal:PREPARED', 'journal:APPLYING',
                        'manifest', 'state', 'journal:COMMITTED')),
        ('recover', ('journal:ROLLING_BACK', 'state', 'manifest', 'journal:ROLLED_BACK')),
        ('cleanup', ('journal:CLEANING', 'journal:DONE')),
        ('cleanup_rolled_back', ('journal:CLEANING', 'journal:DONE'))):
    for target in targets:
        for failure in ('before', 'after', 'sync'):
            setattr(AdversarialLifecycle, 'test_publication_' + action + '_' + target.replace(':', '_') + '_' + failure,
                    publication_case(action, target, failure))


def move_case(action, name, after):
    def test(self): self.move_fault(action, name, after)
    return test


for action in ('deactivate', 'recover'):
    for name in ('alpha', 'beta'):
        for after in (False, True):
            setattr(AdversarialLifecycle, 'test_move_' + action + '_' + name + '_' + str(after),
                    move_case(action, name, after))


def terminal_case(outcome, phase):
    def test(self): self.terminal_metadata_conflict(outcome, phase)
    return test


for outcome in ('committed', 'rolled_back'):
    for phase in ('CLEANING', 'DONE'):
        setattr(AdversarialLifecycle, 'test_terminal_metadata_' + outcome + '_' + phase,
                terminal_case(outcome, phase))


if __name__ == '__main__': unittest.main()
