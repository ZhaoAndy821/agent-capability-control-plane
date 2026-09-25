import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from unittest import mock

import test_deactivate_recovery as fixtures
import active_transaction as txn


class TerminalCleanup(unittest.TestCase):
    setUp = fixtures.DeactivateRecovery.setUp
    call = fixtures.DeactivateRecovery.call
    interrupt = fixtures.DeactivateRecovery.interrupt

    def commit(self):
        (self.skills / 'alpha' / 'nested').mkdir()
        (self.skills / 'alpha' / 'nested' / 'f').write_bytes(b'nested file')
        (self.skills / 'alpha' / 'empty').mkdir()
        self.call('deactivate')
        return self.owner.parse(self.owner.journal.read_bytes())

    def clean(self, dry=False):
        return self.call(extra=['--cleanup'] + (['--dry-run'] if dry else []))

    def pause(self, phase='CLEANING'):
        original = txn.JournalAuthority.publish_journal
        def stop(owner, record, previous=None):
            result = original(owner, record, previous)
            if record['phase'] == phase: raise OSError('after phase publication')
            return result
        with mock.patch.object(txn.JournalAuthority, 'publish_journal', autospec=True, side_effect=stop):
            with self.assertRaises(txn.JournalError): self.clean()
        return self.owner.parse(self.owner.journal.read_bytes())

    def assert_finalized(self, record):
        self.assertFalse(self.owner.journal.exists()); self.assertFalse(self.owner.locator.exists())
        self.assertFalse(self.owner.workspace(record['transaction_id']).exists())
        self.assertTrue(self.owner.lock_path.exists())
        self.assertEqual(b'personal', (self.skills / 'personal' / 'payload').read_bytes())
        self.assertEqual(self.identities['personal'], txn.directory_identity(self.skills / 'personal'))

    def test_committed_cleanup_dry_run_success_and_idempotence(self):
        record = self.commit(); before = self.owner.journal.read_bytes()
        runtime = self.root / 'runtime'; runtime.mkdir(); (runtime / 'keep').write_bytes(b'runtime')
        self.assertEqual('finalize',self.clean(dry=True)['preview']['action']); self.assertEqual(before, self.owner.journal.read_bytes())
        with mock.patch.dict(os.environ, {'ACCP_RUNTIME_ROOT': str(runtime)}):
            self.assertTrue(self.clean()['finalized']); self.assertTrue(self.clean()['noop'])
        self.assertEqual(b'runtime', (runtime / 'keep').read_bytes()); self.assert_finalized(record)

    def test_rolled_back_cleanup_keeps_restored_generation(self):
        self.interrupt(); self.call()
        record = self.owner.parse(self.owner.journal.read_bytes())
        self.clean(); self.assert_finalized(record)
        self.assertEqual(self.old_im, self.im.read_bytes()); self.assertEqual(self.old_state, self.state.read_bytes())
        for name in ('alpha', 'beta'):
            self.assertEqual(self.identities[name], txn.directory_identity(self.skills / name))

    def test_rolled_back_without_workspace(self):
        self.interrupt('PREPARING', after=True); self.call()
        record = self.owner.parse(self.owner.journal.read_bytes())
        self.assertIsNone(record['workspace_identity'])
        self.clean(); self.assert_finalized(record)

    def test_uncommitted_cleanup_is_refused(self):
        self.interrupt(); before = self.owner.journal.read_bytes()
        with self.assertRaises(txn.JournalError): self.clean()
        self.assertEqual(before, self.owner.journal.read_bytes())

    def test_inventory_precedes_delete_and_finalization_order(self):
        self.commit(); events = []; publish = txn.JournalAuthority.publish_journal
        unlink = Path.unlink; rmdir = Path.rmdir
        def journal(owner, record, previous=None):
            result = publish(owner, record, previous); events.append(record['phase']); return result
        def delete(path, *args, **kwargs):
            events.append('locator' if path == self.owner.locator else 'journal' if path == self.owner.journal else 'file')
            return unlink(path, *args, **kwargs)
        def directory(path, *args, **kwargs):
            events.append('directory'); return rmdir(path, *args, **kwargs)
        with mock.patch.object(txn.JournalAuthority, 'publish_journal', autospec=True, side_effect=journal), \
                mock.patch.object(Path, 'unlink', autospec=True, side_effect=delete), \
                mock.patch.object(Path, 'rmdir', autospec=True, side_effect=directory):
            self.clean()
        self.assertEqual('CLEANING', events[0]); self.assertEqual(['DONE', 'locator', 'journal'], events[-3:])

    def test_partial_deletion_failure_then_retry(self):
        record = self.commit(); unlink = Path.unlink; seen = []
        def stop(path, *args, **kwargs):
            if path.name == 'payload':
                seen.append(path)
                if len(seen) == 1: raise PermissionError('fixture delete denied')
            return unlink(path, *args, **kwargs)
        with mock.patch.object(Path, 'unlink', autospec=True, side_effect=stop):
            with self.assertRaises(txn.JournalError): self.clean()
        self.assertEqual('CLEANING', self.owner.parse(self.owner.journal.read_bytes())['phase'])
        self.clean(); self.assert_finalized(record)

    def test_added_modified_and_replaced_remaining_entries_refuse(self):
        self.commit(); record = self.pause()
        root = self.owner.child_path(record['transaction_id'], 'old', 'alpha')
        rogue = root / 'unknown'; rogue.write_bytes(b'preserve')
        before = self.owner.journal.read_bytes()
        with self.assertRaises(txn.JournalError): self.clean()
        self.assertEqual(b'preserve', rogue.read_bytes()); rogue.unlink()
        payload = root / 'payload'; original = payload.read_bytes(); payload.write_bytes(b'changed')
        with self.assertRaises(txn.JournalError): self.clean()
        payload.write_bytes(original)
        payload.rename(self.root / 'saved-file'); payload.write_bytes(original)
        with self.assertRaises(txn.JournalError): self.clean()
        self.assertEqual(before, self.owner.journal.read_bytes())

    def test_hardlinked_remaining_file_refused(self):
        self.commit(); record = self.pause()
        path = self.owner.child_path(record['transaction_id'], 'old', 'alpha') / 'payload'
        os.link(path, self.root / 'shared-file')
        with self.assertRaises(txn.JournalError): self.clean()
        self.assertTrue(path.exists())

    def test_inventory_schema_paths_limits_and_immutable_transition(self):
        self.commit(); record = self.pause(); raw = self.owner.journal.read_bytes()
        for relative in ('../outside', '/absolute', 'C:/escape', '\\\\server\\share', 'a//b', 'con', 'a:stream'):
            altered = json.loads(raw); altered['cleanup_entries'][0]['relative'] = relative
            with self.subTest(relative=relative), self.assertRaises(txn.JournalError): self.owner.serialize(altered)
        for mutation in ('identity', 'duplicate', 'missing', 'unknown'):
            altered = json.loads(raw)
            if mutation == 'identity': altered['cleanup_entries'][0]['identity'] = {'device': '1', 'inode': '2'}
            if mutation == 'duplicate': altered['cleanup_entries'].append(altered['cleanup_entries'][0])
            if mutation == 'missing': altered['cleanup_entries'] = []
            if mutation == 'unknown': altered['cleanup_entries'][0]['unknown'] = True
            with self.subTest(mutation=mutation), self.assertRaises(txn.JournalError): self.owner.serialize(altered)
        altered = json.loads(raw); altered['cleanup_entries'][-1]['identity']['inode'] = '999'
        with self.owner.lifecycle_lock(), self.assertRaises(txn.JournalError):
            self.owner.publish_journal(altered, previous=raw)
        with mock.patch.object(txn, 'MAX_CLEANUP_ENTRIES', 1), self.assertRaises(txn.JournalError):
            self.owner.serialize(record)

    def test_legacy_terminal_inventory_not_reconstructed(self):
        self.commit(); record = self.pause(); del record['cleanup_entries']
        self.owner.journal.write_bytes(self.owner.serialize(record))
        before = self.owner.journal.read_bytes()
        with self.assertRaises(txn.JournalError): self.clean()
        self.assertEqual(before, self.owner.journal.read_bytes())

    def test_pending_write_lock_and_foreign_authority_refuse(self):
        self.commit(); before = self.owner.journal.read_bytes()
        with self.owner.lifecycle_lock(), self.assertRaises(txn.JournalError): self.clean()
        self.owner.journal_pending.write_bytes(before)
        with self.assertRaises(txn.JournalError): self.clean()
        self.owner.journal_pending.unlink()
        record = json.loads(before); record['project_identity'] = {'device': '1', 'inode': '2'}
        self.owner.journal.write_text(json.dumps(record))
        with self.assertRaises(txn.JournalError): self.clean()

    def test_publication_failure_preserves_backups(self):
        record = self.commit()
        with mock.patch.object(txn.os, 'fsync', side_effect=OSError('flush failed')):
            with self.assertRaises(txn.JournalError): self.clean()
        self.assertTrue(self.owner.child_path(record['transaction_id'], 'old', 'alpha').exists())
        self.assertEqual('COMMITTED', self.owner.parse(self.owner.journal.read_bytes())['phase'])
        self.assertTrue(self.owner.journal_pending.exists())

    def test_failed_locator_unlink_and_done_retry(self):
        record = self.commit(); unlink = Path.unlink
        def stop(path, *args, **kwargs):
            if path == self.owner.locator: raise PermissionError('locator denied')
            return unlink(path, *args, **kwargs)
        with mock.patch.object(Path, 'unlink', autospec=True, side_effect=stop):
            with self.assertRaises(txn.JournalError): self.clean()
        self.assertEqual('DONE', self.owner.parse(self.owner.journal.read_bytes())['phase'])
        self.clean(); self.assert_finalized(record)

    def test_evidence_helper_requires_done_and_locator_first(self):
        record = self.commit()
        with self.owner.lifecycle_lock(), self.assertRaises(txn.JournalError):
            self.owner._unlink_evidence(self.owner.locator, self.owner.locator.read_bytes(), record)
        record = self.pause('DONE')
        with self.owner.lifecycle_lock(), self.assertRaises(txn.JournalError):
            self.owner._unlink_evidence(self.owner.journal, self.owner.serialize(record), record)
        self.assertTrue(self.owner.locator.exists()); self.assertTrue(self.owner.journal.exists())
        self.clean(); self.assert_finalized(record)

    def test_last_unlink_flush_failure_is_reflushed_on_retry(self):
        record = self.commit(); sync = txn.sync_directory
        def stop(path):
            if path == self.owner.store and not self.owner.journal.exists():
                raise OSError('after last unlink')
            return sync(path)
        with mock.patch.object(txn, 'sync_directory', side_effect=stop):
            with self.assertRaises(txn.JournalError): self.clean()
        self.assert_finalized(record)
        with mock.patch.object(txn, 'sync_directory', wraps=sync) as flush:
            self.assertTrue(self.clean()['noop'])
        self.assertIn(mock.call(self.owner.base), flush.call_args_list)
        self.assertIn(mock.call(self.owner.store), flush.call_args_list)

    def test_user_cleanup_preserves_pending_project_and_unmanaged_bytes(self):
        self.interrupt(); project_journal = self.owner.journal.read_bytes()
        user = self.root / 'user-active'; (user / 'skills').mkdir(parents=True)
        for name in ('alpha', 'beta', 'personal'):
            (user / 'skills' / name).mkdir()
            (user / 'skills' / name / 'payload').write_bytes(name.encode())
        personal = txn.observed_tree(user / 'skills' / 'personal')
        manifest = json.loads(self.old_im); manifest['scope'] = 'user'
        (user / 'install-manifest.json').write_bytes(json.dumps(manifest).encode())
        (user / 'active-state.json').write_bytes(self.old_state)
        with mock.patch.dict(os.environ, {'ACCP_USER_SCOPE_ROOT': str(user)}):
            self.call('deactivate', ['--scope', 'user'])
            owner = txn.JournalAuthority(self.cp, self.project, 'user', user)
            record = owner.parse(owner.journal.read_bytes())
            self.assertTrue(self.call(extra=['--scope', 'user', '--cleanup'])['finalized'])
            self.assertTrue(self.call(extra=['--scope', 'user', '--cleanup'])['noop'])
        self.assertFalse(owner.journal.exists()); self.assertFalse(owner.locator.exists())
        self.assertFalse(owner.workspace(record['transaction_id']).exists())
        self.assertEqual(personal, txn.observed_tree(user / 'skills' / 'personal'))
        self.assertEqual(project_journal, self.owner.journal.read_bytes())

    @unittest.skipUnless(os.name == 'nt', 'Windows readonly flag')
    def test_readonly_clear_failure_then_retry(self):
        source = self.skills / 'alpha' / 'payload'; source.chmod(stat.S_IREAD)
        record = self.commit(); path = self.owner.child_path(record['transaction_id'], 'old', 'alpha') / 'payload'
        def restore_fixture_mode():
            if path.exists(): path.chmod(stat.S_IWRITE)
        self.addCleanup(restore_fixture_mode)
        unlink = Path.unlink
        def stop(target, *args, **kwargs):
            if target == path: raise PermissionError('after readonly clear')
            return unlink(target, *args, **kwargs)
        with mock.patch.object(Path, 'unlink', autospec=True, side_effect=stop):
            with self.assertRaises(txn.JournalError): self.clean()
        self.assertFalse(path.lstat().st_file_attributes & 1)
        self.clean(); self.assert_finalized(record)

    @unittest.skipUnless(os.name == 'nt', 'Windows junction fixture')
    def test_cleanup_junction_refuses_and_preserves_target(self):
        record = self.commit(); self.pause()
        path = self.owner.child_path(record['transaction_id'], 'old', 'alpha')
        outside = self.root / 'saved-alpha'; path.rename(outside)
        result = subprocess.run([os.environ['COMSPEC'], '/c', 'mklink', '/J', str(path), str(outside)], capture_output=True)
        self.assertEqual(0, result.returncode, result.stderr)
        try:
            with self.assertRaises(txn.JournalError): self.clean()
            self.assertEqual(b'alpha', (outside / 'payload').read_bytes())
        finally: path.rmdir()

    def crash(self, boundary):
        code = ('import os,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); '
                'import accp; import active_transaction as t; accp.ROOT=Path(sys.argv[2]); '
                'a=t.JournalAuthority(sys.argv[2],sys.argv[3]); boundary=sys.argv[4]; '
                'pub=t.JournalAuthority.publish_journal; unlink=Path.unlink; rmdir=Path.rmdir; replace=t.os.replace\n'
                'def publish(owner,r,previous=None):\n'
                ' if boundary=="before-"+r["phase"]: os._exit(79)\n'
                ' result=pub(owner,r,previous)\n'
                ' if boundary==r["phase"]: os._exit(79)\n'
                ' return result\n'
                'def remove(p,*args,**kwargs):\n'
                ' tag="locator" if p==a.locator else "journal" if p==a.journal else "file"\n'
                ' if boundary=="before-"+tag: os._exit(79)\n'
                ' result=unlink(p,*args,**kwargs)\n'
                ' if boundary==tag: os._exit(79)\n'
                ' return result\n'
                'def directory(p,*args,**kwargs):\n'
                ' tag="workspace" if p.name.startswith(".accp-txn-") else "old" if p.name=="old" else "dir"\n'
                ' result=rmdir(p,*args,**kwargs)\n'
                ' if boundary==tag: os._exit(79)\n'
                ' return result\n'
                'def replacing(src,dst):\n'
                ' if Path(dst)==a.journal and boundary=="pending-"+t.strict_json(Path(src).read_bytes())["phase"]: os._exit(79)\n'
                ' return replace(src,dst)\n'
                't.JournalAuthority.publish_journal=publish; Path.unlink=remove; Path.rmdir=directory; t.os.replace=replacing\n'
                'args=accp.parser().parse_args(["recover","--project",sys.argv[3],"--cleanup"]); args.fn(args)\n')
        result = subprocess.run([sys.executable, '-B', '-c', code, str(fixtures.ROOT / 'scripts'),
                                 str(self.cp), str(self.project), boundary], capture_output=True, timeout=20)
        self.assertEqual(79, result.returncode, result.stderr)

    def lifecycle_crash(self, action, boundary):
        code = ('import os,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); '
                'import accp; import active_transaction as t; accp.ROOT=Path(sys.argv[2]); '
                'a=t.JournalAuthority(sys.argv[2],sys.argv[3]); boundary=sys.argv[5]; '
                'pub=t.JournalAuthority.publish_journal; loc=t.JournalAuthority.publish_locator; '
                'write=t.JournalAuthority._publish; replace=t.os.replace\n'
                'def journal(owner,r,previous=None):\n'
                ' if boundary=="before-"+r["phase"]: os._exit(81)\n'
                ' result=pub(owner,r,previous)\n'
                ' if boundary=="after-"+r["phase"]: os._exit(81)\n'
                ' return result\n'
                'def locator(owner,r):\n'
                ' if boundary=="before-locator": os._exit(81)\n'
                ' result=loc(owner,r)\n'
                ' if boundary=="after-locator": os._exit(81)\n'
                ' return result\n'
                'def metadata(owner,target,*args,**kwargs):\n'
                ' tag="manifest" if target.name=="install-manifest.json" else "state" if target.name=="active-state.json" else "other"\n'
                ' if boundary=="before-"+tag: os._exit(81)\n'
                ' result=write(owner,target,*args,**kwargs)\n'
                ' if boundary=="after-"+tag: os._exit(81)\n'
                ' return result\n'
                'def replacing(src,dst):\n'
                ' tag="journal" if Path(dst)==a.journal else "locator" if Path(dst)==a.locator else "manifest" if Path(dst).name=="install-manifest.json" else "state" if Path(dst).name=="active-state.json" else "other"\n'
                ' if boundary=="pending-"+tag: os._exit(81)\n'
                ' return replace(src,dst)\n'
                't.JournalAuthority.publish_journal=journal; t.JournalAuthority.publish_locator=locator; '
                't.JournalAuthority._publish=metadata; t.os.replace=replacing\n'
                'args=accp.parser().parse_args([sys.argv[4],"--project",sys.argv[3]]); args.fn(args)\n')
        result = subprocess.run([sys.executable, '-B', '-c', code, str(fixtures.ROOT / 'scripts'),
                                 str(self.cp), str(self.project), action, boundary], capture_output=True, timeout=20)
        self.assertEqual(81, result.returncode, result.stderr)


def crash_test(boundary):
    def test(self):
        record = self.commit(); self.crash(boundary)
        self.clean(); self.assert_finalized(record)
        self.assertTrue(self.clean()['noop'])
    return test


for boundary in ('before-CLEANING', 'CLEANING', 'file', 'dir', 'old', 'workspace',
                 'before-DONE', 'DONE', 'before-locator', 'locator', 'before-journal', 'journal'):
    setattr(TerminalCleanup, 'test_crash_' + boundary.replace('-', '_'), crash_test(boundary))


def pending_cleanup_crash_test(phase):
    def test(self):
        record = self.commit(); self.crash('pending-' + phase)
        raw = self.owner.journal.read_bytes(); pending = self.owner.journal_pending.read_bytes()
        self.assertEqual('COMMITTED' if phase == 'CLEANING' else 'CLEANING', self.owner.parse(raw)['phase'])
        self.assertEqual(phase, self.owner.parse(pending)['phase'])
        with self.assertRaises(txn.JournalError): self.clean()
        with self.assertRaises(txn.JournalError): self.call()
        self.assertEqual(raw, self.owner.journal.read_bytes())
        self.assertEqual(pending, self.owner.journal_pending.read_bytes())
        self.assertTrue(self.owner.locator.exists())
        self.assertEqual(phase == 'CLEANING', self.owner.workspace(record['transaction_id']).exists())
    return test


for phase in ('CLEANING', 'DONE'):
    setattr(TerminalCleanup, 'test_crash_pending_' + phase, pending_cleanup_crash_test(phase))


def lifecycle_crash_test(action, boundary):
    def test(self):
        if action == 'recover': self.interrupt()
        self.lifecycle_crash(action, boundary)
        if boundary.startswith('pending-') or boundary == 'before-PREPARED':
            # Allocation gaps and complete-looking pending files never authorize repair.
            before = {p: p.read_bytes() for root in (self.base, self.owner.store)
                      if root.exists() for p in root.rglob('*') if p.is_file()}
            with self.assertRaises(txn.JournalError): self.call()
            with self.assertRaises(txn.JournalError): self.clean()
            self.assertEqual(before, {p: p.read_bytes() for p in before})
            return
        self.call()
        if boundary == 'after-COMMITTED':
            self.assertFalse((self.skills / 'alpha').exists())
            self.assertEqual('COMMITTED', self.owner.parse(self.owner.journal.read_bytes())['phase'])
        else:
            self.assertEqual(self.old_im, self.im.read_bytes()); self.assertEqual(self.old_state, self.state.read_bytes())
            for name in ('alpha', 'beta'):
                self.assertEqual(self.identities[name], txn.directory_identity(self.skills / name))
                self.assertEqual(name.encode(), (self.skills / name / 'payload').read_bytes())
        self.clean(); self.assertTrue(self.clean()['noop'])
        self.assertFalse(self.owner.journal.exists()); self.assertFalse(self.owner.locator.exists())
        self.assertEqual(b'personal', (self.skills / 'personal' / 'payload').read_bytes())
    return test


for action, points in (
        ('deactivate', ('PREPARING', 'locator', 'PREPARED', 'APPLYING', 'manifest', 'state', 'COMMITTED')),
        ('recover', ('ROLLING_BACK', 'state', 'manifest', 'ROLLED_BACK'))):
    for point in points:
        for side in ('before', 'after'):
            boundary = side + '-' + point
            setattr(TerminalCleanup, 'test_lifecycle_crash_' + action + '_' + boundary.replace('-', '_'),
                    lifecycle_crash_test(action, boundary))
    for point in (('journal', 'locator', 'manifest', 'state') if action == 'deactivate' else ('journal', 'manifest', 'state')):
        boundary = 'pending-' + point
        setattr(TerminalCleanup, 'test_lifecycle_crash_' + action + '_' + boundary.replace('-', '_'),
                lifecycle_crash_test(action, boundary))


if __name__ == '__main__': unittest.main()
