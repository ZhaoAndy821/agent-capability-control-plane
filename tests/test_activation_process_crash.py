"""A4 process death at real CLI forward/finalization boundaries, not timed races."""
import json
import os
from pathlib import Path
import unittest

import test_e2e as fixtures


class ActivationProcessCrash(unittest.TestCase):
    setUp = fixtures.E2E.setUp
    tearDown = fixtures.E2E.tearDown
    wj = fixtures.E2E.wj
    wj_abs = fixtures.E2E.wj_abs
    call = fixtures.E2E.call
    approve_lock = fixtures.E2E.approve_lock
    snapshot_tree = fixtures.E2E.snapshot_tree

    def prepare(self, scope):
        self.approve_lock()
        self.scope = scope
        if scope == 'user':
            user = self.base / 'user'; user.mkdir()
            self.active = user / '.agents'
            self.env['ACCP_USER_SCOPE_ROOT'] = str(self.active)
        else: self.active = self.project / '.agents'
        self.arguments = ['--project', str(self.project), '--scope', scope]
        self.call('activate', '--mode', 'smoke', *self.arguments)
        self.call('recover', '--cleanup', *self.arguments)
        personal = self.active / 'skills' / 'personal'; personal.mkdir()
        (personal / 'keep').write_bytes(b'user\x00\xffdata')
        self.before = self.live()
        self.original_launcher = self.cli.read_text(encoding='utf-8')

    def live(self):
        root = self.active / 'skills'
        tree = {p.relative_to(root).as_posix():
            (p.stat().st_dev, p.stat().st_ino, p.stat().st_mode, p.read_bytes() if p.is_file() else None)
            for p in [root, *root.rglob('*')]}
        return tree, [(self.active / name).read_bytes() for name in ('install-manifest.json', 'active-state.json')]

    def launcher(self, point=None, deny_admission=False):
        # All injection is in a disposable launcher. Production parser, lock,
        # proof, producer, recovery and ownership code are unchanged.
        prefix = self.original_launcher.split('runpy.run_path(')[0]
        injection = f'''
import os, json
import active_transaction as txn
import accp
POINT = {point!r}
def stop(label):
    if POINT == label: os._exit(73)
publish = txn.JournalAuthority.publish_journal
def journal(owner, record, previous=None):
    result = publish(owner, record, previous)
    stop(record['phase'])
    return result
txn.JournalAuthority.publish_journal = journal
locate = txn.JournalAuthority.publish_locator
def locator(owner, record):
    result = locate(owner, record); stop('locator'); return result
txn.JournalAuthority.publish_locator = locator
replace = os.replace
def replacing(src, dst):
    source, target = pathlib.Path(src), pathlib.Path(dst)
    if target.name == 'install-manifest.json': stop('manifest-pending')
    result = replace(src, dst)
    if target.parent.name == 'old': stop('old-move')
    if target.parent.name == 'skills' and source.parent.name == 'new': stop('new-move')
    if target.name == 'install-manifest.json': stop('manifest')
    if target.name == 'active-state.json': stop('state')
    return result
os.replace = replacing
unlink = pathlib.Path.unlink
def unlinking(path, *args, **kwargs):
    result = unlink(path, *args, **kwargs)
    if path.name == '.accp-transaction.json': stop('locator-unlink')
    if path.parent.name == 'active-transactions' and path.suffix == '.json': stop('journal-unlink')
    return result
pathlib.Path.unlink = unlinking
make = pathlib.Path.mkdir
def making(path, *args, **kwargs):
    result = make(path, *args, **kwargs)
    if path.name.startswith('.accp-txn-'): stop('workspace-gap')
    return result
pathlib.Path.mkdir = making
def denied(*args, **kwargs): raise AssertionError('recovery called admission/runtime/source')
if {deny_admission!r}:
    for name in ('runtime_owner', 'activation_admission', 'resolve_plan', 'evidence_ok', 'ready_runtime_binding'):
        setattr(accp, name, denied)
    accp.activation.ActivationAttempt = denied
raise SystemExit(accp.main())
'''
        self.cli.write_text(prefix + injection, encoding='utf-8')

    def remove_current_authority_inputs(self):
        # Move fixture data, never delete it. Recovery must use historical recorded
        # objects without consulting an extant runtime, review or catalog.
        (self.base / 'runtime').rename(self.base / 'retained-runtime')
        (self.cp / 'registry' / 'catalog.json').rename(self.cp / 'registry' / 'retained-catalog.json')
        (self.cp / 'lock' / 'sources.lock.json').rename(self.cp / 'lock' / 'retained-lock.json')
        self.launcher(deny_admission=True)

    def assert_rolled_back(self):
        for _ in range(2): self.call('recover', *self.arguments)
        self.assertEqual(self.before, self.live())  # original objects and exact metadata bytes
        for _ in range(2): self.call('recover', '--cleanup', *self.arguments)
        self.assertEqual(self.before, self.live())


def process_fault(point, scope='project'):
    def test(self):
        self.prepare(scope); self.launcher(point)
        result = self.call('activate', '--mode', 'smoke', *self.arguments, ok=False)
        self.assertEqual(73, result.returncode, result.stderr + result.stdout)  # proves hook
        self.remove_current_authority_inputs()
        if point in ('manifest-pending', 'workspace-gap'):
            before = self.snapshot_tree()
            for cleanup in ([], ['--cleanup']):
                result = self.call('recover', *cleanup, *self.arguments, ok=False)
                self.assertEqual(2, result.returncode, result.stderr)
                self.assertNotIn('recovery called', result.stderr)
                self.assertEqual(before, self.snapshot_tree())
            # The ambiguous evidence is retained, not normalized by restart.
            self.assertTrue(list((self.cp / '.local' / 'active-transactions').glob('*.json')))
        elif point == 'COMMITTED':
            committed = self.live(); self.assertNotEqual(self.before[0]['fixture-safe'], committed[0]['fixture-safe'])
            self.assertEqual(self.before[0]['personal/keep'], committed[0]['personal/keep'])
            for _ in range(2): self.call('recover', *self.arguments)
            for _ in range(2): self.call('recover', '--cleanup', *self.arguments)
            self.assertEqual(committed, self.live())
        else: self.assert_rolled_back()
    return test


for _point in ('PREPARING', 'locator', 'workspace-gap', 'PREPARED', 'APPLYING',
               'old-move', 'new-move', 'manifest-pending', 'manifest', 'state', 'COMMITTED'):
    setattr(ActivationProcessCrash, 'test_crash_' + _point.replace('-', '_'), process_fault(_point))
setattr(ActivationProcessCrash, 'test_user_crash_new_move', process_fault('new-move', 'user'))


def finalization_fault(point, rollback):
    def test(self):
        self.prepare('project')
        if rollback:
            self.launcher('new-move')
            result = self.call('activate', '--mode', 'smoke', *self.arguments, ok=False)
            self.assertEqual(73, result.returncode, result.stderr)
        else: self.call('activate', '--mode', 'smoke', *self.arguments)
        self.remove_current_authority_inputs()
        self.call('recover', *self.arguments)
        terminal = self.live()
        if rollback: self.assertEqual(self.before, terminal)
        self.launcher(point, deny_admission=True)
        result = self.call('recover', '--cleanup', *self.arguments, ok=False)
        self.assertEqual(73, result.returncode, result.stderr + result.stdout)
        self.launcher(deny_admission=True)
        for _ in range(2): self.call('recover', '--cleanup', *self.arguments)
        self.assertEqual(terminal, self.live())
        self.assertFalse((self.active / '.accp-transaction.json').exists())
        self.assertFalse(list((self.cp / '.local' / 'active-transactions').glob('*.json')))
        self.assertTrue((self.active / '.accp-lifecycle.lock').exists())
    return test


for _point in ('CLEANING', 'DONE', 'locator-unlink', 'journal-unlink'):
    for _rollback in (False, True):
        setattr(ActivationProcessCrash, 'test_finalization_%s_%s' % (_point.replace('-', '_'), _rollback),
                finalization_fault(_point, _rollback))


if __name__ == '__main__': unittest.main()
