"""A4 final-proof drift and terminal inventory boundaries, no policy bypasses."""
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest import mock

import accp
import active_transaction as txn
import artifact_binding as ab
import test_activation_forward as forward
from test_activation_transaction import ActivationFixture


class ActivationBoundaryAdversarial(unittest.TestCase):
    setUp = forward.ActivationForward.setUp
    activate = forward.ActivationForward.activate
    recover = forward.ActivationForward.recover
    live = forward.ActivationForward.live
    old = forward.ActivationForward.old

    def test_partial_provider_directory_is_retained_not_adopted(self):
        self.old(); before = self.live(); original = os.mkdir; fired = []
        def cut(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            path = Path(path)
            if path.name == 'fixture' and path.parent.name == 'new':
                fired.append(path); raise KeyboardInterrupt('partial copy')
            return result
        with mock.patch.object(os, 'mkdir', cut), self.assertRaises(KeyboardInterrupt): self.activate()
        self.assertEqual(1, len(fired)); self.assertFalse(any(fired[0].iterdir()))
        before_refusal = self.f.tree(self.f.root)
        for cleanup in (False, True):
            with self.assertRaises(txn.JournalError): self.recover(cleanup)
            self.assertEqual(before_refusal, self.f.tree(self.f.root))
        self.assertEqual(before, self.live())

    def test_unmanaged_drift_after_first_move_retains_originals_and_evidence(self):
        self.old(); before = self.live(); original = os.replace; fired = []
        def mutate(source, target):
            result = original(source, target)
            if Path(target).parent.name == 'old' and not fired:
                fired.append(Path(target)); (self.paths[1] / 'personal' / 'keep').write_bytes(b'new user data')
            return result
        with mock.patch.object(os, 'replace', mutate), self.assertRaises(txn.JournalError): self.activate()
        self.assertEqual(1, len(fired))
        self.assertEqual(before['tree'][1]['identity'], ab.directory_identity(fired[0]))
        retained = self.f.tree(self.f.root)
        for cleanup in (False, True):
            with self.assertRaises(txn.JournalError): self.recover(cleanup)
            self.assertEqual(retained, self.f.tree(self.f.root))
        self.assertEqual(b'new user data', (self.paths[1] / 'personal' / 'keep').read_bytes())

    def test_both_projected_inventory_counts_refuse_without_publishing(self):
        for old, new in ((('alpha', 'beta'), ()), ((), ('alpha', 'gamma'))):
            with self.subTest(old=old, new=new):
                fixture = ActivationFixture(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
                record = fixture.build(old=old, new=new); before = fixture.observe()
                with mock.patch.object(txn, 'MAX_CLEANUP_ENTRIES', 0):
                    with self.assertRaises(txn.JournalError): fixture.owner._project_activation_cleanup(record)
                self.assertEqual(before, fixture.observe())

    def test_terminal_inventory_capture_interruption_preserves_retry(self):
        self.old(); self.activate(); terminal = self.live(); capture = txn.JournalAuthority._capture_activation_cleanup
        for after in (False, True):
            fired = []; retained = self.f.tree(self.f.root)
            def cut(owner, record):
                if not after:
                    fired.append(True); raise KeyboardInterrupt('before inventory')
                result = capture(owner, record); fired.append(True); raise KeyboardInterrupt('after inventory')
            with mock.patch.object(txn.JournalAuthority, '_capture_activation_cleanup', cut), self.assertRaises(KeyboardInterrupt):
                self.recover(True)
            self.assertEqual([True], fired); self.assertEqual(retained, self.f.tree(self.f.root))
        self.recover(True); self.recover(True); self.assertEqual(terminal, self.live())

    def test_empty_selection_metadata_interruption_restores_original_objects(self):
        self.old(); before = self.live(); self.f.write_resolver_fixture([self.f.entry()], seed=[])
        original = os.replace; fired = []
        def cut(source, target):
            result = original(source, target)
            if Path(target) == self.paths[2]:
                fired.append(True); raise KeyboardInterrupt('empty selection manifest replaced')
            return result
        with mock.patch.object(accp, 'runtime_owner', side_effect=AssertionError('empty runtime')):
            with mock.patch.object(os, 'replace', cut), self.assertRaises(KeyboardInterrupt):
                accp.cmd_activate(self.args)
            self.assertEqual([True], fired)
            self.assertEqual([], self.owner.load_activation()['new_ids'])
            self.assertTrue(self.recover()['rolled_back']); self.recover(True)
        after = self.live(); self.assertEqual(before['tree'], after['tree'])
        for key in ('manifest', 'state'): self.assertEqual(before[key]['sha256'], after[key]['sha256'])

    def test_v2_external_authority_blocks_absent_local_indicators_before_runtime(self):
        self.old(); before = self.live(); publish = txn.JournalAuthority.publish_journal; fired = []
        def cut(owner, record, previous=None):
            result = publish(owner, record, previous)
            if record['phase'] == 'PREPARED':
                fired.append(True); raise KeyboardInterrupt('retained v2 authority')
            return result
        with mock.patch.object(txn.JournalAuthority, 'publish_journal', cut), self.assertRaises(KeyboardInterrupt):
            self.activate()
        self.assertEqual([True], fired)
        saved = []
        for path in (self.owner.lock_path, self.owner.locator):
            target = self.f.root / ('retained-' + path.name); path.rename(target); saved.append((path, target))
        retained = self.f.tree(self.f.root)
        with mock.patch.object(accp, 'runtime_owner', side_effect=AssertionError('unsafe runtime access')):
            with self.assertRaises(txn.JournalError): accp.cmd_activate(self.args)
        self.assertEqual(retained, self.f.tree(self.f.root)); self.assertEqual(before, self.live())
        # Restore only the disposable original indicators to exercise recovery;
        # neither production activation nor recovery repairs missing authority.
        for path, target in saved: target.rename(path)
        self.assertTrue(self.recover()['rolled_back']); self.recover(True)
        self.assertEqual(before, self.live())


def final_drift(kind):
    def test(self):
        self.old(); before = self.live(); validate = accp.activation.ActivationAttempt.validate; fired = []
        def changed(attempt, args, plan, paths, stage=None):
            if stage is not None:
                fired.append(kind)
                if kind == 'expired': attempt.phase = 'expired'
                elif kind == 'nonce': attempt.nonce = '00000000-0000-4000-8000-000000000001'
                elif kind == 'request': args.allow_partial = True
                elif kind == 'scope': args.scope = 'user'
                elif kind == 'candidate': plan['providers'] = []
                elif kind == 'receipt':
                    accp.ready_runtime_binding.return_value = dict(self.f.fixture_rb,
                        runtime_id='00000000-0000-4000-8000-000000000001')
                elif kind == 'invocation': self.f.change_entry(invocation='implicit')
                elif kind == 'rereview':
                    path = self.f.evidence_dir / 'fixture.json'
                    ev = ab.decode_evidence(path.read_bytes()); ev['reviewed_at'] = '2026-09-20T00:00:00Z'
                    raw = ab.encode_evidence(ev); path.write_bytes(raw)
                    locks = accp.readj(accp.LOCK, strict=True)
                    locks['sources']['fixture']['evidence_sha256'] = hashlib.sha256(raw).hexdigest()
                    self.f._write(accp.LOCK, locks)
                    vault = accp.VAULT / 'fixture' / '.accp-vault-manifest.json'
                    manifest = json.loads(vault.read_bytes()); manifest['evidence_sha256'] = hashlib.sha256(raw).hexdigest()
                    vault.write_bytes(ab.canonical_json(manifest) + b'\n')
                    self.assertEqual(['fixture'], accp.resolve_plan('smoke', self.f.project)['providers'])
                else: raise AssertionError(kind)
            return validate(attempt, args, plan, paths, stage)
        with mock.patch.object(accp.activation.ActivationAttempt, 'validate', changed):
            with self.assertRaises((txn.JournalError, ab.BindingError)): self.activate()
        self.assertEqual([kind], fired); self.assertFalse(accp._activation_attempts)
        self.assertEqual(before, self.live()); self.assertEqual('APPLYING', self.owner.load_activation()['phase'])
        # Restore CLI request only; recovery must not consult changed approval or receipt.
        self.args.allow_partial = False; self.args.scope = 'project'
        with mock.patch.object(accp, 'activation_admission', side_effect=AssertionError('recovery admission')):
            self.assertTrue(self.recover()['rolled_back']); self.recover(True)
        self.assertEqual(before, self.live())
    return test


for _kind in ('expired', 'nonce', 'request', 'scope', 'candidate', 'receipt', 'invocation', 'rereview'):
    setattr(ActivationBoundaryAdversarial, 'test_final_proof_' + _kind, final_drift(_kind))


if __name__ == '__main__': unittest.main()
