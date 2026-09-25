"""R1 authoritative, noncreating reports; every fixture stays repository-local."""
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

from test_activation_transaction import ActivationFixture
import test_admission as admission_fixture
import test_e2e
import test_deactivate_recovery as deactivate_fixture
import test_activation_process_crash as crash_fixture
import accp
import active_transaction as txn


class ReaderStates(ActivationFixture):
    def preflight(self):
        with mock.patch.object(accp,'ROOT',self.cp):
            return accp.read_install_manifest(self.base,self.skills,self.im,self.state,self.project,self.owner.scope)

    def report(self,operation='status',expected=None):
        before=self.observe()
        result=self.owner.reader_report(self.preflight,lambda:accp.assert_plain_tree(self.skills),operation=operation)
        self.assertEqual(before,self.observe(),'reader mutated bytes/identity/mode')
        self.assertFalse(result['admission_authority'])
        if expected: self.assertEqual(expected,result['lifecycle'],result)
        return result

    def test_unenrolled_and_settled_absent_installation(self):
        self.owner.lock_path.unlink()
        result=self.report(expected='UNCOORDINATED')
        self.assertIsNone(result['current_generation']); self.assertEqual(2,self.owner.reader_exit(result))
        self.base.rmdir()
        self.report(expected='UNCOORDINATED'); self.assertFalse(self.base.exists())
        self.base.mkdir(); self.owner.lock_path.write_bytes(b'')
        result=self.report(expected='SETTLED')
        self.assertEqual([],result['current_generation']['managed_ids'])
        self.assertFalse(result['current_generation']['skills_exists'])

    def test_settled_pair_and_unmanaged_are_verified(self):
        self.skills.mkdir(); (self.skills/'alpha').mkdir(); (self.skills/'personal').write_bytes(b'user')
        for path,data in zip((self.im,self.state),self.metadata(['alpha'])): path.write_bytes(data)
        report=self.report(expected='SETTLED')
        self.assertEqual(['alpha'],report['current_generation']['managed_ids'])
        self.state.write_bytes(self.metadata([])[1]); self.report(expected='UNKNOWN')
        self.state.unlink(); self.report(expected='UNKNOWN')

    def test_prepared_partial_switch_and_rollback_agree(self):
        self.build(); self.report(expected='RECOVERY_REQUIRED')
        self.applying(); self.move_old('alpha')
        report=self.report(expected='RECOVERY_REQUIRED'); self.assertIsNone(report['current_generation'])
        self.assertEqual('rollback',self.report('recover')['preview']['action'])
        self.assertEqual('blocked',self.report('activate')['preview']['admission'])
        self.assertEqual('blocked',self.report('cleanup')['preview']['admission'])
        self.owner.recover(self.preflight,lambda:accp.assert_plain_tree(self.skills))
        report=self.report(expected='TERMINAL_RETAINED')
        self.assertEqual('rolled_back',report['transaction']['outcome'])
        self.assertEqual(['alpha','beta'],report['current_generation']['managed_ids'])
        self.assertEqual('finalize',self.report('cleanup')['preview']['action'])
        self.owner.cleanup(self.preflight,lambda:accp.assert_plain_tree(self.skills))
        self.report(expected='SETTLED')

    def test_committed_and_partial_cleanup_only_report_live_generation(self):
        self.build(); self.committed()
        report=self.report(expected='TERMINAL_RETAINED')
        self.assertEqual(['alpha','gamma'],report['current_generation']['managed_ids'])
        self.assertEqual('retain',self.report('recover')['preview']['action'])
        self.cleanup_record(); (self.workspace/'old'/'alpha'/'SKILL.md').unlink()
        self.report(expected='FINALIZATION_REQUIRED')
        self.assertEqual('blocked',self.report('recover')['preview']['admission'])
        self.assertEqual('finalize',self.report('cleanup')['preview']['action'])

    def test_pristine_missing_locator_is_recovery_not_safe_absence(self):
        self.build(prepared=False); self.owner.locator.unlink()
        self.report(expected='RECOVERY_REQUIRED')
        self.owner.lock_path.unlink()
        self.report(expected='UNKNOWN')

    def test_malformed_pending_foreign_stale_records(self):
        self.build(); original=self.owner.journal.read_bytes()
        for raw in (b'{',b'{}',original.replace(b'PREPARED',b'UNKNOWN!'),
                    original.replace(b'"schema_version":2',b'"schema_version":99'),
                    original.replace(b'"scope":"project"',b'"scope":"user"')):
            with self.subTest(raw=raw[:30]):
                self.owner.journal.write_bytes(raw); self.report(expected='UNKNOWN')
        self.owner.journal.write_bytes(original)
        for path in (self.owner.journal_pending,self.owner.locator_pending):
            path.write_bytes(b'partial'); self.report(expected='UNKNOWN'); path.unlink()
        locator=self.owner.locator.read_bytes()
        self.owner.locator.write_bytes(b'{}'); self.report(expected='UNKNOWN')
        self.owner.locator.write_bytes(locator); self.owner.journal.unlink(); self.report(expected='UNKNOWN')

    def test_orphan_legacy_and_metadata_pending_refused(self):
        for name in ('.accp-txn-orphan','.skills-stage-old','.skills-backup-old',
                     '.install-manifest.json.fake.pending','.active-state.json.fake.pending'):
            path=self.base/name; path.mkdir(); self.report(expected='UNKNOWN'); path.rmdir()
        self.owner.legacy_lock.write_bytes(b'legacy'); self.report(expected='UNKNOWN')

    def test_replaced_identity_and_unknown_bytes_refuse(self):
        self.build(); self.applying(); self.move_old('alpha')
        (self.skills/'alpha').mkdir(); self.report(expected='UNKNOWN')
        (self.skills/'alpha').rmdir()
        (self.workspace/'old'/'alpha'/'SKILL.md').write_bytes(b'changed')
        self.report(expected='UNKNOWN')

    def test_foreign_checkout_project_base_and_transaction_bindings(self):
        self.build(); original=self.owner.journal.read_bytes()
        for field in ('control_plane_identity','project_identity','base_identity'):
            value=json.loads(original); value[field]['inode']='999999999'
            self.owner.journal.write_bytes(txn.json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n')
            self.report(expected='UNKNOWN')
        self.owner.journal.write_bytes(original)
        locator=json.loads(self.owner.locator.read_bytes()); locator['transaction_id']='00000000-0000-4000-8000-000000000001'
        self.owner.locator.write_bytes(json.dumps(locator).encode()); self.report(expected='UNKNOWN')

    @unittest.skipUnless(os.name=='nt','Windows junction boundary')
    def test_redirected_skills_and_external_store_are_unknown(self):
        self.skills.mkdir(); target=self.root/'outside'; target.mkdir(); (target/'sentinel').write_bytes(b'keep')
        self.skills.rmdir()
        for link in (self.skills,self.owner.store):
            if link.exists(): link.rmdir()
            made=subprocess.run([os.environ['COMSPEC'],'/c','mklink','/J',str(link),str(target)],capture_output=True)
            self.assertEqual(0,made.returncode,made.stderr)
            try:
                result=self.owner.reader_report(self.preflight,lambda:None)
                self.assertEqual('UNKNOWN',result['lifecycle'])
                self.assertEqual(b'keep',(target/'sentinel').read_bytes())
                self.assertEqual(['sentinel'],[p.name for p in target.iterdir()])
            finally: link.rmdir()

    def test_user_scope_terminal_and_empty_selection(self):
        self.base=self.root/'user-agents'; self.base.mkdir()
        self.owner=txn.JournalAuthority(self.cp,self.project,'user',self.base)
        self.owner.lock_path.write_bytes(b'')
        self.skills=self.base/'skills'; self.im=self.base/'install-manifest.json'; self.state=self.base/'active-state.json'
        self.build(old=(),new=(),absent=True,missing_metadata=True)
        self.report(expected='RECOVERY_REQUIRED'); self.committed()
        result=self.report(expected='TERMINAL_RETAINED')
        self.assertEqual('user',result['scope']); self.assertEqual([],result['current_generation']['managed_ids'])

    def test_hardlink_and_stream_boundary(self):
        self.skills.mkdir(); sentinel=self.root/'sentinel'; sentinel.write_bytes(b'outside')
        linked=self.skills/'linked'; os.link(sentinel,linked)
        self.report(expected='UNKNOWN'); linked.unlink()
        if os.name=='nt':
            stream=pathlib.Path(str(self.owner.lock_path)+':reader-test'); stream.write_bytes(b'stream')
            self.report(expected='UNKNOWN'); stream.unlink()

    def test_lock_contention_and_release_failure_do_not_bless(self):
        with self.owner.lifecycle_lock(create=False):
            other=txn.JournalAuthority(self.cp,self.project)
            result=other.reader_report(self.preflight,lambda:None)
            self.assertEqual('BUSY_OR_UNAVAILABLE',result['lifecycle'])
        original=txn.os_lock
        def release(fd,acquire):
            original(fd,acquire)
            if not acquire: raise OSError('release failure')
        with mock.patch.object(txn,'os_lock',side_effect=release):
            self.report(expected='UNKNOWN')

    def test_drift_after_snapshot_refuses_report(self):
        snapshot=self.owner.reader_snapshot; hits=[]
        def drift(*args):
            value=snapshot(*args); hits.append(1)
            if len(hits)==1: self.state.write_bytes(b'unknown')
            return value
        with mock.patch.object(self.owner,'reader_snapshot',side_effect=drift):
            result=self.owner.reader_report(self.preflight,lambda:None)
        self.assertEqual('UNKNOWN',result['lifecycle']); self.assertEqual(1,len(hits))


class ReaderAdmission(unittest.TestCase):
    setUp=admission_fixture.Admission.setUp; _write=staticmethod(admission_fixture.Admission._write)
    entry=admission_fixture.Admission.entry; lock=admission_fixture.Admission.lock
    write_resolver_fixture=admission_fixture.Admission.write_resolver_fixture
    setup_provider=admission_fixture.Admission.setup_provider
    tree=admission_fixture.Admission.tree; change_entry=admission_fixture.Admission.change_entry

    def setup_preview(self):
        self.setup_provider(); self.args.dry_run=True
        self.owner=txn.JournalAuthority(accp.ROOT,self.project)
        self.owner.base.mkdir(); self.owner.lock_path.write_bytes(b'')
        runtime=SimpleNamespace(lock_path=self.root/'runtime-mutex',validate=lambda:{'state':'ready'})
        patcher=mock.patch.object(accp,'runtime_owner',return_value=runtime)
        patcher.start(); self.addCleanup(patcher.stop)

    def preview(self,expected=0):
        before=self.tree(self.root)
        with redirect_stdout(io.StringIO()) as output:
            code=accp.cmd_activate(self.args)
        self.assertEqual(expected,code,output.getvalue()); self.assertEqual(before,self.tree(self.root))
        self.assertEqual({},accp._activation_attempts)
        return json.loads(output.getvalue())

    def test_valid_preview_never_issues_attempt_or_stage(self):
        self.setup_preview()
        with mock.patch.object(accp.activation,'ActivationAttempt',side_effect=AssertionError('attempt issued')):
            report=self.preview()
        self.assertEqual('validated_inputs',report['preview']['admission'])
        self.assertFalse(report['preview']['reservation'])
        self.assertEqual(['fixture'],report['preview']['plan']['providers'])

    def test_unenrolled_direct_helper_cannot_bypass(self):
        self.setup_provider(); self.args.dry_run=True
        self.preview(2)
        with redirect_stdout(io.StringIO()) as output:
            code=accp.activate_plan(self.args,self.plan,accp.active_paths(self.project,'project'))
        self.assertEqual(2,code); self.assertEqual('UNCOORDINATED',json.loads(output.getvalue())['lifecycle'])

    def test_current_policy_vault_and_runtime_writer_are_refused(self):
        self.setup_preview(); original=accp.CATALOG.read_bytes()
        self.change_entry(trust='quarantine'); self.preview(2); accp.CATALOG.write_bytes(original)
        mutex=self.root/'runtime-mutex'; mutex.write_bytes(b'writer'); self.preview(2); mutex.unlink()
        (accp.VAULT/'fixture'/'SKILL.md').write_bytes(b'substituted'); self.preview(2)

    def test_recheck_detects_late_admission_and_vault_drift(self):
        self.setup_preview(); observe=accp.activation.observe_vault; hits=[]
        def drift(*args):
            value=observe(*args); hits.append(1)
            if len(hits)==1: self.change_entry(trust='quarantine')
            return value
        with mock.patch.object(accp.activation,'observe_vault',side_effect=drift),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(2,accp.cmd_activate(self.args))
        self.assertEqual(1,len(hits)); self.assertEqual('UNKNOWN',json.loads(output.getvalue())['lifecycle'])
        self.assertFalse(self.owner.journal.exists()); self.assertFalse((self.owner.base/'skills').exists())

    def test_final_context_recheck_after_second_vault_observation(self):
        self.setup_preview(); observe=accp.activation.observe_vault; hits=[]
        def drift(*args):
            value=observe(*args); hits.append(1)
            if len(hits)==2: self.change_entry(trust='quarantine')
            return value
        with mock.patch.object(accp.activation,'observe_vault',side_effect=drift),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(2,accp.cmd_activate(self.args))
        self.assertEqual(2,len(hits)); self.assertEqual('UNKNOWN',json.loads(output.getvalue())['lifecycle'])

    def test_empty_preview_never_accesses_runtime(self):
        self.write_resolver_fixture([],seed=[])
        args=SimpleNamespace(mode='smoke',project=str(self.project),scope='project',allow_partial=False,dry_run=True)
        owner=txn.JournalAuthority(accp.ROOT,self.project); owner.base.mkdir(); owner.lock_path.write_bytes(b'')
        before=self.tree(self.root)
        with mock.patch.object(accp,'runtime_owner',side_effect=AssertionError('runtime accessed')),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(0,accp.cmd_activate(args))
        self.assertEqual([],json.loads(output.getvalue())['preview']['plan']['providers'])
        self.assertEqual(before,self.tree(self.root))

    def test_runtime_mutex_appearing_during_receipt_observation_refuses(self):
        self.setup_preview(); mutex=self.root/'runtime-mutex'
        def validate(): mutex.write_bytes(b'writer'); return {'state':'ready'}
        runtime=SimpleNamespace(lock_path=mutex,validate=validate)
        with self.assertRaisesRegex(RuntimeError,'runtime writer present'): accp.runtime_read_check(runtime)
        self.assertEqual(b'writer',mutex.read_bytes())


class ReaderV1(unittest.TestCase):
    def check_phase(self,phase):
        fx=deactivate_fixture.DeactivateRecovery(); fx.setUp()
        try:
            if phase in ('PREPARING','PREPARED','APPLYING','COMMITTED'): fx.interrupt(phase,after=True)
            else:
                fx.interrupt('COMMITTED')
                if phase=='ROLLING_BACK':
                    publish=txn.JournalAuthority.publish_journal; hits=[]
                    def stop(owner,record,previous=None):
                        value=publish(owner,record,previous)
                        if record['phase']=='ROLLING_BACK': hits.append(1); raise OSError('reader phase fault')
                        return value
                    with mock.patch.object(txn.JournalAuthority,'publish_journal',stop):
                        with self.assertRaises(txn.JournalError): fx.call()
                    self.assertEqual([1],hits)
                else: fx.call()
            record=fx.owner.parse(fx.owner.journal.read_bytes()); self.assertEqual(phase,record['phase'])
            observe=lambda:{str(p.relative_to(fx.root)):(p.stat().st_ino,p.read_bytes() if p.is_file() else None)
                            for p in fx.root.rglob('*')}
            before=observe()
            preflight=lambda:accp.read_install_manifest(fx.base,fx.skills,fx.im,fx.state,fx.project,'project')
            result=fx.owner.reader_report(preflight,lambda:accp.assert_plain_tree(fx.skills))
            terminal=phase in ('COMMITTED','ROLLED_BACK')
            self.assertEqual('TERMINAL_RETAINED' if terminal else 'RECOVERY_REQUIRED',result['lifecycle'],result)
            self.assertEqual(terminal,result['current_generation'] is not None)
            preview=fx.owner.reader_report(preflight,lambda:accp.assert_plain_tree(fx.skills),operation='recover')
            self.assertEqual('retain' if terminal else 'rollback',preview['preview']['action'])
            self.assertEqual(before,observe())
        finally: fx.doCleanups()


for _phase in ('PREPARING','PREPARED','APPLYING','ROLLING_BACK','COMMITTED','ROLLED_BACK'):
    setattr(ReaderV1,'test_v1_'+_phase.lower(),lambda self,phase=_phase:self.check_phase(phase))


class ReaderProcessBoundary(unittest.TestCase):
    def check_boundary(self,point,expected):
        fx=crash_fixture.ActivationProcessCrash(); fx.setUp()
        try:
            fx.prepare('project'); fx.launcher(point)
            command=(['recover','--cleanup',*fx.arguments] if point=='DONE' else
                     ['activate','--mode','smoke',*fx.arguments])
            if point=='DONE':
                fx.call('activate','--mode','smoke',*fx.arguments)
            result=fx.call(*command,ok=False); self.assertEqual(73,result.returncode,result.stderr+result.stdout)
            fx.remove_current_authority_inputs(); before=fx.snapshot_tree()
            result=fx.call('status',*fx.arguments,ok=False); report=json.loads(result.stdout)
            self.assertEqual(expected,report['lifecycle'],report)
            self.assertEqual(0 if expected in ('TERMINAL_RETAINED','FINALIZATION_REQUIRED') else 2,result.returncode)
            self.assertEqual(before,fx.snapshot_tree())
            if point=='DONE':
                owner=txn.JournalAuthority(fx.cp,fx.project); owner.locator.unlink()
                report=json.loads(fx.call('status',*fx.arguments).stdout)
                self.assertEqual('FINALIZATION_REQUIRED',report['lifecycle'])
        finally: fx.tearDown()


for _point,_expected in [('old-move','RECOVERY_REQUIRED'),('manifest-pending','UNKNOWN'),
                         ('COMMITTED','TERMINAL_RETAINED'),('DONE','FINALIZATION_REQUIRED')]:
    setattr(ReaderProcessBoundary,'test_process_'+_point.replace('-','_'),
            lambda self,point=_point,expected=_expected:self.check_boundary(point,expected))


class ReaderCLI(unittest.TestCase):
    def setUp(self):
        self.fx=test_e2e.E2E(); self.fx.setUp(); self.addCleanup(self.fx.tearDown)

    def test_real_cli_committed_cleanup_preview_and_runtime_audit(self):
        fx=self.fx; before=fx.snapshot_tree()
        result=fx.call('status','--project',str(fx.project),ok=False)
        self.assertEqual(2,result.returncode); self.assertEqual('UNCOORDINATED',json.loads(result.stdout)['lifecycle'])
        self.assertEqual(before,fx.snapshot_tree())
        fx.approve_lock(); fx.call('activate','--mode','smoke','--project',str(fx.project))
        before=fx.snapshot_tree()
        report=json.loads(fx.call('status','--project',str(fx.project)).stdout)
        self.assertEqual('TERMINAL_RETAINED',report['lifecycle'])
        for extra in ([],['--cleanup']):
            result=fx.call('recover','--project',str(fx.project),'--dry-run',*extra)
            self.assertEqual('validated_inputs',json.loads(result.stdout)['preview']['admission'])
        self.assertEqual(before,fx.snapshot_tree())
        fx.call('recover','--project',str(fx.project),'--cleanup'); before=fx.snapshot_tree()
        report=json.loads(fx.call('activate','--mode','smoke','--project',str(fx.project),'--dry-run').stdout)
        self.assertEqual('SETTLED',report['lifecycle'])
        audit=json.loads(fx.call('audit').stdout); self.assertFalse(audit['lifecycle_assessed'])
        self.assertEqual(before,fx.snapshot_tree())
        owner=txn.JournalAuthority(fx.cp,fx.project)
        with owner.lifecycle_lock(create=False):
            result=fx.call('status','--project',str(fx.project),ok=False)
            self.assertEqual(2,result.returncode)
            self.assertEqual('BUSY_OR_UNAVAILABLE',json.loads(result.stdout)['lifecycle'])

    @unittest.skipUnless(os.name=='nt','Windows PowerShell wrapper test')
    def test_powershell_audit_status_matches_python_exit_and_semantics(self):
        fx=self.fx; shim=fx.base/'bin'; shim.mkdir()
        launcher=shim/'python_shim.py'
        launcher.write_text('import runpy,sys\nsys.argv=[sys.argv[1],*sys.argv[2:]]\n'+
                           f'runpy.run_path({str(fx.cli)!r},run_name="__main__")\n',encoding='utf-8')
        (shim/'python.cmd').write_text('@"'+sys.executable+'" -B "'+str(launcher)+'" %*\r\n',encoding='ascii')
        env=dict(fx.env,PATH=str(shim)+os.pathsep+os.environ['PATH'])
        before=fx.snapshot_tree()
        cmd=['powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',str(fx.cp/'scripts/audit.ps1')]
        result=subprocess.run(cmd+['-Project',str(fx.project)],env=env,text=True,capture_output=True)
        self.assertEqual(2,result.returncode,result.stderr)
        self.assertEqual('UNCOORDINATED',json.loads(result.stdout)['lifecycle'])
        bad=subprocess.run(cmd+['-Vault','-Project',str(fx.project)],env=env,text=True,capture_output=True)
        self.assertEqual(2,bad.returncode)
        self.assertEqual(before,fx.snapshot_tree())
        owner=txn.JournalAuthority(fx.cp,fx.project); owner.base.mkdir()
        with owner.lifecycle_lock(): pass
        before=fx.snapshot_tree()
        result=subprocess.run(cmd+['-Project',str(fx.project)],env=env,text=True,capture_output=True)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual('SETTLED',json.loads(result.stdout)['lifecycle'])
        self.assertEqual(before,fx.snapshot_tree())
        fx.approve_lock(); before=fx.snapshot_tree()
        result=subprocess.run(cmd+['-Vault'],env=env,text=True,capture_output=True)
        self.assertEqual(0,result.returncode,result.stderr)
        report=json.loads(result.stdout); self.assertEqual('runtime_audit',report['report_kind'])
        self.assertFalse(report['lifecycle_assessed']); self.assertEqual(before,fx.snapshot_tree())


if __name__=='__main__': unittest.main()
