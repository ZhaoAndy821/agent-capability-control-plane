import unittest, tempfile, pathlib, subprocess, json, os, shutil, hashlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import artifact_binding as ab

SRC=pathlib.Path(__file__).resolve().parents[1]

class E2E(unittest.TestCase):
    def setUp(self):
        # Keep Windows Git's transfer-helper paths short, within this repository.
        (SRC/'.local').mkdir(exist_ok=True)
        self.t=tempfile.TemporaryDirectory(prefix='e',dir=SRC/'.local'); self.base=pathlib.Path(self.t.name)
        self.cp=self.base/'cp'; shutil.copytree(SRC,self.cp,ignore=shutil.ignore_patterns('.git','__pycache__','.local'))
        self.up=self.base/'u'; self.up.mkdir(); subprocess.run(['git','init','-q',str(self.up)],check=True)
        subprocess.run(['git','-C',str(self.up),'config','user.email','test@example.invalid'],check=True)
        subprocess.run(['git','-C',str(self.up),'config','user.name','test'],check=True)
        (self.up/'skill').mkdir()
        (self.up/'skill/SKILL.md').write_text('---\nname: fixture-safe\ndescription: fixture\n---\n# Fixture\n',encoding='utf-8')
        subprocess.run(['git','-C',str(self.up),'add','.'],check=True); subprocess.run(['git','-C',str(self.up),'commit','-qm','fixture'],check=True)
        self.sha=subprocess.check_output(['git','-C',str(self.up),'rev-parse','HEAD'],text=True).strip()
        # file:// makes Git transfer objects instead of hard-linking the fixture.
        upstream_origin = ab.file_origin(self.up)
        cat={'schema_version':2,'entries':[{'id':'fixture-safe','name':'Fixture','kind':'skill','source_url':upstream_origin['url'],'source_resolution':'exact','adoption':'adopted','domains':['test'],'capabilities':['safe-test'],'conflict_group':None,'trust':'reviewed','risk':'low','invocation':'explicit','runtime':{'requires':[],'network':False,'credentials':[]},'deploy':{'deployable':True,'skill_name':'fixture-safe','path':'skill'},'notes':'','origin':'test'}]}
        self.wj('registry/catalog.json',cat); self.wj('registry/conflict-groups.json',{'schema_version':2,'source_of_truth':'registry/catalog.json::entries[].conflict_group','groups':{}})
        self.wj('modes/operational-modes.json',{'schema_version':1,'modes':{'smoke':{'providers':['fixture-safe']}}}); self.wj('modes/evaluation-modes.json',{'schema_version':1,'modes':{}})
        self.wj('lock/sources.lock.json',{'schema_version':2,'sources':{}})
        self.project=self.base/'project'; self.project.mkdir(); self.wj_abs(self.project/'.codex-skillset.json',{'schema_version':1,'allowed_operational_modes':['smoke'],'default_operational_mode':'smoke','include':[],'exclude':[],'capabilities':{'require':['safe-test'],'prefer':[],'forbid':[]}})
        self.env=os.environ.copy(); self.env['ACCP_RUNTIME_ROOT']=str(self.base/'runtime'); self.cli=self.cp/'scripts/accp.py'
        # The sandbox service account has no OS profile. Inject a test principal
        # in this disposable launcher, never through a production environment hook.
        runner=self.base/'fixture_cli.py'
        runner.write_text(
            'import pathlib, runpy, sys\n'
            f'sys.path.insert(0, {str(self.cp/"scripts")!r})\n'
            'import runtime_ownership\n'
            f'runtime_ownership.principal_and_profile = lambda: ("sid:S-1-5-21-1234", pathlib.Path({str(self.base/"home")!r}))\n'
            f'runpy.run_path({str(self.cli)!r}, run_name="__main__")\n', encoding='utf-8')
        self.cli=runner
    def tearDown(self): self.t.cleanup()
    def wj(self,p,o): self.wj_abs(self.cp/p,o)
    def wj_abs(self,p,o): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(o,indent=2)+'\n',encoding='utf-8')
    def call(self,*a,ok=True):
        cp=subprocess.run([sys.executable,str(self.cli),*a],env=self.env,text=True,capture_output=True)
        if ok and cp.returncode!=0: self.fail(cp.stderr+'\n'+cp.stdout)
        return cp
    def approve_lock(self):
        self.call('fetch','fixture-safe'); self.call('review','fixture-safe','--commit',self.sha,'--approve','--notes','fixture audit'); self.call('pin','fixture-safe'); self.call('materialize','fixture-safe')
    def approve_lock_without_materialize(self):
        self.call('fetch','fixture-safe'); self.call('review','fixture-safe','--commit',self.sha,'--approve','--notes','fixture audit'); self.call('pin','fixture-safe')
    def snapshot_tree(self):
        out={}
        for p in sorted(self.base.rglob('*')):
            rel=p.relative_to(self.base).as_posix()
            info=p.lstat(); identity=(info.st_dev,info.st_ino,info.st_nlink)
            if p.is_file(): out[rel]=('file',identity,p.read_bytes())
            elif p.is_dir(): out[rel]=('dir',identity)
        return out
    def test_lock_first_and_atomic_activation(self):
        self.assertNotEqual(self.call('materialize','fixture-safe',ok=False).returncode,0)
        self.approve_lock()
        self.call('activate','--mode','smoke','--project',str(self.project))
        active=self.project/'.agents/skills/fixture-safe'
        self.assertTrue((active/'SKILL.md').exists())
        self.assertIn('allow_implicit_invocation: false',(active/'agents/openai.yaml').read_text())
        old=(active/'SKILL.md').read_bytes()
        self.call('recover','--cleanup','--project',str(self.project))
        # Corrupt Vault. Activation must fail during preflight and old Active Set must remain byte-identical.
        vault=self.base/'runtime/vault/skills/fixture-safe/SKILL.md'; vault.write_text('corrupt',encoding='utf-8')
        cp=self.call('activate','--mode','smoke','--project',str(self.project),ok=False)
        self.assertNotEqual(cp.returncode,0); self.assertEqual(old,(active/'SKILL.md').read_bytes())
    def test_concurrent_lock_is_deterministic(self):
        self.approve_lock(); lock=self.project/'.agents/.accp-activate.lock'; lock.parent.mkdir(parents=True,exist_ok=True); lock.write_text('held')
        cp=self.call('activate','--mode','smoke','--project',str(self.project),ok=False)
        self.assertIn('legacy lock requires manual inspection',cp.stderr)
        self.assertFalse((self.project/'.agents/skills/fixture-safe').exists())

    def test_cli_staged_substitution_refuses_without_live_or_metadata_mutation(self):
        self.approve_lock()
        self.call('activate','--mode','smoke','--project',str(self.project))
        self.call('recover','--cleanup','--project',str(self.project))
        base=self.project/'.agents'
        personal=base/'skills/personal'; personal.mkdir()
        (personal/'keep').write_bytes(b'personal\x00\xff')
        def snapshot():
            return {p.relative_to(base).as_posix():
                    (p.stat().st_ino,p.read_bytes() if p.is_file() else None)
                    for p in [base/'skills', *list((base/'skills').rglob('*')),
                              base/'install-manifest.json', base/'active-state.json']}
        before=snapshot()
        # Fault injection belongs solely to this disposable CLI launcher.
        runner=self.cli.read_text(encoding='utf-8')
        injection=(
            'import shutil\n'
            '_copy = shutil.copytree\n'
            'def corrupt(src, dst, *args, **kwargs):\n'
            '    result = _copy(src, dst, *args, **kwargs)\n'
            '    target = pathlib.Path(dst)\n'
            '    if target.name == "fixture-safe" and target.parent.name == "new" and target.parent.parent.name.startswith(".accp-txn-"):\n'
            '        (target / "SKILL.md").write_bytes(b"unreviewed staged bytes")\n'
            '    return result\n'
            'shutil.copytree = corrupt\n')
        self.cli.write_text(runner.replace('runpy.run_path(',injection+'runpy.run_path('),encoding='utf-8')
        result=self.call('activate','--mode','smoke','--project',str(self.project),ok=False)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Vault artifact content mismatch',result.stderr)
        self.assertEqual(before,snapshot())
    def test_reactivate_and_deactivate_preserve_unmanaged(self):
        self.approve_lock()
        unmanaged=self.project/'.agents/skills/personal'; unmanaged.mkdir(parents=True)
        sentinel=unmanaged/'keep.txt'; sentinel.write_bytes(b'personal skill')
        for _ in range(2):
            self.call('activate','--mode','smoke','--project',str(self.project))
            self.assertEqual(sentinel.read_bytes(),b'personal skill')
            self.call('recover','--cleanup','--project',str(self.project))
        self.call('deactivate','--project',str(self.project))
        self.assertFalse((self.project/'.agents/skills/fixture-safe').exists())
        self.assertEqual(sentinel.read_bytes(),b'personal skill')
        self.call('deactivate','--project',str(self.project))
        self.assertEqual(sentinel.read_bytes(),b'personal skill')
    def test_candidate_unreviewed_denied(self):
        cat=json.loads((self.cp/'registry/catalog.json').read_text()); cat['entries'][0]['adoption']='candidate'; cat['entries'][0]['trust']='unreviewed'; self.wj('registry/catalog.json',cat)
        self.call('fetch','fixture-safe'); self.call('review','fixture-safe','--commit',self.sha,'--approve'); self.call('pin','fixture-safe')
        cp=self.call('materialize','fixture-safe',ok=False); self.assertNotEqual(cp.returncode,0)
    def test_owned_runtime_uninstall_preserves_active_set_and_unknown_contents(self):
        self.approve_lock()
        self.call('activate','--mode','smoke','--project',str(self.project))
        runtime=self.base/'runtime'
        sentinel=runtime/'personal.txt'; sentinel.write_bytes(b'preserve')
        plan=json.loads(self.call('uninstall','--dry-run').stdout)
        self.assertEqual(plan['state'],'ready')
        self.call('uninstall','--yes')
        self.assertEqual(sentinel.read_bytes(),b'preserve')
        self.assertTrue((runtime/'.accp-runtime-owner.json').exists())
        self.assertFalse((runtime/'sources').exists())
        self.assertFalse((runtime/'vault').exists())
        self.assertTrue((self.project/'.agents/skills/fixture-safe/SKILL.md').exists())
        self.call('uninstall','--yes')
    def test_bootstrap_legacy_refusal_and_dry_run_have_no_personal_writes(self):
        home=self.base/'personal-home'; self.env['ACCP_USER_HOME']=str(home)
        legacy=self.base/'runtime'; legacy.mkdir()
        (legacy/'keep').write_bytes(b'legacy')
        self.assertNotEqual(self.call('bootstrap',ok=False).returncode,0)
        self.assertFalse(home.exists())
        self.assertEqual((legacy/'keep').read_bytes(),b'legacy')
        fresh=self.base/'fresh'; self.env['ACCP_RUNTIME_ROOT']=str(fresh)
        self.call('bootstrap','--dry-run')
        self.assertFalse(fresh.exists()); self.assertFalse(home.exists())
        self.call('bootstrap')
        self.assertTrue((home/'.codex/agents').is_dir())
        self.call('uninstall','--yes')
        self.assertTrue((home/'.codex/agents').is_dir())

    def test_resolver_refuses_forbidden_plan_before_runtime_or_active_mutation(self):
        self.approve_lock()
        policy=json.loads((self.project/'.codex-skillset.json').read_text(encoding='utf-8'))
        policy['capabilities']['forbid']=['safe-test']
        self.wj_abs(self.project/'.codex-skillset.json',policy)
        before=self.snapshot_tree()
        cp=self.call('activate','--mode','smoke','--project',str(self.project),ok=False)
        self.assertNotEqual(cp.returncode,0)
        self.assertIn('required capabilities intersect forbid',cp.stderr)
        self.assertEqual(before,self.snapshot_tree())
        self.assertFalse((self.project/'.agents/skills/fixture-safe').exists())

    def test_resolver_exclude_refusal_preserves_unmaterialized_tree(self):
        self.approve_lock_without_materialize()
        fresh=self.base/'unused-runtime'; self.env['ACCP_RUNTIME_ROOT']=str(fresh)
        policy=json.loads((self.project/'.codex-skillset.json').read_text(encoding='utf-8'))
        policy['exclude']=['fixture-safe']; policy['capabilities']['require']=['safe-test']
        self.wj_abs(self.project/'.codex-skillset.json',policy)
        before=self.snapshot_tree()
        cp=self.call('resolve','--mode','smoke','--project',str(self.project),ok=False)
        self.assertNotEqual(cp.returncode,0); self.assertEqual(before,self.snapshot_tree())
        self.assertIn('required capability',cp.stderr)
        cp=self.call('activate','--mode','smoke','--project',str(self.project),ok=False)
        self.assertNotEqual(cp.returncode,0); self.assertEqual(before,self.snapshot_tree())
        self.assertIn('required capability',cp.stderr); self.assertFalse(fresh.exists())

    def test_multi_capability_forbidden_automatic_candidate_refuses_without_runtime(self):
        self.approve_lock_without_materialize()
        fresh=self.base/'unused-runtime'; self.env['ACCP_RUNTIME_ROOT']=str(fresh)
        cat=json.loads((self.cp/'registry/catalog.json').read_text(encoding='utf-8'))
        cat['entries'][0]['capabilities']=['safe-test','blocked-capability']
        self.wj('registry/catalog.json',cat)
        self.wj('modes/operational-modes.json',{'schema_version':1,'modes':{'smoke':{'providers':[]}}})
        policy=json.loads((self.project/'.codex-skillset.json').read_text(encoding='utf-8'))
        policy['capabilities']['require']=['safe-test']; policy['capabilities']['forbid']=['blocked-capability']
        self.wj_abs(self.project/'.codex-skillset.json',policy)
        before=self.snapshot_tree()
        for command in (('resolve','--mode','smoke','--project',str(self.project)),
                        ('activate','--mode','smoke','--project',str(self.project))):
            cp=self.call(*command,ok=False)
            self.assertNotEqual(cp.returncode,0); self.assertEqual(before,self.snapshot_tree())
            self.assertIn('required capability',cp.stderr)
            self.assertIn('violates capabilities.forbid',cp.stderr)
            self.assertFalse(fresh.exists())

if __name__=='__main__': unittest.main()
