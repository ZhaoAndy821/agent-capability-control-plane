import copy
import json
import os
import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import test_e2e as fixture

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import artifact_binding as ab


class BindingMaterialize(unittest.TestCase):
    """M2 binding checks against the real CLI and disposable E2E fixture."""

    def setUp(self):
        self.fx = fixture.E2E()
        fixture.E2E.setUp(self.fx)

    def tearDown(self):
        fixture.E2E.tearDown(self.fx)

    def call(self, *args, **kwargs):
        return self.fx.call(*args, **kwargs)

    def approve_lock(self):
        return self.fx.approve_lock()

    def approve_lock_without_materialize(self):
        return self.fx.approve_lock_without_materialize()

    def test_materialize_batch_rejects_foreign_binding_before_runtime_work(self):
        self.approve_lock_without_materialize()
        catalog_path = self.fx.cp / "registry/catalog.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        bad = copy.deepcopy(catalog["entries"][0])
        bad["id"] = "foreign-bound"
        bad["name"] = "Foreign bound"
        catalog["entries"].append(bad)
        self.fx.wj("registry/catalog.json", catalog)
        lock_path = self.fx.cp / "lock/sources.lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["sources"]["foreign-bound"] = copy.deepcopy(lock["sources"]["fixture-safe"])
        lock["sources"]["foreign-bound"]["evidence"] = "audit/evidence/foreign-bound.json"
        (self.fx.cp/'audit/evidence/foreign-bound.json').write_bytes(
            (self.fx.cp/'audit/evidence/fixture-safe.json').read_bytes())
        self.fx.wj_abs(lock_path, lock)
        unused = self.fx.base / "unused-runtime"
        self.fx.env["ACCP_RUNTIME_ROOT"] = str(unused)
        before = self.fx.snapshot_tree()
        for command in (("materialize", "fixture-safe", "foreign-bound"),):
            result = self.call(*command, ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(before, self.fx.snapshot_tree())
        self.assertFalse(unused.exists())

    def test_activation_rejects_tampered_vault_and_preserves_active_state(self):
        self.approve_lock()
        self.call("activate", "--mode", "smoke", "--project", str(self.fx.project))
        active = self.fx.project / ".agents/skills/fixture-safe"
        active_before = {p: p.read_bytes() for p in active.rglob("*") if p.is_file()}
        state_path = self.fx.project / ".agents/active-state.json"
        manifest_path = self.fx.project / ".agents/install-manifest.json"
        state_before = state_path.read_bytes()
        manifest_before = manifest_path.read_bytes()
        vault = self.fx.base / "runtime/vault/skills/fixture-safe"
        (vault / "SKILL.md").write_text("tampered\n", encoding="utf-8")
        vault_manifest_path = vault / ab.MANIFEST
        vault_manifest = json.loads(vault_manifest_path.read_text(encoding="utf-8"))
        vault_manifest["artifact_tree_sha256"] = ab.digest(
            "accp-artifact-tree-v1", ab.inventory_tree(vault, vault=True))
        vault_manifest_path.write_bytes(ab.canonical_json(vault_manifest) + b"\n")
        result = self.call("activate", "--mode", "smoke", "--project", str(self.fx.project), ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state_before, state_path.read_bytes())
        self.assertEqual(manifest_before, manifest_path.read_bytes())
        self.assertEqual(active_before, {p: p.read_bytes() for p in active.rglob("*") if p.is_file()})

    def test_materialize_refuses_uploadpack_hook_before_fetch_or_marker_execution(self):
        marker = self.fx.base / "pack-hook-ran"
        self.approve_lock_without_materialize()
        subprocess_config = ["git", "-C", str(self.fx.up), "config", "uploadpack.packObjectsHook",
                             "cmd /c echo ran>" + str(marker)]
        subprocess.run(subprocess_config, check=True)
        before = self.fx.snapshot_tree()
        for command in (("fetch", "fixture-safe"), ("materialize", "fixture-safe")):
            result = self.call(*command, ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(before, self.fx.snapshot_tree())
        self.assertFalse(marker.exists())

    def test_catalog_drift_after_raw_export_keeps_live_vault_unpublished(self):
        self.approve_lock_without_materialize()
        runner=self.fx.base/'drift_cli.py'
        runner.write_text(
            'import sys,pathlib,json\n'
            f'sys.path.insert(0,{str(self.fx.cp/"scripts")!r})\n'
            'import runtime_ownership,accp\n'
            f'runtime_ownership.principal_and_profile=lambda:("sid:S-1-5-21-1234",pathlib.Path({str(self.fx.base/"home")!r}))\n'
            'original=accp.binding.export_locked_tree\n'
            'def drift(*args,**kwargs):\n'
            '    result=original(*args,**kwargs)\n'
            '    record=json.loads(accp.CATALOG.read_text())\n'
            '    record["entries"][0]["notes"]="late changed review context"\n'
            '    accp.CATALOG.write_text(json.dumps(record))\n'
            '    return result\n'
            'accp.binding.export_locked_tree=drift\n'
            'raise SystemExit(accp.main())\n',encoding='utf-8')
        self.fx.cli=runner
        sentinel=self.fx.base/'runtime/personal';sentinel.write_bytes(b'unrelated')
        result=self.call('materialize','fixture-safe',ok=False)
        self.assertNotEqual(result.returncode,0)
        vault=self.fx.base/'runtime/vault/skills'
        self.assertFalse((vault/'fixture-safe').exists())
        self.assertEqual(sentinel.read_bytes(),b'unrelated')
        self.assertTrue(list(vault.glob('.stage-fixture-safe-*')))

    def test_raw_tree_empty_directory_and_executable_survive_materialization(self):
        def git(*args, data=None):
            return subprocess.check_output(['git','-C',str(self.fx.up),*args],input=data).decode().strip()
        skill=git('hash-object','-w','--stdin',data=b'---\nname: fixture-safe\n---\nraw bytes\r\n')
        script=git('hash-object','-w','--stdin',data=b'#!/bin/sh\necho fixture\n')
        empty=git('mktree',data=b'')
        tree=git('mktree',data=(f'100644 blob {skill}\tSKILL.md\n40000 tree {empty}\tempty\n'
                               f'100755 blob {script}\trun.sh\n').encode())
        root=git('mktree',data=f'40000 tree {tree}\tskill\n'.encode())
        self.fx.sha=git('commit-tree',root,data=b'raw fixture\n')
        git('update-ref','HEAD',self.fx.sha)
        self.approve_lock()
        vault=self.fx.base/'runtime/vault/skills/fixture-safe'
        evidence=ab.read_bound_record(self.fx.cp/'audit/evidence/fixture-safe.json').value
        self.assertEqual(evidence['candidate']['source_tree_oid'],tree)
        self.assertEqual(evidence['executable_surface'],['run.sh'])
        self.assertTrue((vault/'empty').is_dir())
        self.assertEqual(list((vault/'empty').iterdir()),[])
        self.assertEqual((vault/'SKILL.md').read_bytes(),b'---\nname: fixture-safe\n---\nraw bytes\r\n')
        self.assertEqual((vault/'run.sh').read_bytes(),b'#!/bin/sh\necho fixture\n')
        self.assertEqual((vault/'agents/openai.yaml').read_bytes(),ab.policy_bytes('explicit'))
        self.assertEqual(ab.inventory_tree(vault,vault=True),evidence['artifact_inventory'])
        if os.name!='nt': self.assertEqual((vault/'run.sh').stat().st_mode & 0o777,0o755)
        for path in (self.fx.cp/'audit/evidence/fixture-safe.json',self.fx.cp/'lock/sources.lock.json',vault/ab.MANIFEST):
            raw=path.read_bytes()
            self.assertEqual(raw,ab.canonical_json(json.loads(raw))+b'\n')
        self.assertTrue(evidence['reviewed_at'].endswith('Z'))
        self.assertTrue(ab.read_bound_record(vault/ab.MANIFEST).value['materialized_at'].endswith('Z'))

    def test_staged_manifest_drift_is_refused_before_live_publication(self):
        self.approve_lock_without_materialize()
        runner=self.fx.base/'manifest_drift_cli.py'
        runner.write_text(
            'import sys,pathlib,json\n'
            f'sys.path.insert(0,{str(self.fx.cp/"scripts")!r})\n'
            'import runtime_ownership,accp\n'
            f'runtime_ownership.principal_and_profile=lambda:("sid:S-1-5-21-1234",pathlib.Path({str(self.fx.base/"home")!r}))\n'
            'original=accp.recheck_materialize\n'
            'def drift(*args,**kwargs):\n'
            '    result=original(*args,**kwargs)\n'
            '    for stage in accp.VAULT.glob(".stage-*"):\n'
            '        path=stage/accp.binding.MANIFEST\n'
            '        record=json.loads(path.read_bytes())\n'
            '        record["candidate_sha256"]="0"*64\n'
            '        path.write_bytes(accp.binding.canonical_json(record)+b"\\n")\n'
            '    return result\n'
            'accp.recheck_materialize=drift\n'
            'raise SystemExit(accp.main())\n',encoding='utf-8')
        self.fx.cli=runner
        result=self.call('materialize','fixture-safe',ok=False)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('stage identity/manifest drift before publication',result.stderr)
        vault=self.fx.base/'runtime/vault/skills'
        self.assertFalse((vault/'fixture-safe').exists())
        self.assertTrue(list(vault.glob('.stage-fixture-safe-*')))


if __name__ == "__main__":
    unittest.main()
