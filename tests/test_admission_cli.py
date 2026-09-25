import json
import pathlib
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).parent))
import test_e2e as fixture


class AdmissionCLI(unittest.TestCase):
    """M2 admission checks through the real disposable CLI fixture."""

    def setUp(self):
        self.fx = fixture.E2E()
        fixture.E2E.setUp(self.fx)

    def tearDown(self):
        fixture.E2E.tearDown(self.fx)

    def call(self, *args, **kwargs):
        return self.fx.call(*args, **kwargs)

    def wj(self, *args, **kwargs):
        return self.fx.wj(*args, **kwargs)

    def wj_abs(self, *args, **kwargs):
        return self.fx.wj_abs(*args, **kwargs)

    def snapshot_tree(self):
        return self.fx.snapshot_tree()

    def approve_lock(self):
        return self.fx.approve_lock()

    def approve_lock_without_materialize(self):
        return self.fx.approve_lock_without_materialize()

    def catalog(self):
        return json.loads((self.fx.cp / "registry/catalog.json").read_text(encoding="utf-8"))

    def lock(self):
        return json.loads((self.fx.cp / "lock/sources.lock.json").read_text(encoding="utf-8"))

    def write_catalog_entry(self, **changes):
        data = self.catalog()
        for key, value in changes.items():
            if isinstance(value, dict) and isinstance(data["entries"][0].get(key), dict):
                data["entries"][0][key].update(value)
            else:
                data["entries"][0][key] = value
        self.wj("registry/catalog.json", data)

    def assert_denied_everywhere(self, needle, *, already_locked=False):
        """Each gate must fail before changing the disposable tree."""
        if not already_locked:
            self.approve_lock_without_materialize()
        runtime_sentinel = self.fx.base / "runtime" / "vault" / "preserved.txt"
        runtime_sentinel.parent.mkdir(parents=True, exist_ok=True)
        runtime_sentinel.write_bytes(b"runtime sentinel")
        active_sentinel = self.fx.project / ".agents" / "skills" / "personal" / "keep.txt"
        active_sentinel.parent.mkdir(parents=True, exist_ok=True)
        active_sentinel.write_bytes(b"active sentinel")
        before = self.snapshot_tree()
        old_runtime = self.fx.env["ACCP_RUNTIME_ROOT"]
        self.fx.env["ACCP_USER_SCOPE_ROOT"] = str(self.fx.base / "user-agents")
        roots = (old_runtime, str(self.fx.base / "fresh-runtime"))
        for root in roots:
            self.fx.env["ACCP_RUNTIME_ROOT"] = root
            commands = [
                ("resolve", "--mode", "smoke", "--project", str(self.fx.project)),
                ("activate", "--mode", "smoke", "--project", str(self.fx.project)),
                ("activate", "--mode", "smoke", "--project", str(self.fx.project), "--dry-run"),
                ("activate", "--mode", "smoke", "--project", str(self.fx.project), "--scope", "user"),
                ("activate", "--mode", "smoke", "--project", str(self.fx.project), "--scope", "user", "--dry-run"),
                ("materialize", "fixture-safe"),
            ]
            for command in commands:
                with self.subTest(root=root, command=command):
                    cp = self.call(*command, ok=False)
                    self.assertNotEqual(cp.returncode, 0)
                    if '--dry-run' in command:
                        report=json.loads(cp.stdout)
                        self.assertEqual('UNCOORDINATED',report['lifecycle'])
                        self.assertEqual('blocked',report['preview']['admission'])
                    else:
                        self.assertIn(needle, cp.stderr)
                    self.assertEqual(before, self.snapshot_tree())
                    self.assertEqual(b"runtime sentinel", runtime_sentinel.read_bytes())
                    self.assertEqual(b"active sentinel", active_sentinel.read_bytes())
                    self.assertFalse((self.fx.project / ".agents" / "skills" / "fixture-safe").exists())
        self.fx.env["ACCP_RUNTIME_ROOT"] = old_runtime

    def test_inactive_adoption_trust_and_operational_shape_are_denied(self):
        variants = (
            ({"adoption": "quarantine"}, "adoption=quarantine"),
            ({"adoption": "candidate"}, "adoption=candidate"),
            ({"trust": "unreviewed"}, "trust=unreviewed"),
            ({"trust": "quarantine"}, "trust=quarantine"),
            ({"invocation": "dormant"}, "dormant provider refused"),
            ({"deploy": {"deployable": False}}, "not deployable"),
        )
        self.approve_lock()
        original = self.catalog()
        for changes, needle in variants:
            with self.subTest(changes=changes):
                self.write_catalog_entry(**changes)
                self.assert_denied_everywhere(needle, already_locked=True)
                self.wj("registry/catalog.json", original)

    def test_unknown_trust_and_unknown_dependency_are_denied_without_work(self):
        self.approve_lock()
        original = self.catalog()
        self.write_catalog_entry(trust="unknown")
        self.assert_denied_everywhere("invalid trust", already_locked=True)
        self.wj("registry/catalog.json", original)
        self.write_catalog_entry(runtime={"requires": ["not-an-installed-runtime"]})
        # Keep the reviewed catalog binding current, so this exercises dependency
        # refusal rather than the earlier F06 catalog-drift check.
        self.approve_lock_without_materialize()
        self.assert_denied_everywhere("unsupported dependency requirement", already_locked=True)

    def test_implicit_medium_and_string_high_risk_approval_are_denied(self):
        self.approve_lock()
        original = self.catalog()
        self.write_catalog_entry(invocation="implicit", risk="medium")
        self.assert_denied_everywhere("implicit invocation requires low risk", already_locked=True)
        self.wj("registry/catalog.json", original)
        self.write_catalog_entry(risk="high")
        lock = self.lock()
        lock["sources"]["fixture-safe"]["approval"]["high_risk"] = "true"
        lock_path = self.fx.cp / "lock/sources.lock.json"
        self.wj_abs(lock_path, lock)
        self.assert_denied_everywhere("approval.high_risk must be boolean", already_locked=True)

    def test_batch_materialize_preflight_denies_later_provider_before_work(self):
        self.approve_lock_without_materialize()
        before = self.snapshot_tree()
        cp = self.call("materialize", "fixture-safe", "later-denied", ok=False)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("later-denied: not locked", cp.stderr)
        self.assertEqual(before, self.snapshot_tree())

        self.approve_lock_without_materialize()
        data = self.catalog()
        alias = dict(data["entries"][0])
        alias["id"] = "fixture-denied"
        alias["name"] = "Denied alias"
        data["entries"].append(alias)
        self.wj("registry/catalog.json", data)
        self.call("fetch", "fixture-denied")
        self.call("review", "fixture-denied", "--commit", self.fx.sha, "--approve")
        self.call("pin", "fixture-denied")
        data["entries"][1]["trust"] = "unreviewed"
        self.wj("registry/catalog.json", data)
        before = self.snapshot_tree()
        cp = self.call("materialize", "fixture-safe", "fixture-denied", ok=False)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("trust=unreviewed", cp.stderr)
        self.assertEqual(before, self.snapshot_tree())

    def test_duplicate_catalog_evidence_and_lock_json_refuse_pin_without_rewrite(self):
        self.approve_lock_without_materialize()
        variants = (
            ("registry/catalog.json", b'{"schema_version":2,"schema_version":2,"entries":[]}'),
            ("audit/evidence/fixture-safe.json", b'{"status":"approved","status":"approved"}'),
            ("lock/sources.lock.json", b'{"schema_version":2,"sources":{},"sources":{}}'),
        )
        for relative, malformed in variants:
            path=self.fx.cp/relative; original=path.read_bytes()
            path.write_bytes(malformed); before=self.snapshot_tree()
            with self.subTest(path=relative):
                cp=self.call("pin","fixture-safe",ok=False)
                self.assertNotEqual(cp.returncode,0)
                self.assertIn("duplicate JSON key",cp.stderr)
                self.assertEqual(before,self.snapshot_tree())
            path.write_bytes(original)

    def test_owned_runtime_dry_run_and_project_user_activation_with_partial_approval(self):
        self.approve_lock_without_materialize()
        runtime = self.fx.base / "runtime"
        # No creating reader lock or unmaterialized-preview authority.
        before=self.snapshot_tree()
        cp = self.call("activate", "--mode", "smoke", "--project", str(self.fx.project), "--dry-run",ok=False)
        self.assertEqual(cp.returncode, 2)
        self.assertEqual('UNCOORDINATED',json.loads(cp.stdout)['lifecycle'])
        self.assertEqual(before,self.snapshot_tree())
        self.assertTrue(runtime.exists())

        self.write_catalog_entry(trust="partial")
        before=self.snapshot_tree()
        cp=self.call("materialize","fixture-safe","--allow-partial",ok=False)
        self.assertIn("partial/conditional provider needs explicit approval",cp.stderr)
        self.assertNotEqual(cp.returncode,0); self.assertEqual(before,self.snapshot_tree())
        self.call("fetch", "fixture-safe")
        self.call("review", "fixture-safe", "--commit", self.fx.sha, "--approve")
        self.call("pin", "fixture-safe", "--approve-partial")
        before=self.snapshot_tree()
        for command in (("materialize","fixture-safe"),
                        ("activate","--mode","smoke","--project",str(self.fx.project))):
            cp=self.call(*command,ok=False)
            self.assertNotEqual(cp.returncode,0)
            self.assertIn("partial/conditional provider needs explicit approval",cp.stderr)
            self.assertEqual(before,self.snapshot_tree())
        self.call("materialize", "fixture-safe", "--allow-partial")
        self.call("activate", "--mode", "smoke", "--project", str(self.fx.project), "--allow-partial")
        self.assertTrue((self.fx.project / ".agents/skills/fixture-safe/SKILL.md").exists())
        self.call('recover','--cleanup','--project',str(self.fx.project))
        before=self.snapshot_tree()
        preview=self.call('activate','--mode','smoke','--project',str(self.fx.project),'--allow-partial','--dry-run')
        self.assertEqual('validated_inputs',json.loads(preview.stdout)['preview']['admission'])
        self.assertEqual(before,self.snapshot_tree())

        user_root = self.fx.base / "user-agents"
        personal=user_root/"skills"/"personal"; personal.mkdir(parents=True)
        (personal/"keep").write_bytes(b"user sentinel")
        self.fx.env["ACCP_USER_SCOPE_ROOT"] = str(user_root)
        self.call("activate", "--mode", "smoke", "--project", str(self.fx.project), "--scope", "user", "--allow-partial")
        self.assertTrue((user_root / "skills/fixture-safe/SKILL.md").exists())
        self.assertEqual(b"user sentinel",(personal/"keep").read_bytes())


if __name__ == "__main__":
    unittest.main()
