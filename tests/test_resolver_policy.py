import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import accp
import artifact_binding as ab


class ResolverFixture(unittest.TestCase):
    """Small, real JSON/evidence fixtures for the resolver contract."""
    def setUp(self):
        local = pathlib.Path(__file__).resolve().parents[1] / ".local" / "audit-temp"
        local.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="accp-f04-", dir=str(local))
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        for d in ("registry", "modes", "lock", "audit/evidence"):
            (self.root / d).mkdir(parents=True)
        self.project = self.root / "project"
        self.project.mkdir()
        self._patch = mock.patch.multiple(
            accp, ROOT=self.root, CATALOG=self.root / "registry/catalog.json",
            CONFLICTS=self.root / "registry/conflict-groups.json",
            OP_MODES=self.root / "modes/operational-modes.json",
            EVAL_MODES=self.root / "modes/evaluation-modes.json",
            LOCK=self.root / "lock/sources.lock.json",
            EVIDENCE=self.root / "audit/evidence")
        self._patch.start()
        self.addCleanup(self._patch.stop)
        self.catalog = {}
        self.modes = {"schema_version": 1, "modes": {"smoke": {"providers": []}}}
        self.conflicts = {"schema_version": 2, "source_of_truth": "registry/catalog.json::entries[].conflict_group", "groups": {}}

    def tearDown(self):
        pass

    def add(self, ident, caps, *, group=None, deployable=True, requires=None, credentials=None,
            adoption="adopted", trust="reviewed"):
        self.catalog[ident] = {"id": ident, "name": ident, "kind": "skill",
            "source_url": "https://example.invalid/" + ident, "source_resolution": "exact",
            "adoption": adoption, "domains": ["test"], "capabilities": list(caps),
            "conflict_group": group, "trust": trust, "risk": "low", "invocation": "explicit",
            "runtime": {"requires": list(requires or []), "network": False,
                         "credentials": list(credentials or [])},
            "deploy": {"deployable": deployable, "skill_name": ident, "path": "skill"},
            "notes": "", "origin": "test"}

    def write(self, policy=None, providers=None):
        entries = list(self.catalog.values())
        self._write(self.root / "registry/catalog.json", {"schema_version": 2, "entries": entries})
        self._write(self.root / "registry/conflict-groups.json", self.conflicts)
        self.modes["modes"]["smoke"]["providers"] = list(providers or [])
        self._write(self.root / "modes/operational-modes.json", self.modes)
        self._write(self.root / "modes/evaluation-modes.json", {"schema_version": 1, "modes": {}})
        locks = {}
        for ident in self.catalog:
            evidence = self.root / "audit/evidence" / (ident + ".json")
            commit = "a" * 40
            entry = self.catalog[ident]
            source = ab.payload_inventory({"SKILL.md": ("---\nname: %s\ndescription: fixture\n---\n" % ident).encode()})
            candidate = {"binding_version": 1, "source_id": ident,
                         "catalog_sha256": ab.catalog_digest(entry),
                         "origin": ab.canonical_origin(entry["source_url"]), "commit": commit,
                         "source_tree_oid": commit, "deploy_path": "skill",
                         "source_tree_sha256": ab.digest("accp-source-tree-v1", source),
                         "artifact_tree_sha256": "0" * 64, "invocation": entry.get("invocation") if entry.get("invocation") in ("explicit", "implicit") else "explicit",
                         "projection": ab.PROJECTION}
            artifact = ab.projected_inventory(source, candidate["invocation"])
            candidate["artifact_tree_sha256"] = ab.digest("accp-artifact-tree-v1", artifact)
            ev = {"schema_version": 2, "candidate": candidate,
                  "candidate_sha256": ab.digest("accp-candidate-v1", candidate),
                  "source_inventory": source, "artifact_inventory": artifact,
                  "status": "approved", "reviewer": "fixture", "reviewed_at": "2026-09-16T00:00:00Z",
                  "notes": "", "executable_surface": []}
            evidence.write_bytes(ab.canonical_json(ev) + b"\n")
            locks[ident] = {"repo": entry["source_url"], "commit": commit, "deploy_path": "skill",
                            "evidence": "audit/evidence/" + ident + ".json",
                            "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                            "binding": {"schema_version": 1, "candidate_sha256": ev["candidate_sha256"]},
                            "approval": {"partial_or_conditional": False, "high_risk": False}}
        self._write(self.root / "lock/sources.lock.json", {"schema_version": 2, "sources": locks})
        if policy is not None:
            self._write(self.project / ".codex-skillset.json", policy)

    @staticmethod
    def _write(path, obj):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")

    def policy(self, require=(), prefer=(), forbid=(), include=(), exclude=(), allowed=None):
        p = {"schema_version": 1, "include": list(include), "exclude": list(exclude),
             "capabilities": {"require": list(require), "prefer": list(prefer), "forbid": list(forbid)}}
        if allowed is not None:
            p["allowed_operational_modes"] = list(allowed)
        return p

    def resolve(self, policy=None, providers=None, **kw):
        self.write(policy if policy is not None else self.policy(), providers)
        return accp.resolve_plan("smoke", self.project, **kw)

    def test_required_unique_provider_and_recomputed_coverage(self):
        self.add("one", ["a", "b"])
        out = self.resolve(self.policy(require=["a", "b"]))
        self.assertEqual(out["providers"], ["one"])
        self.assertEqual(out["capabilities_covered"], ["a", "b"])

    def test_exclude_and_forbid_win_on_seed_and_preference(self):
        self.add("seed", ["a"]); self.add("opt", ["b"])
        with self.assertRaises(RuntimeError):
            self.resolve(self.policy(require=["a"], forbid=["a"]), ["seed"])
        with self.assertRaises(RuntimeError):
            self.resolve(self.policy(require=["a"], exclude=["seed"]), ["seed"])

    def test_multi_capability_forbidden_candidate_is_filtered_for_required_and_prefer(self):
        self.add("safe", ["need"]); self.add("blocked", ["need", "blocked"])
        out = self.resolve(self.policy(require=["need"], forbid=["blocked"]))
        self.assertEqual(out["providers"], ["safe"])
        self.catalog.clear(); self.add("base", ["base"]); self.add("blocked", ["want", "blocked"])
        out = self.resolve(self.policy(require=["base"], prefer=["want"], forbid=["blocked"]))
        self.assertEqual(out["providers"], ["base"])

    def test_seed_include_nondeployable_unlocked_and_approval_denied_fail(self):
        self.add("seed", ["a"], deployable=False)
        with self.assertRaises(RuntimeError): self.resolve(self.policy(), ["seed"])
        self.catalog["seed"]["deploy"]["deployable"] = True
        self.write(self.policy(), ["seed"])
        lock = json.loads((self.root / "lock/sources.lock.json").read_text())
        del lock["sources"]["seed"]
        self._write(self.root / "lock/sources.lock.json", lock)
        with self.assertRaises(RuntimeError): accp.resolve_plan("smoke", self.project)
        self.catalog["seed"]["trust"] = "unreviewed"
        with self.assertRaises(RuntimeError): self.resolve(self.policy(include=["seed"]))

    def test_missing_required_fails_and_ambiguous_preference_is_skipped(self):
        self.add("base", ["base"]); self.add("p1", ["want"]); self.add("p2", ["want"])
        with self.assertRaises(RuntimeError): self.resolve(self.policy(require=["missing"]))
        out = self.resolve(self.policy(require=["base"], prefer=["want"]))
        self.assertEqual(out["providers"], ["base"])

    def test_supported_dependency_is_case_normalized(self):
        self.add("dep", ["x"], requires=["FFMPEG"])
        with mock.patch.object(accp.shutil, "which", return_value="ffmpeg") as which:
            out = self.resolve(self.policy(require=["x"]))
        self.assertEqual(out["providers"], ["dep"])
        which.assert_called_with("ffmpeg")

    def test_excluded_required_provider_has_safe_alternative_only(self):
        self.add("bad", ["x"]); self.add("good", ["x"])
        out = self.resolve(self.policy(require=["x"], exclude=["bad"]))
        self.assertEqual(out["providers"], ["good"])
        self.assertEqual(self.resolve(self.policy(require=["x"], prefer=["x"], exclude=["bad"]))["providers"], ["good"])

    def test_duplicate_references_are_deduplicated_but_duplicate_catalog_ids_fail(self):
        self.add("one", ["a"])
        out = self.resolve(self.policy(require=["a", "a"], include=["one", "one"]), ["one", "one"])
        self.assertEqual(out["providers"], ["one"])
        self.write(self.policy(require=["a"]));
        (self.root / "registry/catalog.json").write_text(
            '{"schema_version":2,"entries":[{"id":"one"},{"id":"one"}]}', encoding="utf-8")
        with self.assertRaises(Exception): accp.resolve_plan("smoke", self.project)

    def test_permuted_inputs_have_canonical_result(self):
        self.add("a", ["a"]); self.add("b", ["b"])
        p1 = self.policy(require=["b", "a"], include=["b", "a"])
        p2 = self.policy(require=["a", "b"], include=["a", "b"])
        self.assertEqual(self.resolve(p1, ["b", "a"])["providers"],
                         self.resolve(p2, ["a", "b"])["providers"])

    def test_ambiguous_required_and_optional_conflict_are_fail_closed(self):
        self.add("a", ["x"]); self.add("b", ["x"])
        with self.assertRaises(RuntimeError): self.resolve(self.policy(require=["x"]))
        self.add("req", ["r"], group="g"); self.add("pref", ["p"], group="g")
        self.conflicts["groups"]["g"] = {"max_active": 1, "members": ["req", "pref"]}
        out = self.resolve(self.policy(require=["r"], prefer=["p"]))
        self.assertEqual(out["providers"], ["req"])

    def test_gate_rejects_nondeployable_and_unsupported_dependency(self):
        self.add("bad", ["x"], deployable=False)
        with self.assertRaises(RuntimeError): self.resolve(self.policy(require=["x"]))
        self.catalog.clear(); self.add("baddep", ["x"], requires=["plotting-stack"])
        with self.assertRaises(RuntimeError): self.resolve(self.policy(require=["x"]))

    def test_missing_supported_dependency_rejects_required_and_skips_prefer(self):
        self.add("dep", ["x"], requires=["ffmpeg"])
        with mock.patch.object(accp.shutil, "which", return_value=None):
            with self.assertRaises(RuntimeError): self.resolve(self.policy(require=["x"]))
        self.catalog.clear(); self.add("base", ["base"]); self.add("dep", ["x"], requires=["ffmpeg"])
        with mock.patch.object(accp.shutil, "which", return_value=None):
            out = self.resolve(self.policy(require=["base"], prefer=["x"]))
        self.assertEqual(out["providers"], ["base"])

    def test_capacity_zero_and_optional_conflict_never_evict_required(self):
        self.add("a", ["a"], group="g"); self.add("b", ["b"], group="g")
        self.conflicts["groups"]["g"] = {"max_active": 0, "members": ["a", "b"]}
        with self.assertRaises(RuntimeError): self.resolve(self.policy(require=["a"]))
        self.conflicts["groups"]["g"] = {"max_active": 1, "members": ["a", "b"]}
        out = self.resolve(self.policy(require=["a"], prefer=["b"]))
        self.assertEqual(out["providers"], ["a"])

    def test_credentials_are_warning_only_and_two_key_approval_is_preserved(self):
        self.add("cred", ["x"], credentials=["TOKEN"])
        out = self.resolve(self.policy(require=["x"]))
        self.assertTrue(any("TOKEN" in w for w in out["warnings"]))
        self.catalog["cred"]["adoption"] = "conditional"
        with self.assertRaises(RuntimeError): self.resolve(self.policy(require=["x"]))
        self.write(self.policy(require=["x"]))
        lock = json.loads((self.root / "lock/sources.lock.json").read_text())
        lock["sources"]["cred"]["approval"]["partial_or_conditional"] = True
        self._write(self.root / "lock/sources.lock.json", lock)
        out = accp.resolve_plan("smoke", self.project, allow_partial=True)
        self.assertEqual(out["providers"], ["cred"])

    def test_empty_allowed_list_denies_mode_and_missing_is_unrestricted(self):
        self.add("ok", ["x"])
        with self.assertRaises(RuntimeError): self.resolve(self.policy(require=["x"], allowed=[]))
        self.assertEqual(self.resolve(self.policy(require=["x"]))["providers"], ["ok"])

    def test_unreadable_policy_metadata_cannot_drop_hard_constraints(self):
        self.add('one',['blocked']); self.write(self.policy(forbid=['blocked']),['one'])
        policy=self.project/'.codex-skillset.json'; original=accp.os.lstat; original_stat=accp.os.stat
        for failure in (PermissionError('policy access denied'), OSError('policy I/O error')):
            def denied(path,*args,**kwargs):
                if pathlib.Path(path)==policy: raise failure
                return original(path,*args,**kwargs)
            def denied_stat(path,*args,**kwargs):
                if pathlib.Path(path)==policy: raise failure
                return original_stat(path,*args,**kwargs)
            # pathlib.lstat uses os.stat(follow_symlinks=False) on Python 3.11;
            # inject both spellings so the regression also fails the old lexists gate.
            with self.subTest(failure=type(failure).__name__), mock.patch.object(accp.os,'lstat',side_effect=denied), mock.patch.object(accp.os,'stat',side_effect=denied_stat):
                with self.assertRaisesRegex(OSError,'policy'):
                    accp.resolve_plan('smoke',self.project)
                args=accp.argparse.Namespace(mode='smoke',project=self.project,allow_partial=False,scope='project',dry_run=False)
                with mock.patch.object(accp,'runtime_owner') as runtime, mock.patch.object(accp,'activate_plan') as activate:
                    with self.assertRaisesRegex(OSError,'policy'): accp.cmd_activate(args)
                    runtime.assert_not_called(); activate.assert_not_called()
                self.assertFalse((self.project/'.agents').exists())

    def test_policy_disappearing_after_presence_check_is_not_absence(self):
        self.add('one',['blocked']); self.write(self.policy(forbid=['blocked']),['one'])
        policy=self.project/'.codex-skillset.json'; original=accp.readj
        def disappeared(path,**kwargs):
            if pathlib.Path(path)==policy: raise FileNotFoundError('policy vanished after preflight')
            return original(path,**kwargs)
        with mock.patch.object(accp,'readj',side_effect=disappeared):
            with self.assertRaisesRegex(FileNotFoundError,'policy vanished'):
                accp.resolve_plan('smoke',self.project)

    def test_genuinely_missing_project_policy_is_allowed(self):
        self.add('one',['a']); self.write(providers=['one'])
        self.assertFalse((self.project/'.codex-skillset.json').exists())
        self.assertEqual(['one'],accp.resolve_plan('smoke',self.project)['providers'])

    def test_normalization_rejects_legacy_fallback_and_contradictory_policy(self):
        self.add("ok", ["x"])
        for key in ("allowed_modes", "default_mode", "fallback"):
            p = self.policy(require=["x"]); p[key] = "smoke"
            with self.subTest(key=key), self.assertRaises(RuntimeError): self.resolve(p)
        with self.assertRaises(RuntimeError): self.resolve(self.policy(require=["x"], forbid=["x"]))

    def test_strict_duplicate_keys_and_nonfinite_json_fail(self):
        self.add("ok", ["x"]); self.write(self.policy(require=["x"]))
        p = self.project / ".codex-skillset.json"
        p.write_text('{"schema_version":1,"include":[],"include":[]}', encoding="utf-8")
        with self.assertRaises(Exception): accp.resolve_plan("smoke", self.project)
        p.write_text('{"schema_version":1,"capabilities":{"require":[NaN]}}', encoding="utf-8")
        with self.assertRaises(Exception): accp.resolve_plan("smoke", self.project)

    def test_duplicate_keys_at_each_authoritative_level_fail_closed(self):
        self.add("ok", ["x"])
        paths = {
            "catalog": self.root / "registry/catalog.json",
            "lock": self.root / "lock/sources.lock.json",
            "ops": self.root / "modes/operational-modes.json",
            "conflicts": self.root / "registry/conflict-groups.json",
            "evidence": self.root / "audit/evidence/ok.json",
            "policy": self.project / ".codex-skillset.json",
        }
        raws = {
            "catalog": '{"schema_version":2,"entries":[],"entries":[]}',
            "lock": '{"schema_version":2,"sources":{},"sources":{}}',
            "ops": '{"schema_version":1,"modes":{"smoke":{"providers":[]}},"modes":{}}',
            "conflicts": '{"schema_version":2,"groups":{},"groups":{}}',
            "evidence": '{"schema_version":1,"source_id":"ok","repo":"x","commit":"' + "a" * 40 + '","status":"approved","status":"approved"}',
            "policy": '{"schema_version":1,"include":[],"include":[]}',
        }
        for name, path in paths.items():
            self.write(self.policy(require=["x"]))
            path.write_text(raws[name], encoding="utf-8")
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'duplicate JSON key'):
                accp.resolve_plan("smoke", self.project)

    def test_malformed_policy_and_catalog_shapes_are_not_coerced(self):
        self.add("ok", ["x"])
        policies = [None, {"schema_version": 2}, {"schema_version": 1, "include": None},
                    {"schema_version": 1, "capabilities": {"require": [True]}},
                    {"schema_version": 1, "capabilities": {"require": None}},
                    {"schema_version": 1, "capabilities": {"require": [], "forbid": "x"}}]
        for policy in policies:
            self.write(self.policy(require=["x"]))
            p = self.project / ".codex-skillset.json"
            p.write_text("null" if policy is None else json.dumps(policy), encoding="utf-8")
            with self.subTest(policy=policy), self.assertRaises(Exception): accp.resolve_plan("smoke", self.project)
        for mutate in ({"capabilities": None}, {"runtime": None}, {"deploy": {"deployable": 1}},
                       {"conflict_group": 1}, {"runtime": {"requires": [], "credentials": None}}):
            self.add("ok", ["x"]); self.catalog["ok"].update(mutate); self.write(self.policy(require=["x"]))
            with self.subTest(mutate=mutate), self.assertRaises(Exception): accp.resolve_plan("smoke", self.project)

    def test_final_gate_rechecks_bypassed_exclusion_forbid_duplicates_and_coverage(self):
        self.add("one", ["a", "b"]); self.write(self.policy(require=["a"], forbid=["b"]))
        context = accp.normalize_resolver_inputs("smoke", self.project)
        with mock.patch.object(accp, "provider_eligibility", return_value=None):
            with self.assertRaises(RuntimeError): accp.validate_resolved_plan(["one"], context)
        self.write(self.policy(require=["a"]))
        context = accp.normalize_resolver_inputs("smoke", self.project)
        with mock.patch.object(accp, "provider_eligibility", return_value=None):
            with self.assertRaises(Exception): accp.validate_resolved_plan(["one", "one"], context)
            covered, warnings = accp.validate_resolved_plan(["one"], context)
        self.assertEqual(covered, {"a", "b"}); self.assertEqual(warnings, [])

    def test_final_gate_rejects_unknown_missing_coverage_and_conflict(self):
        self.add("one", ["a"], group="g"); self.add("two", ["b"], group="g")
        self.conflicts["groups"]["g"] = {"max_active": 1, "members": ["one", "two"]}
        self.write(self.policy(require=["a", "b"]))
        context = accp.normalize_resolver_inputs("smoke", self.project)
        with mock.patch.object(accp, "provider_eligibility", return_value=None):
            for selected in (["unknown"], ["one"], ["one", "two"]):
                with self.subTest(selected=selected), self.assertRaises(Exception):
                    accp.validate_resolved_plan(selected, context)

    def test_final_gate_rejects_omitted_explicit_seed(self):
        self.add("seed", ["a"]); self.write(self.policy(), ["seed"])
        context = accp.normalize_resolver_inputs("smoke", self.project)
        with mock.patch.object(accp, "provider_eligibility", return_value=None):
            with self.assertRaises(Exception): accp.validate_resolved_plan([], context)

    def test_final_gate_checks_exclusion_independently_of_candidate_predicate(self):
        self.add('one', ['a']); self.write(self.policy(exclude=['one']))
        context=accp.normalize_resolver_inputs('smoke',self.project)
        with mock.patch.object(accp,'provider_eligibility',return_value=None):
            with self.assertRaisesRegex(RuntimeError,'excluded IDs'):
                accp.validate_resolved_plan(['one'],context)

    def test_resolve_revalidates_evidence_at_final_gate(self):
        self.add('one',['a']); self.write(self.policy(require=['a']))
        evidence=accp.evidence_ok; calls=[]
        def changed(*args,**kwargs):
            calls.append(args[0])
            if len(calls)==2: raise RuntimeError('evidence changed before final gate')
            return evidence(*args,**kwargs)
        with mock.patch.object(accp,'evidence_ok',side_effect=changed):
            with self.assertRaisesRegex(RuntimeError,'evidence changed before final gate'):
                accp.resolve_plan('smoke',self.project)
        self.assertEqual(['one','one'],calls)

    def test_overflow_nonfinite_and_boolean_version_refuse(self):
        self.add('one',['a'])
        for raw in ('{"schema_version":true}', '{"schema_version":1,"project_type":[1e9999]}'):
            self.write(self.policy())
            (self.project/'.codex-skillset.json').write_text(raw,encoding='utf-8')
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                accp.resolve_plan('smoke',self.project)

    def test_selection_conflicts_uses_catalog_groups_and_conservative_default(self):
        self.add("a", ["a"], group="g"); self.add("b", ["b"], group="g")
        self.write(self.policy())
        context = accp.normalize_resolver_inputs("smoke", self.project)
        self.assertIsNotNone(accp.selection_conflicts(["a", "b"], context))

    def test_excluded_preference_include_and_forbidden_seed_never_override_policy(self):
        self.add('one',['want','blocked'])
        out=self.resolve(self.policy(include=['one'],exclude=['one'],prefer=['want']),['one'])
        self.assertEqual([],out['providers'])
        with self.assertRaisesRegex(RuntimeError,'violates capabilities.forbid'):
            self.resolve(self.policy(forbid=['blocked']),['one'])
        out=self.resolve(self.policy(prefer=['want'],forbid=['want']))
        self.assertEqual([],out['providers'])
        self.assertTrue(any('skipped: forbidden' in w for w in out['warnings']))

    def test_capacities_reject_wrong_types_and_count_unique_members(self):
        self.add('one',['a'],group='g'); self.add('two',['b'],group='g')
        for capacity in (True,'1',-1,None,1.5):
            self.conflicts['groups']['g']={'max_active':capacity}
            with self.subTest(capacity=capacity), self.assertRaisesRegex(RuntimeError,'invalid max_active'):
                self.resolve(self.policy(),['one'])
        self.conflicts['groups']['g']={'max_active':2,'members':[]}
        out=self.resolve(self.policy(require=['a','b']),['one','one','two'])
        self.assertEqual(['one','two'],out['providers'])

    def test_provider_ids_and_unknown_references_fail_closed(self):
        self.add('one',['a'])
        for ident in ('../one','C:\\one','\\\\server\\share','One','con','one.','a/b',True):
            with self.subTest(ident=ident), self.assertRaises(RuntimeError):
                self.resolve(self.policy(include=[ident]))
        for providers,include in ((['unknown'],[]),([],['unknown'])):
            with self.subTest(providers=providers,include=include), self.assertRaisesRegex(RuntimeError,'unknown provider IDs'):
                self.resolve(self.policy(include=include),providers)
        self.assertEqual([],self.resolve(self.policy(exclude=['unknown']))['providers'])

    def test_evidence_denial_is_identical_for_seeds_required_and_preferred(self):
        self.add('one',['a'])
        for field,value in (('source_id','foreign'),('commit','b'*40),('status','unreviewed')):
            for kind in ('seed','require','prefer'):
                self.write(self.policy(**({kind:['a']} if kind!='seed' else {})),['one'] if kind=='seed' else [])
                path=self.root/'audit/evidence/one.json'
                evidence=json.loads(path.read_text())
                if field=='status': evidence[field]=value
                else: evidence['candidate'][field]=value
                evidence['candidate_sha256']=ab.digest('accp-candidate-v1',evidence['candidate'])
                path.write_bytes(ab.canonical_json(evidence)+b'\n')
                # Rebind the digest so identity/status checks, not just hashing, are exercised.
                locks=json.loads((self.root/'lock/sources.lock.json').read_text())
                locks['sources']['one']['evidence_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
                locks['sources']['one']['binding']['candidate_sha256']=evidence['candidate_sha256']
                self._write(self.root/'lock/sources.lock.json',locks)
                with self.subTest(field=field,kind=kind):
                    if kind=='prefer': self.assertEqual([],accp.resolve_plan('smoke',self.project)['providers'])
                    else:
                        with self.assertRaisesRegex(RuntimeError,'catalog identity mismatch|lock/candidate mismatch|evidence status'):
                            accp.resolve_plan('smoke',self.project)

    def test_missing_dependency_candidate_cannot_displace_safe_alternative(self):
        self.add('bad',['a'],requires=['bash/WSL']); self.add('good',['a'])
        with mock.patch.object(accp.shutil,'which') as which:
            self.assertEqual(['good'],self.resolve(self.policy(require=['a']))['providers'])
        which.assert_not_called()

    def test_catalog_order_and_required_ambiguity_are_deterministic(self):
        self.add('a',['x']); self.add('b',['x'])
        errors=[]
        for _ in range(2):
            with self.assertRaises(RuntimeError) as caught:
                self.resolve(self.policy(require=['x']))
            errors.append(str(caught.exception))
            self.catalog=dict(reversed(list(self.catalog.items())))
        self.assertEqual(errors[0],errors[1])
        self.catalog['b']['capabilities']=['y']
        first=self.resolve(self.policy(require=['y','x']))
        self.catalog=dict(reversed(list(self.catalog.items())))
        second=self.resolve(self.policy(require=['x','y']))
        for output in (first,second): output.pop('generated_at')
        self.assertEqual(first,second)

    def test_partial_approval_still_requires_both_keys(self):
        self.add('one',['a'],trust='partial')
        for lock_key,call_key in ((False,False),(False,True),(True,False),(True,True)):
            self.write(self.policy(require=['a']))
            path=self.root/'lock/sources.lock.json'; locks=json.loads(path.read_text())
            locks['sources']['one']['approval']['partial_or_conditional']=lock_key
            self._write(path,locks)
            with self.subTest(lock_key=lock_key,call_key=call_key):
                if lock_key and call_key:
                    self.assertEqual(['one'],accp.resolve_plan('smoke',self.project,allow_partial=call_key)['providers'])
                else:
                    with self.assertRaises(RuntimeError): accp.resolve_plan('smoke',self.project,allow_partial=call_key)


if __name__ == "__main__":
    unittest.main()
