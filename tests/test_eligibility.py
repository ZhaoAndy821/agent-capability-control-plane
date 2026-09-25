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


class EligibilityFixture(unittest.TestCase):
    """Model-free M1 fixtures: every source is a local, real JSON record."""

    def setUp(self):
        local = pathlib.Path(__file__).resolve().parents[1] / ".local" / "audit-temp"
        local.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="accp-f05-", dir=str(local))
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.evidence_dir = self.root / "audit" / "evidence"
        self.evidence_dir.mkdir(parents=True)
        self.project = self.root / "project"
        self.project.mkdir()
        self.patch = mock.patch.multiple(
            accp, ROOT=self.root, EVIDENCE=self.evidence_dir,
            CATALOG=self.root / "registry/catalog.json",
            CONFLICTS=self.root / "registry/conflict-groups.json",
            OP_MODES=self.root / "modes/operational-modes.json",
            EVAL_MODES=self.root / "modes/evaluation-modes.json",
            LOCK=self.root / "lock/sources.lock.json")
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self._write(self.root / "registry/catalog.json", {"schema_version": 2, "entries": []})
        self._write(self.root / "registry/conflict-groups.json", {
            "schema_version": 2, "source_of_truth": "registry/catalog.json::entries[].conflict_group", "groups": {}})
        self._write(self.root / "modes/operational-modes.json", {
            "schema_version": 1, "modes": {"smoke": {"providers": []}}})
        self._write(self.root / "modes/evaluation-modes.json", {"schema_version": 1, "modes": {}})
        self.catalog = {}

    @staticmethod
    def _write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def entry(self, ident="fixture", **changes):
        e = {"id": ident, "name": ident, "kind": "skill",
             "source_url": "https://example.invalid/" + ident, "source_resolution": "exact",
             "adoption": "adopted", "trust": "reviewed", "risk": "low",
             "invocation": "explicit", "domains": ["test"], "capabilities": ["cap"],
             "conflict_group": None, "runtime": {"requires": [], "credentials": [], "network": False},
             "deploy": {"deployable": True, "skill_name": ident, "path": "skill"},
             "notes": "", "origin": "test"}
        for key, value in changes.items():
            if isinstance(value, dict) and isinstance(e.get(key), dict): e[key].update(value)
            else: e[key] = value
        return e

    def lock(self, e, *, approval=None, commit=None):
        ident = e["id"]
        commit = commit or "a" * 40
        ev_path = self.evidence_dir / (ident + ".json")
        source = ab.payload_inventory({"SKILL.md": ("---\nname: %s\ndescription: fixture\n---\n" % ident).encode()})
        candidate = {"binding_version": 1, "source_id": ident,
                     "catalog_sha256": ab.catalog_digest(e), "origin": ab.canonical_origin(e["source_url"]),
                     "commit": commit, "source_tree_oid": commit, "deploy_path": "skill",
                     "source_tree_sha256": ab.digest("accp-source-tree-v1", source),
                     "artifact_tree_sha256": "0" * 64, "invocation": e.get("invocation") if e.get("invocation") in ("explicit", "implicit") else "explicit",
                     "projection": ab.PROJECTION}
        artifact = ab.projected_inventory(source, candidate["invocation"])
        candidate["artifact_tree_sha256"] = ab.digest("accp-artifact-tree-v1", artifact)
        ev = {"schema_version": 2, "candidate": candidate,
              "candidate_sha256": ab.digest("accp-candidate-v1", candidate),
              "source_inventory": source, "artifact_inventory": artifact,
              "status": "approved", "reviewer": "fixture", "reviewed_at": "2026-09-16T00:00:00Z",
              "notes": "", "executable_surface": []}
        ev_path.parent.mkdir(parents=True, exist_ok=True)
        ev_path.write_bytes(ab.canonical_json(ev) + b"\n")
        return {"repo": e["source_url"], "commit": commit, "deploy_path": "skill",
                "evidence": "audit/evidence/" + ev_path.name,
                "evidence_sha256": hashlib.sha256(ev_path.read_bytes()).hexdigest(),
                "binding": {"schema_version": 1, "candidate_sha256": ev["candidate_sha256"]},
                "approval": {"partial_or_conditional": False, "high_risk": False,
                             **(approval or {})}}

    def write_resolver_fixture(self, entries, policy=None, seed=None):
        self._write(self.root / "registry/catalog.json", {"schema_version": 2, "entries": entries})
        locks = {e["id"]: self.lock(e) for e in entries}
        self._write(self.root / "lock/sources.lock.json", {"schema_version": 2, "sources": locks})
        self._write(self.root / "modes/operational-modes.json", {
            "schema_version": 1, "modes": {"smoke": {"providers": list(seed or [])}}})
        if policy is not None: self._write(self.project / ".codex-skillset.json", policy)

    def test_catalog_validator_accepts_complete_entry_and_all_inactive_domains_are_shape_valid(self):
        for adoption in ("adopted", "alternate", "candidate", "conditional", "deferred",
                         "experimental", "optional", "quarantine", "reference", "rejected"):
            for trust in ("reviewed", "partial", "unreviewed", "quarantine"):
                for invocation in ("explicit", "implicit", "dormant"):
                    e = self.entry(adoption=adoption, trust=trust, risk="medium", invocation=invocation)
                    self.assertIsNone(accp.validate_catalog_eligibility(e))

    def test_catalog_validator_rejects_missing_null_wrong_type_and_unknown_fields(self):
        base = self.entry()
        for key in ("id", "adoption", "trust", "risk", "invocation", "capabilities", "conflict_group", "deploy", "runtime"):
            with self.subTest(key=key):
                bad = dict(base); bad.pop(key)
                with self.assertRaises((RuntimeError, ValueError, TypeError, KeyError)): accp.validate_catalog_eligibility(bad)
        for key in ("adoption", "trust", "risk", "invocation"):
            for value in (None, 1, [], {}, " ", "UNKNOWN", base[key].upper(), ' '+base[key]):
                bad = dict(base); bad[key] = value
                with self.subTest(key=key, value=repr(value)):
                    with self.assertRaises((RuntimeError, ValueError, TypeError, KeyError)): accp.validate_catalog_eligibility(bad)
        bad = dict(base); bad["unexpected"] = 1
        self.assertIsNone(accp.validate_catalog_eligibility(bad))  # descriptive extensions remain allowed

    def test_approval_validator_requires_object_and_strict_optional_fields(self):
        for value in (None, 1, [], "x"):
            with self.assertRaises((RuntimeError, ValueError, TypeError)): accp.validate_approval_fields(value)
        for key in ("partial_or_conditional", "high_risk"):
            for value in (None, 0, 1, "true", "false", [], {}):
                with self.subTest(key=key, value=repr(value)):
                    with self.assertRaises((RuntimeError, ValueError, TypeError)): accp.validate_approval_fields({key: value})
        for value in (None, "", " ", 1, True):
            with self.assertRaises((RuntimeError, ValueError, TypeError)):
                accp.validate_approval_fields({"approved_at": value})
        with self.assertRaises((RuntimeError, ValueError, TypeError)): accp.validate_approval_fields({"extra": 1})
        self.assertEqual({},accp.validate_approval_fields({}))
        accepted={"partial_or_conditional": True, "high_risk": False, "approved_at": "2026-09-14T00:00:00Z"}
        self.assertEqual(accepted,accp.validate_approval_fields(accepted))

    def test_approval_matrix_requires_domains_deployability_invocation_and_authorization(self):
        e = self.entry(); l = self.lock(e)
        self.assertIsNone(accp.approval_ok(e, l))
        for field, values in (("adoption", ("conditional", "experimental", "deprecated", "blocked")),
                              ("trust", ("partial", "quarantine", "unknown", "unreviewed")),
                              ("invocation", ("dormant", "unknown"))):
            for value in values:
                with self.subTest(field=field, value=value):
                    bad = dict(e); bad[field] = value
                    with self.assertRaises(RuntimeError): accp.approval_ok(bad, l, allow_partial=True)
        for value in (False, None, 0, 1, "true", [], {}):
            bad = dict(e); bad["deploy"] = {"deployable": value}
            with self.assertRaises((RuntimeError, ValueError, TypeError, KeyError)): accp.approval_ok(bad, l)
        for adoption, trust in (("adopted", "partial"), ("conditional", "reviewed"), ("conditional", "partial")):
            candidate = self.entry(adoption=adoption, trust=trust)
            for approved in (False, True):
                ll = self.lock(candidate, approval={"partial_or_conditional": approved})
                for call_flag in (False,True):
                    with self.subTest(adoption=adoption, trust=trust, approved=approved,call_flag=call_flag):
                        if approved and call_flag: self.assertIsNone(accp.approval_ok(candidate, ll, allow_partial=call_flag))
                        else:
                            with self.assertRaises(RuntimeError): accp.approval_ok(candidate, ll, allow_partial=call_flag)
        for call_flag in (None,0,1,'false','true',[],{}):
            with self.subTest(call_flag=repr(call_flag)), self.assertRaisesRegex(RuntimeError,'allow_partial must be boolean'):
                accp.approval_ok(self.entry(),l,allow_partial=call_flag)

    def test_high_risk_requires_literal_true_and_implicit_is_low_risk_only(self):
        e = self.entry(risk="high"); l = self.lock(e, approval={"high_risk": True})
        self.assertIsNone(accp.approval_ok(e, l))
        missing=dict(l,approval={})
        with self.assertRaisesRegex(RuntimeError,'high-risk'): accp.approval_ok(e,missing)
        implicit=self.entry(invocation='implicit')
        self.assertIsNone(accp.approval_ok(implicit,self.lock(implicit)))
        for value in (False, None, 0, 1, "true", "false", [], {}):
            with self.subTest(value=repr(value)):
                with self.assertRaises((RuntimeError, ValueError, TypeError)): accp.approval_ok(e, self.lock(e, approval={"high_risk": value}))
        for risk in ("medium", "high", "unknown"):
            implicit = self.entry(risk=risk, invocation="implicit")
            with self.assertRaises(RuntimeError): accp.approval_ok(implicit, self.lock(implicit, approval={"high_risk": True}))

    def test_dependencies_validate_supported_case_missing_credentials_and_unknown(self):
        e = self.entry(); e["runtime"]["requires"] = ["PYTHON", "Git"]
        with mock.patch.object(accp.shutil, "which", side_effect=lambda n: n):
            self.assertEqual(accp.check_dependencies(e), ([], []))
        e["runtime"]["credentials"] = ["TOKEN"]
        with mock.patch.object(accp.shutil, "which", return_value=None):
            missing, creds = accp.check_dependencies(e)
        self.assertEqual(set(missing), {"python", "git"}); self.assertEqual(creds, ["TOKEN"])
        e["runtime"]["requires"] = ["ffmpeg", "made-up-runtime"]
        with self.assertRaisesRegex(RuntimeError, "unsupported dependency requirement"):
            accp.check_dependencies(e)

    def test_operational_core_checks_binding_strictly_and_returns_evidence(self):
        e = self.entry(); l = self.lock(e)
        ev = accp.require_operational_eligibility(e["id"], e, l)
        self.assertEqual(ev["candidate"]["source_id"], e["id"])
        foreign = dict(l, repo="https://foreign.invalid/repo")
        with self.assertRaises(RuntimeError): accp.require_operational_eligibility(e["id"], e, foreign)
        with self.assertRaises(RuntimeError): accp.require_operational_eligibility("other", e, l)

    def test_materialize_existing_per_id_gate_denies_before_source_work(self):
        e = self.entry(); l = self.lock(e)
        touched = []
        args = type("Args", (), {"id": [e["id"]], "allow_partial": False})()
        with mock.patch.object(accp, "catalog_index", return_value={e["id"]: e}), \
             mock.patch.object(accp, "lock_index", return_value={e["id"]: l}), \
             mock.patch.object(accp, "ensure_source_at_lock", side_effect=lambda *a: touched.append(a)), \
             mock.patch.object(accp, "runtime_owner") as owner:
            denied = dict(e, trust="unreviewed")
            with mock.patch.object(accp, "catalog_index", return_value={e["id"]: denied}):
                with self.assertRaises(RuntimeError): accp.cmd_materialize(args)
            owner.assert_not_called()
        self.assertEqual(touched, [], "approval denial must precede runtime/source/cache work")

    def test_resolver_seed_include_require_prefer_share_operational_gate(self):
        base = self.entry("base", capabilities=["base"])
        optional = self.entry("optional", capabilities=["want"])
        policy = {"schema_version": 1, "include": ["optional"], "exclude": [],
                  "capabilities": {"require": ["base"], "prefer": ["want"], "forbid": []}}
        self.write_resolver_fixture([base, optional], policy, seed=["base"])
        out = accp.resolve_plan("smoke", self.project)
        self.assertEqual(out["providers"], ["base", "optional"])
        for changes in ({'trust':'quarantine'},{'adoption':'candidate'},{'invocation':'dormant'},
                        {'risk':'high'},{'deploy':{'deployable':False}},
                        {'runtime':{'requires':['unknown-stack']}}):
            denied=self.entry('denied',capabilities=['want'],**changes)
            for path in ('seed','include','require','prefer'):
                policy={'schema_version':1,'include':['denied'] if path=='include' else [],
                        'capabilities':{'require':['want'] if path=='require' else ['base'],
                                        'prefer':['want'] if path=='prefer' else []}}
                self.write_resolver_fixture([base,denied],policy,seed=['base','denied'] if path=='seed' else ['base'])
                with self.subTest(changes=changes,path=path):
                    if path=='prefer': self.assertEqual(['base'],accp.resolve_plan('smoke',self.project)['providers'])
                    else:
                        with self.assertRaisesRegex(RuntimeError,'operational eligibility denied'):
                            accp.resolve_plan('smoke',self.project)

    def test_schema_literals_and_required_runtime_approval_shapes_align(self):
        catalog = json.loads((pathlib.Path(__file__).resolve().parents[1] / "schemas/catalog.schema.json").read_text())
        lock = json.loads((pathlib.Path(__file__).resolve().parents[1] / "schemas/lock.schema.json").read_text())
        self.assertEqual(catalog["properties"]["schema_version"]["const"], 2)
        self.assertEqual(lock["properties"]["schema_version"]["const"], 2)
        item=catalog['properties']['entries']['items']
        for field,domain in accp.ELIGIBILITY_DOMAINS.items():
            self.assertIn(field,item['required'])
            self.assertEqual(set(item['properties'][field]['enum']),domain)
        approval=lock['properties']['sources']['additionalProperties']['properties']['approval']
        self.assertIs(approval['additionalProperties'],False)
        self.assertEqual(set(approval['properties']),{'partial_or_conditional','high_risk','approved_at'})
        for field in ('partial_or_conditional','high_risk'):
            self.assertEqual(approval['properties'][field]['type'],'boolean')

    def test_all_recognized_operational_domains_with_both_authorizations(self):
        lock=self.lock(self.entry(),approval={'partial_or_conditional':True,'high_risk':True})
        for adoption in ('adopted','alternate','candidate','conditional','deferred','experimental','optional','quarantine','reference','rejected'):
            for trust in ('reviewed','partial','unreviewed','quarantine'):
                for risk in ('low','medium','high'):
                    for invocation in ('explicit','implicit','dormant'):
                        entry=self.entry(adoption=adoption,trust=trust,risk=risk,invocation=invocation)
                        allowed=adoption in ('adopted','conditional') and trust in ('reviewed','partial') and (invocation=='explicit' or invocation=='implicit' and risk=='low')
                        with self.subTest(adoption=adoption,trust=trust,risk=risk,invocation=invocation):
                            if allowed: self.assertIsNone(accp.approval_ok(entry,lock,True))
                            else:
                                with self.assertRaises(RuntimeError): accp.approval_ok(entry,lock,True)

    def test_runtime_field_errors_refuse_without_probing_executables(self):
        for field in ('requires','credentials'):
            for value in (None,'python',[True],[1],[None],[''],[' '],{}):
                entry=self.entry(runtime={field:value})
                with self.subTest(field=field,value=value), mock.patch.object(accp.shutil,'which') as which:
                    with self.assertRaises(RuntimeError): accp.check_dependencies(entry)
                    which.assert_not_called()
            entry=self.entry(); del entry['runtime'][field]
            with self.assertRaises(RuntimeError): accp.check_dependencies(entry)

    def test_core_denies_duplicate_evidence_and_unresolved_requirements(self):
        entry=self.entry(); lock=self.lock(entry)
        path=self.evidence_dir/'fixture.json'
        path.write_text('{"status":"approved","status":"approved"}',encoding='utf-8')
        lock['evidence_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(RuntimeError,'duplicate JSON key'):
            accp.require_operational_eligibility('fixture',entry,lock)
        entry=self.entry(runtime={'requires':['FFMPEG']}); lock=self.lock(entry)
        with mock.patch.object(accp.shutil,'which',return_value=None):
            with self.assertRaisesRegex(RuntimeError,'missing dependencies'):
                accp.require_operational_eligibility('fixture',entry,lock)
        entry=self.entry(runtime={'requires':['unknown-stack']}); lock=self.lock(entry)
        with self.assertRaisesRegex(RuntimeError,'unsupported dependency'):
            accp.require_operational_eligibility('fixture',entry,lock)


if __name__ == "__main__":
    unittest.main()
