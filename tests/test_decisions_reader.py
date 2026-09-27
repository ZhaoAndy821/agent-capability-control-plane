"""`accp.py decisions`: a read-only aggregate of the decision facts Core recorded.

These tests pin the properties that make the command safe to hand to a read-only
console: a stable schema, no invented rejection, the raw facts kept alongside every
normalised one, an admission verdict taken from the plane's OWN predicate, and not
a byte changed by running it -- on the path that actually reads plane state, not
only on an unenrolled workspace where no reader logic runs.
"""

import hashlib
import io
import json
import pathlib
import re
import shutil
import sys
import tempfile
import unittest
from argparse import Namespace
from contextlib import contextmanager, redirect_stdout
from unittest import mock

sys.dont_write_bytecode = True
SRC = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC / "scripts"))
import accp  # noqa: E402


@contextmanager
def audit_tempdir():
    root = SRC / ".local" / "audit-temp"
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root) as name:
        yield pathlib.Path(name)


def tree_hash(root):
    """Content hash of every file below `root`, independent of timestamps."""
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(root)).encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def all_keys(node, found):
    if isinstance(node, dict):
        found.update(node.keys())
        for value in node.values():
            all_keys(value, found)
    elif isinstance(node, list):
        for value in node:
            all_keys(value, found)
    return found


def walk_pairs(node, path="", found=None):
    """Every (path, key, value) triple in a document, at any depth."""
    if found is None:
        found = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.append((path, key, value))
            walk_pairs(value, path + "." + str(key), found)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            walk_pairs(value, path + "[" + str(index) + "]", found)
    return found


TOP_LEVEL_KEYS = [
    "admission_authority",
    "base",
    "capability_admission_records",
    "coverage",
    "detail",
    "lifecycle_records",
    "observed_at",
    "project",
    "report_kind",
    "reservation",
    "schema_version",
    "scope",
]


class DecisionsReader(unittest.TestCase):
    def setUp(self):
        self.tmp = audit_tempdir()
        self.base = self.tmp.__enter__()
        self.addCleanup(self.tmp.__exit__, None, None, None)
        self.cp = self.base / "control-plane"
        shutil.copytree(SRC / "examples" / "minimal-instance", self.cp)
        for name, path in (
            ("ROOT", self.cp),
            ("LOCK", self.cp / "lock" / "sources.lock.json"),
            ("CATALOG", self.cp / "registry" / "catalog.json"),
        ):
            patcher = mock.patch.object(accp, name, path)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.project = self.base / "project"
        self.project.mkdir()

    def lock_path(self):
        return self.cp / "lock" / "sources.lock.json"

    def enroll(self):
        """Enrol the project base so the reader takes the coordinated path.

        Without this the reader reports UNCOORDINATED and never runs
        `reader_snapshot` -- the only status-path code that reads plane state --
        so a read-only test would prove nothing about the code that matters.
        """
        agents = self.project / ".agents"
        agents.mkdir(exist_ok=True)
        (agents / ".accp-lifecycle.lock").write_bytes(b"")

    def run_decisions(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = accp.cmd_decisions(Namespace(project=str(self.project), scope="project"))
        return code, json.loads(buffer.getvalue())

    def test_schema_is_stable(self):
        code, out = self.run_decisions()
        self.assertEqual(out["report_kind"], "decision_observations")
        self.assertEqual(out["schema_version"], 1)
        self.assertEqual(sorted(out), TOP_LEVEL_KEYS)
        # `audit` carries these at the top level so a consumer can gate on them; a
        # report that buries them reads as `undefined` to such a consumer.
        self.assertIs(out["admission_authority"], False)
        self.assertIs(out["reservation"], False)
        # A workspace with no enrolled base is an observation, not a crash: the
        # reader reports UNCOORDINATED and the exit code follows `status`.
        self.assertEqual(code, 2)

    # Every key NAME the report can contain, at any depth, in either variant.
    #
    # What this guard is, stated without overclaiming: it fails if any key NAME
    # outside this set appears anywhere in the document, in either variant, and it
    # pins the coverage values exactly. It does NOT prove that no number can appear
    # -- five successive versions of it were defeated by six independent reviews,
    # by placing a count somewhere the rule did not look, and no rule over names can
    # decide a meaning. What keeps this report honest is the command itself: it
    # reads a recorded fact or maps one, and every value it derives is pinned by a
    # test in this file. This guard is the schema-stability check, not a proof.
    REPORT_KEY_NAMES = {
        "action", "active_state", "admission_authority", "adoption", "approval", "approved_at",
        "base", "basis", "binding", "candidate_sha256", "capability_admission_records",
        "capability_admission_verdicts", "capability_id", "capability_lock_approvals",
        "capability_rejection_records", "catalog", "commit", "consistency", "coverage",
        "current_generation", "decision", "deploy_path", "deployable", "detail", "evidence",
        "evidence_refs", "evidence_sha256", "high_risk", "install_manifest", "invocation",
        "lifecycle", "lifecycle_decision_actions", "lifecycle_decisions", "lifecycle_records",
        "lock", "lock_approval_state", "managed_ids", "observed_at", "operational_admission",
        "partial_or_conditional", "predicate", "project", "reason_code", "record_family", "repo",
        "report_kind", "reservation", "risk", "rule", "schema_version", "scope", "skills_exists",
        "source_facts", "transaction", "transaction_id", "trust", "verdict",
    }

    EXPECTED_COVERAGE = {
        "lifecycle_decisions": "complete_for_available_history",
        "lifecycle_decision_actions": "recorded_only_on_preview_invocations_not_evaluated_here",
        "capability_lock_approvals": "recorded",
        "capability_admission_verdicts": "derived_from_the_planes_own_pure_predicate",
        "capability_rejection_records": "not_persisted_by_core",
    }

    def reports(self):
        """Both variants. A mutation gated on `consistency == 'locked'` only fires
        on an enrolled base, so a guard that produces only the unenrolled report
        never sees the document that path builds."""
        unenrolled = self.run_decisions()
        self.enroll()
        enrolled = self.run_decisions()
        return ("unenrolled", unenrolled), ("enrolled", enrolled)

    def test_the_report_shape_is_exactly_the_known_schema(self):
        for label, (_code, report) in self.reports():
            unexpected = sorted(all_keys(report, set()) - self.REPORT_KEY_NAMES)
            self.assertEqual(
                unexpected, [],
                label + ": key name(s) this command should not be producing at all: " + repr(unexpected),
            )
            self.assertEqual(report["coverage"], self.EXPECTED_COVERAGE, label)
            self.assertIsInstance(report["detail"], str, label + ": detail must stay the error string")
            for record in report["lifecycle_records"]:
                self.assertIsInstance(record["decision"], type(None), label)
                self.assertEqual(record["evidence_refs"], [], label)
                self.assertIsInstance(record["source_facts"]["detail"], str, label)

    def test_the_rejection_gap_is_declared_not_counted(self):
        _, (_, out) = self.reports()[0]
        self.assertEqual(out["coverage"]["capability_rejection_records"], "not_persisted_by_core")
        self.assertEqual(
            out["coverage"]["capability_admission_verdicts"],
            "derived_from_the_planes_own_pure_predicate",
        )
        # The declaration above is the positive half; the shape test is the
        # negative half, and it must hold on the enrolled report too.
        for label, (_code, report) in self.reports():
            self.assertEqual(report["coverage"]["capability_rejection_records"], "not_persisted_by_core", label)

    def test_capability_records_keep_the_facts_they_normalised(self):
        _, out = self.run_decisions()
        records = {r["capability_id"]: r for r in out["capability_admission_records"]}
        self.assertEqual(sorted(records), ["example-eligible", "example-ineligible"])
        for record in records.values():
            self.assertEqual(record["record_family"], "capability_admission")
            self.assertEqual(record["lock_approval_state"], "approved")
            self.assertIsNone(record["reason_code"])
            lock = record["source_facts"]["lock"]
            self.assertEqual(
                lock["approval"],
                {
                    "partial_or_conditional": False,
                    "high_risk": False,
                    "approved_at": "1970-01-01T00:00:00Z",
                },
            )
            self.assertEqual(record["evidence_refs"], [lock["evidence"]])
            self.assertEqual(record["source_facts"]["catalog"]["risk"], "low")

    def test_the_admission_verdict_comes_from_the_planes_own_predicate(self):
        """The shipped fixture contains a locked-but-refused provider on purpose.

        `example-ineligible` is `adoption: 'candidate'`, and its own catalog note
        says it "is refused by operational admission". A record that called it
        admitted would invert the honesty goal this command exists for.
        """
        _, out = self.run_decisions()
        records = {r["capability_id"]: r for r in out["capability_admission_records"]}
        self.assertEqual(records["example-eligible"]["operational_admission"]["verdict"], "eligible")
        refused = records["example-ineligible"]["operational_admission"]
        self.assertEqual(refused["verdict"], "refused")
        self.assertEqual(refused["predicate"], "approval_ok")
        self.assertIn("adoption=candidate", refused["detail"])
        self.assertEqual(
            records["example-ineligible"]["source_facts"]["catalog"]["adoption"], "candidate"
        )

    def test_a_lock_with_no_catalog_entry_is_unknown_not_refused(self):
        lock = json.loads(self.lock_path().read_text())
        lock["sources"]["example-orphan"] = dict(lock["sources"]["example-eligible"])
        lock["sources"]["example-orphan"]["evidence"] = "audit/evidence/example-orphan.json"
        self.lock_path().write_text(json.dumps(lock))
        _, out = self.run_decisions()
        records = {r["capability_id"]: r for r in out["capability_admission_records"]}
        self.assertEqual(records["example-orphan"]["operational_admission"]["verdict"], "unknown")
        self.assertIsNone(records["example-orphan"]["source_facts"]["catalog"])

    def test_conditional_or_high_risk_approval_is_named_as_such(self):
        lock = json.loads(self.lock_path().read_text())
        lock["sources"]["example-eligible"]["approval"]["partial_or_conditional"] = True
        self.lock_path().write_text(json.dumps(lock))
        _, out = self.run_decisions()
        states = {r["capability_id"]: r["lock_approval_state"] for r in out["capability_admission_records"]}
        self.assertEqual(states["example-eligible"], "approved_with_conditions")
        self.assertEqual(states["example-ineligible"], "approved")

    def test_lifecycle_decision_fields_stay_null_because_core_recorded_none(self):
        _, out = self.run_decisions()
        record = out["lifecycle_records"][0]
        self.assertIsNone(record["decision"])
        self.assertIsNone(record["rule"])
        self.assertIsNone(record["action"])
        self.assertEqual(record["reason_code"], "NO_EXISTING_LIFECYCLE_LOCK")
        self.assertEqual(record["consistency"], "uncoordinated")
        self.assertEqual(
            out["coverage"]["lifecycle_decision_actions"],
            "recorded_only_on_preview_invocations_not_evaluated_here",
        )

    def test_running_it_twice_changes_nothing(self):
        before = (tree_hash(self.cp), tree_hash(self.project))
        first_code, first = self.run_decisions()
        second_code, second = self.run_decisions()
        self.assertEqual(tree_hash(self.cp), before[0], "decisions wrote into the control plane")
        self.assertEqual(tree_hash(self.project), before[1], "decisions wrote into the project")
        self.assertEqual(first_code, second_code)
        self._assert_same_facts(first, second)

    def test_running_it_twice_changes_nothing_on_an_enrolled_base(self):
        """The coordinated path is the only one that reads plane state.

        On an unenrolled project `reader_session` reports `coordinated=False` and
        `reader_snapshot` is never called, so a write added anywhere inside the
        reader -- or inside this command, gated on the base existing -- would pass
        an unenrolled-only test while writing on a real instance. Enrolling the
        base is what makes the read-only claim cover the code that runs.
        """
        self.enroll()
        before = (tree_hash(self.cp), tree_hash(self.project))
        code, out = self.run_decisions()
        self.assertEqual(tree_hash(self.cp), before[0], "decisions wrote into the control plane")
        self.assertEqual(tree_hash(self.project), before[1], "decisions wrote into the project")
        lifecycle = out["lifecycle_records"][0]
        self.assertEqual(lifecycle["consistency"], "locked")
        self.assertEqual(lifecycle["reason_code"], "VALIDATED")
        self.assertEqual(code, 0, "a VALIDATED lifecycle with a readable lock exits 0")

    def _assert_same_facts(self, first, second):
        def blank_timestamps(node):
            if isinstance(node, dict):
                if "observed_at" in node:
                    node["observed_at"] = "<time>"
                for value in node.values():
                    blank_timestamps(value)
            elif isinstance(node, list):
                for value in node:
                    blank_timestamps(value)

        blank_timestamps(first)
        blank_timestamps(second)
        self.assertEqual(first, second, "two runs must observe the same facts")

    def test_an_empty_lock_is_recorded_not_unavailable(self):
        self.lock_path().write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "generated_at": "1970-01-01T00:00:00Z",
                    "policy": "lock-first",
                    "sources": {},
                }
            )
        )
        _, out = self.run_decisions()
        self.assertEqual(out["capability_admission_records"], [])
        self.assertEqual(out["coverage"]["capability_lock_approvals"], "recorded")

    def test_an_unreadable_lock_is_unavailable_not_empty(self):
        self.lock_path().write_text("{ not json")
        code, out = self.run_decisions()
        self.assertEqual(out["capability_admission_records"], [])
        self.assertEqual(out["coverage"]["capability_lock_approvals"], "unavailable")
        self.assertTrue(out["detail"], "the read failure must be stated, not swallowed")
        self.assertEqual(code, 2)

    def test_a_read_failure_forces_a_non_zero_exit_even_when_the_lifecycle_validated(self):
        """The `or detail` term in the exit expression is otherwise untested.

        Enrolling the base makes the lifecycle read VALIDATED; making the lock
        unreadable then sets `detail` without changing that. Both halves are needed
        for the case to isolate the term, and a mutation that deletes `or detail`
        must fail here.
        """
        self.enroll()
        self.lock_path().write_text("{ not json")
        code, out = self.run_decisions()
        self.assertEqual(out["lifecycle_records"][0]["reason_code"], "VALIDATED")
        self.assertTrue(out["detail"], "the lock read failure must be reported")
        self.assertEqual(code, 2, "a reported read failure must not exit 0")

    def test_the_command_requires_a_project(self):
        parser = accp.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["decisions"])
        args = parser.parse_args(["decisions", "--project", str(self.project)])
        self.assertIs(args.fn, accp.cmd_decisions)
        self.assertEqual(args.scope, "project")


if __name__ == "__main__":
    unittest.main()
