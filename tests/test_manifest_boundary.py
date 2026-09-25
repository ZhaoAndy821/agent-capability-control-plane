import json
import io
import os
import pathlib
import shutil
import stat
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


class ManifestBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = audit_tempdir()
        self.base = self.tmp.__enter__()
        control_plane = self.base / 'control-plane'
        control_plane.mkdir()
        patcher = mock.patch.object(accp, 'ROOT', control_plane)
        patcher.start()
        self.addCleanup(patcher.stop)
        self._set_up_resolver_fixtures(control_plane)
        self.project = self.base / "project"
        self.project.mkdir()
        self.agents = self.project / ".agents"
        self.skills = self.agents / "skills"
        self.skills.mkdir(parents=True)
        self.manifest = self.agents / "install-manifest.json"
        self.state = self.agents / "active-state.json"
        self.mutex = self.agents / ".accp-activate.lock"
        self.managed = self.skills / "managed-safe"
        self.unmanaged = self.skills / "unmanaged-safe"
        self.managed.mkdir()
        self.unmanaged.mkdir()
        (self.managed / "payload.txt").write_text("managed", encoding="utf-8")
        (self.unmanaged / "payload.txt").write_text("preserve", encoding="utf-8")

    def _set_up_resolver_fixtures(self, control_plane):
        fixture_paths = {
            'CATALOG': control_plane / 'registry' / 'catalog.json',
            'LOCK': control_plane / 'lock' / 'sources.lock.json',
            'CONFLICTS': control_plane / 'registry' / 'conflict-groups.json',
            'OP_MODES': control_plane / 'modes' / 'operational-modes.json',
        }
        for path in fixture_paths.values():
            path.parent.mkdir(parents=True, exist_ok=True)
        fixture_paths['CATALOG'].write_text(
            json.dumps({'schema_version': 2, 'entries': []}) + '\n', encoding='utf-8')
        fixture_paths['LOCK'].write_text(
            json.dumps({'schema_version': 2, 'sources': {}}) + '\n', encoding='utf-8')
        fixture_paths['CONFLICTS'].write_text(
            json.dumps({'schema_version': 2, 'groups': {}}) + '\n', encoding='utf-8')
        fixture_paths['OP_MODES'].write_text(json.dumps({
            'schema_version': 1,
            'modes': {'fixture': {'providers': []}, 'audit': {'providers': []}},
        }) + '\n', encoding='utf-8')
        patchers = [mock.patch.object(accp, name, path)
                    for name, path in fixture_paths.items()]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.__exit__(None, None, None)

    def args(self, command, dry_run=False, scope="project"):
        values = {"project": str(self.project), "scope": scope}
        if command == "activate":
            values.update({"mode": "audit", "allow_partial": False, "dry_run": dry_run})
        else:
            values["dry_run"] = dry_run
        return Namespace(**values)

    def valid_manifest(self, managed_ids=None):
        return {
            "schema_version": 1,
            "control_plane_path": str(accp.ROOT),
            "scope": "project",
            "project": str(self.project.resolve()),
            "managed_ids": ["managed-safe"] if managed_ids is None else managed_ids,
        }

    def write_manifest(self, value):
        if isinstance(value, bytes):
            self.manifest.write_bytes(value)
        else:
            self.manifest.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def snapshot(self):
        return {
            str(p.relative_to(self.agents)): p.read_bytes()
            for p in self.agents.rglob("*")
            if p.is_file()
        }

    def invoke_command(self, command, dry_run=False, scope="project"):
        fn = accp.cmd_activate if command == "activate" else accp.cmd_deactivate
        return fn(self.args(command, dry_run, scope))

    def assert_refused_before_mutation(self, command, value):
        self.write_manifest(value)
        before = self.snapshot()
        with self.assertRaises((RuntimeError, json.JSONDecodeError)):
            self.invoke_command(command)
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.mutex.exists())
        self.assertEqual([], list(self.agents.glob(".skills-stage-*")))

    def test_valid_manifest_activation_removes_only_managed_child(self):
        self.write_manifest(self.valid_manifest())
        self.state.write_text(json.dumps({'schema_version':1,'control_plane_path':str(accp.ROOT),
                                          'active_ids':['managed-safe']}),encoding='utf-8')
        self.invoke_command("activate")
        self.assertFalse(self.managed.exists())
        self.assertTrue((self.unmanaged / "payload.txt").exists())
        self.assertEqual([], json.loads(self.manifest.read_text())["managed_ids"])

    def test_valid_manifest_deactivation_removes_only_managed_child(self):
        self.write_manifest(self.valid_manifest())
        self.state.write_text(json.dumps({'schema_version': 1, 'control_plane_path': str(accp.ROOT),
                                          'active_ids': ['managed-safe']}))
        self.invoke_command("deactivate")
        self.assertFalse(self.managed.exists())
        self.assertTrue((self.unmanaged / "payload.txt").exists())

    def test_missing_managed_child_refuses_lifecycle_mutation(self):
        shutil.rmtree(self.managed)
        self.write_manifest(self.valid_manifest())
        self.state.write_text(json.dumps({'schema_version': 1, 'control_plane_path': str(accp.ROOT),
                                          'active_ids': ['managed-safe']}))
        with self.assertRaises(FileNotFoundError): self.invoke_command("deactivate")
        self.assertTrue(self.unmanaged.exists())

    def test_missing_manifest_is_treated_as_empty(self):
        self.invoke_command("activate")
        self.assertTrue(self.managed.exists())
        self.assertTrue(self.unmanaged.exists())
        accp.cmd_recover(Namespace(project=str(self.project),scope='project',dry_run=False,cleanup=True))
        self.manifest.unlink()
        with self.assertRaises(ValueError): self.invoke_command("deactivate")
        self.state.unlink()
        self.invoke_command("deactivate")
        self.assertTrue(self.managed.exists())
        self.assertTrue(self.unmanaged.exists())

    def test_invalid_json_and_non_object_are_refused_for_both_commands(self):
        for value in (b"{", [], ["managed-safe"], "managed-safe"):
            for command in ("activate", "deactivate"):
                with self.subTest(value=value, command=command):
                    self.assert_refused_before_mutation(command, value)

    def test_managed_ids_must_be_a_present_list(self):
        for ids in (None, {}, True, "managed-safe"):
            value = self.valid_manifest()
            if ids is None:
                del value["managed_ids"]
            else:
                value["managed_ids"] = ids
            for command in ("activate", "deactivate"):
                with self.subTest(ids=ids, command=command):
                    self.assert_refused_before_mutation(command, value)

    def test_duplicate_json_metadata_is_refused(self):
        value = json.dumps(self.valid_manifest()).replace(
            '"managed_ids": ["managed-safe"]',
            '"managed_ids": ["managed-safe"], "managed_ids": []',
        ).encode()
        for command in ("activate", "deactivate"):
            self.assert_refused_before_mutation(command, value)

    def test_manifest_metadata_must_match_control_plane_scope_and_project(self):
        cases = [
            {"schema_version": 1},
            {**self.valid_manifest(), "schema_version": True},
            {**self.valid_manifest(), "schema_version": 2},
            {**self.valid_manifest(), "control_plane_path": str(self.base / "other")},
            {**self.valid_manifest(), "scope": "user"},
            {**self.valid_manifest(), "project": str(self.base / "other")},
        ]
        for value in cases:
            for command in ("activate", "deactivate"):
                with self.subTest(value=value, command=command):
                    self.assert_refused_before_mutation(command, value)

    def test_managed_ids_reject_escape_absolute_and_invalid_names(self):
        ids = [
            "",
            None,
            1,
            "Managed-Safe",
            "managed safe",
            "managed/safe",
            "managed\\safe",
            "../outside",
            "..\\outside",
            "/tmp/outside",
            r"C:\\outside",
            r"C:/outside",
            r"\\\\server\\share\\outside",
            r"\\?\\C:\\outside",
            r"C:outside",
            r"\\server\share\outside",
            r"\\.\pipe\outside",
            ".",
            "..",
            ".agents",
            "managed-safe.",
            "managed-safe ",
            "con",
            "con.txt",
            "lpt1",
            "lpt1.txt",
            "aux",
            "nul",
            ["nested"],
        ]
        victim = self.base / "victim"
        victim.mkdir()
        (victim / "sentinel.txt").write_text("preserve", encoding="utf-8")
        ids.append(str(victim.resolve()))
        for invalid in ids:
            for command in ("activate", "deactivate"):
                with self.subTest(invalid=invalid, command=command):
                    self.assert_refused_before_mutation(
                        command, self.valid_manifest([invalid])
                    )
        self.assertEqual("preserve", (victim / "sentinel.txt").read_text(encoding="utf-8"))

    def test_duplicate_managed_ids_are_refused(self):
        for command in ("activate", "deactivate"):
            self.assert_refused_before_mutation(
                command, self.valid_manifest(["managed-safe", "managed-safe"])
            )

    def test_dry_run_validates_manifest_without_mutation(self):
        self.write_manifest(self.valid_manifest(["../outside"]))
        (self.agents/'.accp-lifecycle.lock').write_bytes(b'')
        before = self.snapshot()
        for command in ("activate", "deactivate"):
            with self.subTest(command=command), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(2,self.invoke_command(command, dry_run=True))
                report=json.loads(output.getvalue())
                self.assertEqual('UNKNOWN',report['lifecycle'])
                self.assertEqual('blocked',report['preview']['admission'])
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.mutex.exists())

    def test_valid_user_scope_uses_its_own_agents_boundary(self):
        user = self.base / "user-root"
        user_skills = user / "skills"
        user_skills.mkdir(parents=True)
        (user_skills / "managed-safe").mkdir()
        (user_skills / "unmanaged-safe").mkdir()
        (user_skills / "managed-safe" / "payload.txt").write_text("managed", encoding="utf-8")
        (user_skills / "unmanaged-safe" / "payload.txt").write_text("preserve", encoding="utf-8")
        user_manifest = user / "install-manifest.json"
        user_manifest.write_text(
            json.dumps({**self.valid_manifest(), "scope": "user"}) + "\n", encoding="utf-8"
        )
        (user / 'active-state.json').write_text(json.dumps({'schema_version': 1,
            'control_plane_path': str(accp.ROOT), 'active_ids': ['managed-safe']}))
        old = os.environ.get("ACCP_USER_SCOPE_ROOT")
        os.environ["ACCP_USER_SCOPE_ROOT"] = str(user)
        try:
            self.invoke_command("deactivate", scope="user")
        finally:
            if old is None:
                os.environ.pop("ACCP_USER_SCOPE_ROOT", None)
            else:
                os.environ["ACCP_USER_SCOPE_ROOT"] = old
        self.assertFalse((user_skills / "managed-safe").exists())
        self.assertTrue((user_skills / "unmanaged-safe").exists())

    def test_symlinked_managed_child_cannot_redirect_cleanup(self):
        outside = self.base / "symlink-outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep", encoding="utf-8")
        link = self.skills / "managed-link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            exc = sys.exc_info()[1]
            if isinstance(exc, NotImplementedError) or getattr(exc, "winerror", None) in (5, 1314) or getattr(exc, "errno", None) in (1, 13):
                self.skipTest("directory symlink creation unavailable without privilege")
            raise
        try:
            self.write_manifest(self.valid_manifest(["managed-link"]))
            for command in ("activate", "deactivate"):
                with self.subTest(command=command), self.assertRaises(RuntimeError):
                    self.invoke_command(command)
            self.assertTrue((outside / "keep.txt").exists())
        finally:
            link.unlink(missing_ok=True)

    def test_dangling_symlinked_managed_child_cannot_redirect_cleanup(self):
        link = self.skills / "managed-link"
        try:
            link.symlink_to(self.base / "does-not-exist", target_is_directory=True)
        except (OSError, NotImplementedError):
            exc = sys.exc_info()[1]
            if isinstance(exc, NotImplementedError) or getattr(exc, "winerror", None) in (5, 1314) or getattr(exc, "errno", None) in (1, 13):
                self.skipTest("directory symlink creation unavailable without privilege")
            raise
        try:
            self.write_manifest(self.valid_manifest(["managed-link"]))
            for command in ("activate", "deactivate"):
                with self.subTest(command=command), self.assertRaises(RuntimeError):
                    self.invoke_command(command)
        finally:
            link.unlink(missing_ok=True)

    def test_manifest_and_state_symlinks_are_refused_before_writes(self):
        for target, outside_name in ((self.manifest, "manifest-target.json"), (self.state, "state-target.json")):
            outside = self.base / outside_name
            outside.write_text("{}\n", encoding="utf-8")
            try:
                target.symlink_to(outside)
            except (OSError, NotImplementedError):
                exc = sys.exc_info()[1]
                if isinstance(exc, NotImplementedError) or getattr(exc, "winerror", None) in (5, 1314) or getattr(exc, "errno", None) in (1, 13):
                    self.skipTest("file symlink creation unavailable without privilege")
                raise
            try:
                before = self.snapshot()
                for command in ("activate", "deactivate"):
                    with self.subTest(target=target.name, command=command), self.assertRaises(RuntimeError):
                        self.invoke_command(command)
                    self.assertEqual(before, self.snapshot())
                    self.assertFalse(self.mutex.exists())
                    self.assertEqual([], list(self.agents.glob(".skills-stage-*")))
                self.assertEqual("{}\n", outside.read_text(encoding="utf-8"))
            finally:
                target.unlink(missing_ok=True)

    def test_reparse_attribute_is_refused_even_without_symlink_mode(self):
        target = self.skills / "managed-safe"
        original_lstat = pathlib.Path.lstat
        reparse_info = Namespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)

        def fake_lstat(path):
            if path == target:
                return reparse_info
            return original_lstat(path)

        with mock.patch.object(pathlib.Path, "lstat", autospec=True, side_effect=fake_lstat):
            with self.assertRaises(RuntimeError):
                accp.assert_plain_path(target)

    def test_synthetic_symlink_mode_is_refused_for_manifest_state_and_managed_path(self):
        cases = [(self.manifest, None), (self.state, None), (self.managed, self.valid_manifest())]
        original_lstat = pathlib.Path.lstat
        symlink_info = Namespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
        for target, manifest in cases:
            if manifest is not None:
                self.write_manifest(manifest)

            def fake_lstat(path, target=target):
                if path == target:
                    return symlink_info
                return original_lstat(path)

            before = self.snapshot()
            with mock.patch.object(pathlib.Path, "lstat", autospec=True, side_effect=fake_lstat):
                for command in ("activate", "deactivate"):
                    with self.subTest(target=target.name, command=command), self.assertRaises(RuntimeError):
                        self.invoke_command(command)
                    self.assertEqual(before, self.snapshot())
                    self.assertFalse(self.mutex.exists())
                    self.assertEqual([], list(self.agents.glob(".skills-stage-*")))

    @unittest.skipUnless(os.name == "nt", "Windows reparse-point fixture")
    def test_junctioned_agents_root_and_skills_root_cannot_redirect_cleanup(self):
        import subprocess

        for source, outside_name in ((self.agents, "agents-outside"), (self.skills, "skills-outside")):
            outside = self.base / outside_name
            outside.mkdir()
            (outside / "keep.txt").write_text("keep", encoding="utf-8")
            saved = self.base / (source.name + "-saved")
            source.rename(saved)
            try:
                cp = subprocess.run(
                    [os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"), "/c", "mklink", "/J", str(source), str(outside)],
                    capture_output=True,
                )
                if cp.returncode:
                    self.skipTest("junction creation unavailable")
                before = self.snapshot()
                for command in ("activate", "deactivate"):
                    with self.subTest(target=source.name, command=command), self.assertRaises(RuntimeError):
                        self.invoke_command(command)
                    self.assertEqual(before, self.snapshot())
                    self.assertFalse(self.mutex.exists())
                    self.assertEqual([], list(self.agents.glob(".skills-stage-*")))
                self.assertTrue((outside / "keep.txt").exists())
            finally:
                if source.is_dir() or source.is_symlink():
                    source.rmdir()
                saved.rename(source)

    @unittest.skipUnless(os.name == "nt", "Windows reparse-point fixture")
    def test_junctioned_managed_child_cannot_redirect_cleanup(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep", encoding="utf-8")
        junction = self.skills / "managed-safe"
        (junction / "payload.txt").unlink()
        junction.rmdir()
        import subprocess
        cp = subprocess.run([os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"), "/c", "mklink", "/J", str(junction), str(outside)], capture_output=True)
        if cp.returncode:
            self.skipTest("junction creation unavailable")
        try:
            self.write_manifest(self.valid_manifest())
            before = self.snapshot()
            for command in ("activate", "deactivate"):
                with self.subTest(command=command), self.assertRaises(RuntimeError):
                    self.invoke_command(command)
                self.assertFalse(self.mutex.exists())
                self.assertEqual([], list(self.agents.glob(".skills-stage-*")))
            self.assertEqual(before, self.snapshot())
            self.assertTrue((outside / "keep.txt").exists())
        finally:
            junction.rmdir()

    @unittest.skipUnless(os.name == "nt", "Windows reparse-point fixture")
    def test_nested_junction_cannot_redirect_cleanup(self):
        outside = self.base / "nested-outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep", encoding="utf-8")
        nested = self.unmanaged / "nested-link"
        import subprocess
        cp = subprocess.run([os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"), "/c", "mklink", "/J", str(nested), str(outside)], capture_output=True)
        if cp.returncode:
            self.skipTest("junction creation unavailable")
        try:
            self.write_manifest(self.valid_manifest())
            before = self.snapshot()
            for command in ("activate", "deactivate"):
                with self.subTest(command=command), self.assertRaises(RuntimeError):
                    self.invoke_command(command)
                self.assertFalse(self.mutex.exists())
                self.assertEqual([], list(self.agents.glob(".skills-stage-*")))
            self.assertEqual(before, self.snapshot())
            self.assertTrue((outside / "keep.txt").exists())
        finally:
            nested.rmdir()


if __name__ == "__main__":
    unittest.main()
