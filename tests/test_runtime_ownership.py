import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import scripts.runtime_ownership as ownership
from scripts.runtime_ownership import RuntimeOwnership


class RuntimeOwnershipTests(unittest.TestCase):
    """Acceptance tests for the F02 ownership boundary.

    These tests deliberately use repository-local temporary paths.  They never
    use the process home directory or the default runtime.
    """

    def setUp(self):
        self.temp_root = REPO / ".local" / "audit-temp"
        self.temp_root.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=self.temp_root)
        self.base = pathlib.Path(self.tmp.name)
        self.control_plane = self.base / "fake_cp"
        self.control_plane.mkdir()
        self.project = self.base / "project"
        self.project.mkdir()
        self.runtime = self.base / "runtime"
        self.fixture_home = self.base / "fixture-home"
        self.fixture_home.mkdir()
        self.identity_patch = mock.patch.object(
            ownership,
            "principal_and_profile",
            return_value=("uid:424242", self.fixture_home),
        )
        self.identity_patch.start()

    def tearDown(self):
        self.identity_patch.stop()
        self.tmp.cleanup()

    def owner(self, path=None, project=None):
        return RuntimeOwnership(
            self.runtime if path is None else path,
            self.control_plane,
            project=project if project is not None else self.project,
        )

    def create_owned(self, path=None):
        owner = self.owner(path)
        with owner.session(create=True):
            pass
        return owner

    @staticmethod
    def read_json(path):
        return json.loads(path.read_text(encoding="utf-8"))

    def write_json(self, path, value):
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def marker(self, owner):
        return owner.marker_path

    def receipt(self, owner):
        return owner.receipt_path

    def test_valid_owned_runtime_removes_only_fixed_components(self):
        owner = self.create_owned()
        root = owner.root
        (root / "unrelated.txt").write_text("preserve", encoding="utf-8")
        (root / "unrelated-dir").mkdir()
        (root / "unrelated-dir" / "keep.txt").write_text("preserve", encoding="utf-8")
        (root / "sources" / "cache.txt").write_text("owned", encoding="utf-8")
        (root / "vault" / "cache.txt").write_text("owned", encoding="utf-8")
        (root / "install-manifest.json").write_text("{}\n", encoding="utf-8")
        (root / "active-state.json").write_text("{}\n", encoding="utf-8")

        plan = owner.uninstall(yes=True)

        self.assertIn(plan.get("state", "retired"), ("retired", "complete"))
        self.assertTrue(root.exists())
        self.assertTrue(self.marker(owner).exists())
        self.assertTrue(self.receipt(owner).exists())
        self.assertFalse((root / "sources").exists())
        self.assertFalse((root / "vault").exists())
        self.assertFalse((root / "install-manifest.json").exists())
        self.assertFalse((root / "active-state.json").exists())
        self.assertEqual("preserve", (root / "unrelated.txt").read_text())
        self.assertEqual("preserve", (root / "unrelated-dir" / "keep.txt").read_text())
        self.assertEqual("retired", self.read_json(self.receipt(owner))["state"])

    def test_dry_run_requires_no_confirmation_and_does_not_mutate(self):
        owner = self.create_owned()
        (owner.root / "unknown.txt").write_text("keep", encoding="utf-8")
        before = {p.relative_to(owner.root).as_posix(): p.read_bytes()
                  for p in owner.root.rglob("*") if p.is_file()}

        plan = owner.uninstall(dry_run=True)

        self.assertIsInstance(plan, dict)
        self.assertEqual(before, {p.relative_to(owner.root).as_posix(): p.read_bytes()
                                  for p in owner.root.rglob("*") if p.is_file()})
        self.assertEqual("ready", self.read_json(self.receipt(owner))["state"])
        self.assertFalse(owner.lock_path.exists())

    def test_real_uninstall_without_yes_is_refused(self):
        owner = self.create_owned()
        (owner.root / "sources" / "keep").write_text("keep", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            owner.uninstall()
        self.assertTrue((owner.root / "sources" / "keep").exists())

    def test_existing_unrelated_runtime_is_never_adopted_or_deleted(self):
        self.runtime.mkdir()
        sentinel = self.runtime / "sentinel.txt"
        sentinel.write_text("legacy", encoding="utf-8")
        owner = self.owner()

        with self.assertRaises(RuntimeError):
            owner.validate()
        with self.assertRaises(RuntimeError):
            with owner.session(create=True):
                pass
        with self.assertRaises(RuntimeError):
            owner.uninstall(yes=True)
        self.assertEqual("legacy", sentinel.read_text())

    def test_empty_relative_and_traversal_runtime_inputs_are_rejected(self):
        for raw in ("", ".", "..", "runtime", "..\\outside", "C:relative"):
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                self.owner(raw)

    def test_protected_roots_are_rejected_before_metadata_or_mutation(self):
        protected = [self.control_plane, self.project, pathlib.Path.home(), pathlib.Path.cwd()]
        if os.name != "nt":
            protected.append(pathlib.Path(os.path.abspath(os.sep)))
        for path in protected:
            with self.subTest(path=path):
                with self.assertRaises(RuntimeError):
                    self.owner(path).uninstall(yes=True)

    @unittest.skipUnless(os.name == "nt", "Windows drive/UNC roots")
    def test_drive_and_unc_roots_are_rejected(self):
        for raw in ("C:\\\\", "\\\\localhost\\share\\"):
            with self.subTest(raw=raw):
                with self.assertRaises(RuntimeError):
                    self.owner(raw).uninstall(yes=True)

    def test_marker_and_receipt_are_required_and_exactly_bound(self):
        owner = self.create_owned()
        marker = self.read_json(self.marker(owner))
        receipt = self.read_json(self.receipt(owner))

        cases = [
            ("missing-marker", "missing-marker"),
            ("missing-receipt", "missing-receipt"),
            ("bad-marker-json", "bad-marker-json"),
            ("bad-receipt-json", "bad-receipt-json"),
            ("marker-path", ("marker", "runtime_path", str(self.base / "elsewhere"))),
            ("receipt-id", ("receipt", "runtime_id", "00000000-0000-4000-8000-000000000000")),
            ("receipt-principal", ("receipt", "principal", "uid:999999")),
            ("receipt-marker-hash", ("receipt", "marker_sha256", "0" * 64)),
        ]

        for name, mutate in cases:
            with self.subTest(name=name):
                # Rebuild a private runtime for each mutation.
                local = self.base / name
                current = self.create_owned(local)
                if mutate == "missing-marker":
                    self.marker(current).unlink()
                elif mutate == "missing-receipt":
                    self.receipt(current).unlink()
                elif mutate == "bad-marker-json":
                    self.marker(current).write_text("[]", encoding="utf-8")
                elif mutate == "bad-receipt-json":
                    self.receipt(current).write_text("{}", encoding="utf-8")
                else:
                    record, key, value = mutate
                    target = self.marker(current) if record == "marker" else self.receipt(current)
                    data = self.read_json(target)
                    data[key] = value
                    self.write_json(target, data)
                with self.assertRaises(RuntimeError):
                    current.validate()
                with self.assertRaises(RuntimeError):
                    current.uninstall(yes=True)
                self.assertTrue(current.root.exists())

    def _mutate_marker(self, owner, key, value):
        data = self.read_json(self.marker(owner))
        data[key] = value
        self.write_json(self.marker(owner), data)

    def _mutate_receipt(self, owner, key, value):
        data = self.read_json(self.receipt(owner))
        data[key] = value
        self.write_json(self.receipt(owner), data)

    def test_root_symlink_and_component_redirection_are_refused(self):
        target = self.base / "real-runtime"
        owner = self.create_owned(target)
        linked = self.base / "linked-runtime"
        try:
            linked.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            if getattr(exc, "winerror", None) in (5, 1314) or getattr(exc, "errno", None) in (1, 13):
                self.skipTest("directory symlink creation unavailable")
            raise
        with self.assertRaises(RuntimeError):
            self.owner(linked).uninstall(yes=True)

        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep", encoding="utf-8")
        shutil.rmtree(owner.root / "sources")
        (owner.root / "sources").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            owner.uninstall(yes=True)
        self.assertTrue((outside / "keep.txt").exists())

    def test_hardlinked_owned_file_is_refused_before_recursive_delete(self):
        owner = self.create_owned()
        outside = self.base / "outside.txt"
        outside.write_text("keep", encoding="utf-8")
        linked = owner.root / "sources" / "linked.txt"
        try:
            os.link(outside, linked)
        except (OSError, NotImplementedError):
            self.skipTest("hard links unavailable")
        with self.assertRaises(RuntimeError):
            owner.uninstall(yes=True)
        self.assertTrue(outside.exists())
        self.assertTrue(linked.exists())

    def test_partial_delete_keeps_deleting_state_and_retry_is_bounded(self):
        owner = self.create_owned()
        (owner.root / "sources" / "cache.txt").write_text("owned", encoding="utf-8")
        (owner.root / "vault" / "cache.txt").write_text("owned", encoding="utf-8")
        original = ownership.shutil.rmtree

        def fail_sources(path, *args, **kwargs):
            if pathlib.Path(path) == owner.root / "sources":
                raise OSError("fixture deletion failure")
            return original(path, *args, **kwargs)

        with mock.patch.object(ownership.shutil, "rmtree", side_effect=fail_sources):
            with self.assertRaises(RuntimeError):
                owner.uninstall(yes=True)
        self.assertEqual("deleting", self.read_json(self.receipt(owner))["state"])
        self.assertTrue((owner.root / "sources").exists())
        owner.uninstall(yes=True)
        self.assertEqual("retired", self.read_json(self.receipt(owner))["state"])

    def test_legacy_runtime_is_rebuild_only_and_not_auto_adopted(self):
        self.runtime.mkdir()
        (self.runtime / "sources").mkdir()
        (self.runtime / "sources" / "legacy.txt").write_text("legacy", encoding="utf-8")
        owner = self.owner()
        with self.assertRaises(RuntimeError):
            with owner.session(create=True):
                pass
        with self.assertRaises(RuntimeError):
            owner.uninstall(yes=True)
        self.assertTrue((self.runtime / "sources" / "legacy.txt").exists())
        fresh = self.create_owned(self.base / 'fresh')
        fresh.uninstall(yes=True)
        self.assertEqual('legacy', (self.runtime/'sources/legacy.txt').read_text())

    def test_windows_path_spellings_and_store_overlap(self):
        roots = [self.control_plane/'.local/runtime-owners',
                 self.control_plane/'.local/runtime-owners/child', self.fixture_home,
                 self.control_plane.parent]
        if os.name == 'nt':
            roots += [r'\rooted', r'\\?\C:\runtime', r'\\.\C:\runtime',
                      str(self.runtime)+':stream', str(self.runtime)+'.',
                      str(self.runtime)+' ', str(self.base/'NUL.txt'),
                      str(self.base/'COM1'), str(self.base/'a')+'/../runtime']
        for root in roots:
            with self.subTest(root=root), self.assertRaises(RuntimeError):
                self.owner(root)

    def test_forged_marker_and_copied_records_do_not_grant_ownership(self):
        original = self.create_owned()
        stranger = self.base/'stranger'; stranger.mkdir()
        (stranger/ownership.MARKER).write_bytes(original.marker_path.read_bytes())
        forged = self.owner(stranger)
        with self.assertRaises(RuntimeError):
            forged.uninstall(yes=True)
        forged.receipt_path.write_bytes(original.receipt_path.read_bytes())
        with self.assertRaises(RuntimeError):
            forged.uninstall(yes=True)
        self.assertTrue((original.root/'sources').is_dir())

    def test_strict_record_schema_matrix(self):
        for record_name in ('marker_path', 'receipt_path'):
            for mutation in ('duplicate', 'oversized', 'bad-json', 'bool-schema',
                             'unknown', 'root-id', 'control-plane', 'bad-uuid'):
                with self.subTest(record=record_name, mutation=mutation):
                    owner = self.create_owned(self.base/(record_name+'-'+mutation))
                    path = getattr(owner, record_name)
                    data = self.read_json(path)
                    if mutation == 'duplicate':
                        path.write_text('{"schema_version":1,"schema_version":1}')
                    elif mutation == 'oversized':
                        path.write_text(' '*16385)
                    elif mutation == 'bad-json':
                        path.write_text('{')
                    else:
                        key, value = {'bool-schema': ('schema_version', True),
                                      'unknown': ('delete_paths', [str(self.base)]),
                                      'root-id': ('root_identity', {'device':'0','inode':'1'}),
                                      'control-plane': ('control_plane_path', str(self.base)),
                                      'bad-uuid': ('runtime_id', 'not-a-uuid')}[mutation]
                        data[key] = value; self.write_json(path, data)
                    with mock.patch.object(ownership.shutil, 'rmtree') as remove:
                        with self.assertRaises((RuntimeError, ValueError)):
                            owner.uninstall(yes=True)
                        remove.assert_not_called()
                    self.assertFalse(owner.lock_path.exists())

    def test_component_and_root_replacements_are_refused(self):
        for name in ('sources', 'vault', 'root'):
            with self.subTest(name=name):
                owner = self.create_owned(self.base/name)
                path = owner.root if name == 'root' else owner.root/name
                saved = self.base/(name+'-saved'); path.rename(saved)
                path.mkdir()
                if name == 'root':
                    (path/ownership.MARKER).write_bytes((saved/ownership.MARKER).read_bytes())
                with self.assertRaises(RuntimeError):
                    owner.uninstall(yes=True)
                self.assertTrue(path.exists()); self.assertTrue(saved.exists())

    def test_receipt_inventory_and_state_fail_closed(self):
        for name, value in [('components', {'../escape': {'type':'directory'}}),
                            ('state','unknown'), ('marker_sha256', []),
                            ('components', {'sources': {'type':'file'}})]:
            owner = self.create_owned(self.base/('inventory-'+str(len(list(self.base.iterdir())))))
            data = self.read_json(owner.receipt_path); data[name] = value
            self.write_json(owner.receipt_path, data)
            with self.assertRaises(RuntimeError):
                owner.uninstall(yes=True)
            self.assertTrue((owner.root/'sources').exists())

    def test_stale_mutex_blocks_mutation(self):
        owner = self.create_owned()
        owner.lock_path.write_text('held')
        before = owner.receipt_path.read_bytes()
        with self.assertRaises(RuntimeError):
            owner.uninstall(yes=True)
        self.assertEqual(before, owner.receipt_path.read_bytes())
        self.assertTrue((owner.root/'sources').exists())
        self.assertEqual('held', owner.lock_path.read_text())

    def test_receipt_write_failure_prevents_deletion(self):
        owner = self.create_owned()
        with mock.patch.object(owner, '_write_receipt', side_effect=OSError('receipt failed')):
            with self.assertRaises(OSError):
                owner.uninstall(yes=True)
        self.assertEqual('ready', self.read_json(owner.receipt_path)['state'])
        self.assertTrue((owner.root/'sources').exists())

    def test_second_deletion_failure_can_retry_missing_first_component(self):
        owner = self.create_owned()
        original = owner._delete_directory
        def fail_second(path):
            if path.name == 'vault': raise OSError('second deletion failed')
            return original(path)
        with mock.patch.object(owner, '_delete_directory', side_effect=fail_second):
            with self.assertRaises(RuntimeError): owner.uninstall(yes=True)
        self.assertFalse((owner.root/'sources').exists())
        self.assertEqual('deleting', self.read_json(owner.receipt_path)['state'])
        owner.uninstall(yes=True)
        self.assertEqual('retired', self.read_json(owner.receipt_path)['state'])

    def test_retired_is_idempotent_but_never_reinitialized(self):
        owner = self.create_owned(); owner.uninstall(yes=True)
        self.assertEqual('retired', owner.uninstall(yes=True)['state'])
        with self.assertRaises(RuntimeError):
            with owner.session(create=True): pass
        (owner.root/'sources').mkdir()
        with self.assertRaises(RuntimeError): owner.uninstall(yes=True)
        self.assertTrue((owner.root/'sources').exists())

    def test_failed_creation_is_not_auto_adopted(self):
        owner = self.owner()
        with mock.patch.object(owner, '_write_receipt', side_effect=OSError('registration failed')):
            with self.assertRaises(OSError):
                with owner.session(create=True): pass
        self.assertTrue(owner.root.exists())
        self.assertFalse(owner.receipt_path.exists())
        with self.assertRaises(RuntimeError):
            with owner.session(create=True): pass

    def test_absent_runtime_and_creation_dry_run_are_nonmutating(self):
        owner = self.owner()
        self.assertEqual('absent', owner.uninstall(yes=True)['state'])
        with owner.session(create=True, dry_run=True): pass
        self.assertFalse(owner.root.exists()); self.assertFalse(owner.store.exists())
        nested = self.owner(self.base/'missing-parent/runtime')
        with self.assertRaises(RuntimeError):
            with nested.session(create=True, dry_run=True): pass
        self.assertFalse(owner.store.exists())

    def test_different_checkout_or_principal_cannot_uninstall(self):
        owner = self.create_owned()
        other = self.base/'other-cp'; other.mkdir()
        with self.assertRaises(RuntimeError):
            RuntimeOwnership(owner.root, other).uninstall(yes=True)
        with mock.patch.object(ownership, 'principal_and_profile', return_value=('uid:999',self.fixture_home)):
            with self.assertRaises(RuntimeError): self.owner().uninstall(yes=True)

    @unittest.skipUnless(os.name == 'nt', 'Windows junctions')
    def test_junction_root_ancestor_and_nested_components(self):
        for placement in ('root', 'ancestor', 'component', 'nested', 'unknown'):
            with self.subTest(placement=placement):
                owner = self.create_owned(self.base/('junction-'+placement))
                outside = self.base/('outside-'+placement); outside.mkdir()
                sentinel = outside/'keep'; sentinel.write_text('keep')
                if placement == 'root':
                    link = self.base/'runtime-alias'; candidate = link
                    target = owner.root
                elif placement == 'ancestor':
                    link = self.base/'ancestor-alias'; target = self.base
                    candidate = link/owner.root.name
                else:
                    link = owner.root/({'component':'sources','nested':'sources/nested','unknown':'personal-link'}[placement])
                    if placement == 'component': link.rmdir()
                    target = outside; candidate = owner.root
                cp = subprocess.run([os.environ['COMSPEC'],'/c','mklink','/J',str(link),str(target)],capture_output=True)
                self.assertEqual(cp.returncode,0,cp.stderr.decode(errors='replace'))
                try:
                    if placement == 'unknown':
                        owner.uninstall(yes=True)
                        self.assertTrue(link.exists())
                    else:
                        with self.assertRaises(RuntimeError): self.owner(candidate).uninstall(yes=True)
                        self.assertFalse(owner.lock_path.exists())
                    self.assertEqual('keep',sentinel.read_text())
                finally:
                    link.rmdir()  # unlink the junction, never recursively follow it

    def test_synthetic_link_and_reparse_metadata(self):
        owner = self.create_owned()
        original = pathlib.Path.lstat
        for path in (owner.root, owner.marker_path, owner.receipt_path, owner.root/'sources'):
            for mode, attrs in ((stat.S_IFLNK,0),(stat.S_IFREG,0x400)):
                info = type('Info', (), {'st_mode':mode,'st_file_attributes':attrs})()
                def fake(p, *args, **kwargs):
                    return info if p == path else original(p, *args, **kwargs)
                with mock.patch.object(pathlib.Path,'lstat',autospec=True,side_effect=fake):
                    with self.assertRaises(RuntimeError): owner.uninstall(yes=True)
                self.assertTrue((owner.root/'sources').exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows read-only files')
    def test_readonly_single_link_file_is_deleted_safely(self):
        owner = self.create_owned()
        payload = owner.root/'sources/object'; payload.write_bytes(b'git object')
        payload.chmod(stat.S_IREAD)
        try:
            owner.uninstall(yes=True)
            self.assertFalse(payload.exists())
        finally:
            if payload.exists(): payload.chmod(stat.S_IWRITE)

    @unittest.skipUnless(os.name == 'nt', 'Windows token SID adapter')
    def test_native_sid_adapter_and_profile_lookup_failure(self):
        original = ownership.ctypes.WinDLL
        profile_path = str(self.fixture_home)
        class ProfileLookup:
            fail = False
            def __call__(self, token, buffer, size):
                if self.fail:
                    ownership.ctypes.set_last_error(2)
                    return 0
                buffer.value = profile_path
                return 1
        lookup = ProfileLookup()
        def dll(name, *args, **kwargs):
            if name == 'userenv':
                return type('Userenv', (), {'GetUserProfileDirectoryW': lookup})()
            return original(name, *args, **kwargs)
        # Real Windows token APIs; only profile lookup is simulated because this
        # sandbox service account has no OS profile. No environment identity hook.
        with mock.patch.object(ownership.ctypes, 'WinDLL', side_effect=dll):
            principal, profile = ownership.windows_identity()
            self.assertRegex(principal, r'^sid:S-1-[0-9-]+$')
            self.assertEqual(profile, self.fixture_home)
            lookup.fail = True
            with self.assertRaisesRegex(RuntimeError, 'OS profile'):
                ownership.windows_identity()


if __name__ == "__main__":
    unittest.main()
