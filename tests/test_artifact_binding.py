"""Focused F06 M1 contract tests; every fixture is disposable and local."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import artifact_binding as ab


class ArtifactBindingTests(unittest.TestCase):
    def setUp(self):
        local = Path(__file__).resolve().parents[1] / '.local' / 'audit-temp'
        local.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=local)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_canonical_json_vectors_and_rejections(self):
        self.assertEqual(ab.canonical_json({"b": 2, "a": "x"}), b'{"a":"x","b":2}')
        self.assertEqual(ab.canonical_json([True, None, -3]), b'[true,null,-3]')
        for value in (1.0, float("nan"), 2**63, -(2**63)-1, {1: "x"}, {"x": b"x"}, {"x": "\ud800"}):
            with self.assertRaises((ValueError, TypeError, ab.BindingError)):
                ab.canonical_json(value)

    def test_parse_json_is_strict(self):
        good = b'{"a":1}'
        self.assertEqual(ab.parse_json(good), {"a": 1})
        for raw in (b"\xef\xbb\xbf{}", b"{\"a\":1}{\"b\":2}", b"{\"a\":", b"\xff", b"1.0"):
            with self.assertRaises((ValueError, TypeError, ab.BindingError)):
                ab.parse_json(raw)
        with self.assertRaises((ValueError, TypeError, ab.BindingError)):
            ab.parse_json(b'{"a":1,"a":2}')

    def test_digest_domain_separation(self):
        expected = hashlib.sha256(b"accp-candidate-v1\0" + ab.canonical_json({"x": 1})).hexdigest()
        self.assertEqual(ab.digest("accp-candidate-v1", {"x": 1}), expected)
        self.assertNotEqual(ab.digest("accp-candidate-v1", {"x": 1}), ab.digest("accp-context-v1", {"x": 1}))

    def test_relative_path_contract(self):
        self.assertEqual(ab.canonical_relative_path(".", allow_dot=True), ".")
        self.assertEqual(ab.canonical_relative_path("agents/openai.yaml"), "agents/openai.yaml")
        for value in (None, "", "..", "../x", "/x", "C:x", "C:/x", r"a\\b", "a/../b", "a:stream", "CON", "x.", "x ", "a\x00b"):
            with self.assertRaises((ValueError, TypeError, ab.BindingError)):
                ab.canonical_relative_path(value)
        with self.assertRaises((ValueError, TypeError, ab.BindingError)):
            ab.canonical_relative_path(".", allow_dot=False)

    def test_file_origin_round_trip_and_https_canonicality(self):
        source = self.root / "source"
        source.mkdir()
        origin = ab.file_origin(source)
        self.assertEqual(origin["kind"], "file")
        self.assertEqual(ab.canonical_origin(origin["url"]), origin)
        self.assertEqual(ab.canonical_origin("https://github.com/a/b.git"),
                         {"kind": "https", "url": "https://github.com/a/b.git"})
        for bad in ("http://github.com/a/b", "https://github.com/a/b?x=1", "https://u:p@github.com/a/b", "ssh://github.com/a/b", "https://github.com/a//b"):
            with self.assertRaises((ValueError, TypeError, ab.BindingError)):
                ab.canonical_origin(bad)

    def test_inventory_and_projection_exact_bytes(self):
        tree = self.root / "tree"
        (tree / "agents").mkdir(parents=True)
        (tree / "SKILL.md").write_bytes(b"skill\n")
        (tree / "agents" / "openai.yaml").write_bytes(b"policy: {}\n")
        inv = ab.inventory_tree(tree)
        paths = [item["path"] for item in inv]
        self.assertEqual(paths, sorted(paths, key=lambda p: p.encode()))
        projected = ab.project_invocation({"SKILL.md": b"skill\n", "agents/openai.yaml": b"old\n"}, "implicit")
        self.assertEqual(projected["agents/openai.yaml"], b"policy:\n  allow_implicit_invocation: true\n")
        projected["SKILL.md"] = b"changed"
        self.assertEqual((tree / "SKILL.md").read_bytes(), b"skill\n")
        self.assertEqual(ab.payload_inventory(projected), ab.payload_inventory(dict(projected)))

    def test_inventory_rejects_links_and_reserved_nested_metadata(self):
        tree = self.root / "tree"; tree.mkdir()
        (tree / ".accp-vault-manifest.json").write_bytes(b"root")
        with self.assertRaises((ValueError, TypeError, ab.BindingError)):
            ab.inventory_tree(tree)
        (tree / '.accp-vault-manifest.json').unlink()
        nested = tree / "nested"; nested.mkdir()
        (nested / ".accp-vault-manifest.json").write_bytes(b"nested")
        with self.assertRaises((ValueError, TypeError, ab.BindingError)):
            ab.inventory_tree(tree)
        linktree = self.root / "linktree"; linktree.mkdir()
        target = self.root / "target"; target.write_bytes(b"x")
        link = linktree / "link"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest("native symlink privilege unavailable: %s" % exc)
        with self.assertRaises((ValueError, TypeError, ab.BindingError, OSError)):
            ab.inventory_tree(linktree)

    def test_native_hardlink_refused_and_target_unchanged(self):
        targetdir = self.root / "target"; targetdir.mkdir()
        treedir = self.root / "hardtree"; treedir.mkdir()
        target = targetdir / "data"; target.write_bytes(b"outside")
        os.link(target, treedir / "data")
        before = target.read_bytes()
        with self.assertRaises(ab.BindingError):
            ab.inventory_tree(treedir)
        self.assertEqual(target.read_bytes(), before)

    @unittest.skipUnless(os.name == "nt", "native junction requires Windows")
    def test_native_junction_refused_and_target_unchanged(self):
        target = self.root / 'junction-target'; target.mkdir()
        sentinel = target / 'sentinel'; sentinel.write_bytes(b'unrelated')
        tree = self.root / "junction"; tree.mkdir()
        link = tree / "redirect"
        cmd = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'cmd.exe')
        subprocess.run([cmd, "/c", "mklink", "/J", str(link), str(target)], check=True,
                       capture_output=True)
        try:
            before = sentinel.read_bytes()
            with self.assertRaises(ab.BindingError):
                ab.inventory_tree(tree)
            self.assertEqual(sentinel.read_bytes(), before)
        finally:
            link.rmdir()

    @unittest.skipUnless(os.name == "nt", "NTFS ADS requires Windows")
    def test_native_ads_refused(self):
        tree = self.root / "ads"; tree.mkdir()
        plain = tree / "file.txt"; plain.write_bytes(b"outside")
        Path(str(plain) + ":secret").write_bytes(b"hidden")
        with self.assertRaises(ab.BindingError):
            ab.inventory_tree(tree)

    def test_raw_bare_git_export_and_no_mutation(self):
        import shutil
        from unittest import mock
        git = shutil.which('git')
        self.assertIsNotNone(git, 'Git is required for raw-object acceptance')
        repo = self.root / "repo.git"
        def run(args, data=None):
            return subprocess.run([git, "-C", str(repo), *args], input=data, capture_output=True, check=True).stdout
        subprocess.run([git, "init", "--bare", str(repo)], check=True, capture_output=True)
        origin = "https://example.invalid/source"
        run(["config", "remote.origin.url", origin])
        blob = run(["hash-object", "-w", "--stdin"], b"hello\n").decode().strip()
        tree = run(["mktree"], ("100644 blob %s\tSKILL.md\n" % blob).encode()).decode().strip()
        commit = run(["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit-tree", tree], b"fixture\n").decode().strip()
        config_before = (repo / "config").read_bytes(); status_before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
        result = ab.export_locked_tree(repo, commit, ".", ab.canonical_origin(origin))
        self.assertEqual(result.payload, {"SKILL.md": b"hello\n"})
        self.assertEqual(result.inventory, [{"path": "SKILL.md", "type": "file", "size": 6, "sha256": hashlib.sha256(b"hello\n").hexdigest()}])
        self.assertEqual((repo / "config").read_bytes(), config_before)
        self.assertEqual({p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}, status_before)
        # Both loose and packed objects must be verified; no worktree is used.
        run(['update-ref', 'refs/heads/fixture', commit]); run(['repack', '-ad'])
        self.assertEqual(ab.export_locked_tree(repo, commit, '.', ab.canonical_origin(origin)).payload,
                         {'SKILL.md': b'hello\n'})
        subtree = run(['mktree'], f'40000 tree {tree}\tskill\n'.encode()).decode().strip()
        nested_commit = run(['-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                             'commit-tree', subtree], b'nested\n').decode().strip()
        nested = ab.export_locked_tree(repo, nested_commit, 'skill', ab.canonical_origin(origin))
        self.assertEqual(nested.source_tree_oid, tree)
        self.assertEqual(nested.payload, result.payload)
        empty = run(['mktree'], b'').decode().strip()
        dirs = run(['mktree'], f'100644 blob {blob}\tSKILL.md\n40000 tree {empty}\tempty\n'.encode()).decode().strip()
        dirs_commit = run(['-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                           'commit-tree', dirs], b'empty-directory\n').decode().strip()
        exported = ab.export_locked_tree(repo, dirs_commit, '.', ab.canonical_origin(origin))
        self.assertIn({'path': 'empty', 'type': 'directory'}, exported.inventory)
        self.assertIn({'path': 'empty', 'type': 'directory'}, ab.projected_inventory(exported.inventory, 'explicit'))
        for mode, kind, object_id in [('120000', 'blob', blob), ('160000', 'commit', commit)]:
            unsafe_tree = run(['mktree'], f'{mode} {kind} {object_id}\tSKILL.md\n'.encode()).decode().strip()
            unsafe_commit = run(['-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                                 'commit-tree', unsafe_tree], b'unsafe\n').decode().strip()
            with self.subTest(mode=mode), self.assertRaisesRegex(ab.BindingError, 'mode/link/gitlink'):
                ab.export_locked_tree(repo, unsafe_commit, '.', ab.canonical_origin(origin))
        original = ab._bounded_git
        def corrupt(repo_arg, args, limit):
            result = original(repo_arg, args, limit)
            return b'forged' if args == ['cat-file', 'blob', blob] else result
        with mock.patch.object(ab, '_bounded_git', side_effect=corrupt):
            with self.assertRaisesRegex(ab.BindingError, 'hash mismatch'):
                ab.export_locked_tree(repo, commit, '.', ab.canonical_origin(origin))
        run(['config', 'core.fsmonitor', 'untrusted-helper'])
        with mock.patch.object(ab, '_bounded_git') as git_call:
            with self.assertRaisesRegex(ab.BindingError, 'configuration'):
                ab.export_locked_tree(repo, commit, '.', ab.canonical_origin(origin))
            git_call.assert_not_called()

    def test_evidence_roundtrip_and_independent_binding_mismatches(self):
        source = [{"path": "SKILL.md", "type": "file", "size": 6,
                   "sha256": hashlib.sha256(b"hello\n").hexdigest()}]
        artifact = ab.projected_inventory(source, "explicit")
        candidate = {"binding_version": 1, "source_id": "demo", "catalog_sha256": "a" * 64,
                     "origin": {"kind": "https", "url": "https://example.invalid/source"},
                     "commit": "1" * 40, "source_tree_oid": "2" * 40, "deploy_path": ".",
                     "source_tree_sha256": ab.digest("accp-source-tree-v1", source),
                     "artifact_tree_sha256": ab.digest("accp-artifact-tree-v1", artifact),
                     "invocation": "explicit", "projection": "accp-invocation-v1"}
        record = {"schema_version": 2, "candidate": candidate,
                  "candidate_sha256": ab.digest("accp-candidate-v1", candidate),
                  "source_inventory": source, "artifact_inventory": artifact,
                  "status": "approved", "reviewer": "fixture", "reviewed_at": "2026-09-16T00:00:00Z",
                  "notes": "", "executable_surface": ["SKILL.md"]}
        self.assertEqual(ab.decode_evidence(ab.encode_evidence(record)), record)
        for field in ("candidate_sha256", "source_inventory", "artifact_inventory"):
            broken = dict(record)
            if field == "candidate_sha256": broken[field] = "f" * 64
            else:
                broken[field] = [dict(item) for item in record[field]]
                if field == "source_inventory":
                    broken[field].append({"path": "x", "type": "directory"})
                else:
                    broken[field][0]["size"] += 1
            with self.assertRaises(ab.BindingError):
                ab.validate_evidence(broken)

    def test_candidate_and_lock_representation(self):
        candidate = {
            "binding_version": 1, "source_id": "demo", "catalog_sha256": "a" * 64,
            "origin": {"kind": "https", "url": "https://github.com/a/b.git"},
            "commit": "1" * 40, "source_tree_oid": "2" * 40, "deploy_path": ".",
            "source_tree_sha256": "3" * 64, "artifact_tree_sha256": "4" * 64,
            "invocation": "explicit", "projection": "accp-invocation-v1",
        }
        self.assertEqual(ab.validate_candidate(candidate), candidate)
        for field in ("catalog_sha256", "commit", "deploy_path", "projection"):
            broken = dict(candidate); broken[field] = "a/../b" if field == "deploy_path" else "bad"
            with self.assertRaises((ValueError, TypeError, ab.BindingError)):
                ab.validate_candidate(broken)
        lock = {"repo": "https://github.com/a/b.git", "commit": candidate["commit"], "deploy_path": ".",
                "evidence": "audit/evidence/demo.json", "evidence_sha256": "a" * 64,
                "approval": {"partial_or_conditional": False, "high_risk": False}}
        self.assertEqual(ab.validate_lock_record(lock), lock)
        with self.assertRaises((ValueError, TypeError, ab.BindingError)):
            ab.validate_lock_record(lock, operational=True)

    def test_evidence_and_vault_require_schema_and_newline_encoding(self):
        with self.assertRaises((ValueError, TypeError, ab.BindingError)):
            ab.decode_evidence(b"{}\n")
        with self.assertRaises((ValueError, TypeError, ab.BindingError)):
            ab.validate_vault_manifest({"schema_version": 1})


class DeployPathModeScopeTests(unittest.TestCase):
    """A symlink or gitlink outside the selected deploy path must not block export.

    Before this contract existed, `entries()` refused every mode other than
    tree/regular/executable while simply *reading* a tree, and resolving a deploy
    path reads the root tree before it descends. A repository with a symlinked
    root-level file was therefore unusable even when the selected subtree was clean
    -- `mattpocock/skills` (root `AGENTS.md` is a symlink) is a real example.

    The security property is unchanged and is asserted here in both directions:
    special-mode entries are ignored as non-selected siblings OUTSIDE the deploy
    path, and are still refused INSIDE it.
    """

    def setUp(self):
        local = Path(__file__).resolve().parents[1] / '.local' / 'audit-temp'
        local.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=local)
        self.root = Path(self.tmp.name)
        self.git = shutil.which('git')
        if self.git is None:
            self.skipTest('Git is required for raw-object acceptance')
        self.repo = self.root / 'repo.git'
        subprocess.run([self.git, 'init', '--bare', str(self.repo)],
                       check=True, capture_output=True)
        self.origin = 'https://example.invalid/scope'
        self.git_run(['config', 'remote.origin.url', self.origin])

    def tearDown(self):
        self.tmp.cleanup()

    def git_run(self, args, data=None):
        return subprocess.run([self.git, '-C', str(self.repo), *args],
                              input=data, capture_output=True, check=True).stdout

    def blob(self, content):
        return self.git_run(['hash-object', '-w', '--stdin'], content).decode().strip()

    def mktree(self, spec):
        """spec: list of (mode, type, oid, name)."""
        body = ''.join(f'{m} {t} {o}\t{n}\n' for m, t, o, n in spec).encode()
        return self.git_run(['mktree'], body).decode().strip()

    def commit(self, tree, message=b'fixture\n'):
        return self.git_run(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                         'commit-tree', tree], message).decode().strip()

    def export(self, commit, deploy_path):
        return ab.export_locked_tree(self.repo, commit, deploy_path,
                                     ab.canonical_origin(self.origin))

    def skill_blob(self):
        return self.blob(b'hello\n')

    def test_1_root_symlink_sibling_with_clean_deploy_subtree_exports(self):
        """OUTSIDE deploy.path: a canonical symlink sibling is ignored content."""
        skill = self.skill_blob()
        inner = self.mktree([('100644', 'blob', skill, 'SKILL.md')])
        root = self.mktree([('40000', 'tree', inner, 'skill'),
                            ('120000', 'blob', self.blob(b'target.md'), 'AGENTS.md')])
        result = self.export(self.commit(root), 'skill')
        self.assertEqual(result.payload, {'SKILL.md': b'hello\n'})
        self.assertEqual([r['path'] for r in result.inventory], ['SKILL.md'])
        self.assertNotIn('AGENTS.md', result.payload)

    def test_2_root_gitlink_sibling_with_clean_deploy_subtree_exports(self):
        """OUTSIDE deploy.path: a canonical gitlink sibling is ignored content."""
        skill = self.skill_blob()
        inner = self.mktree([('100644', 'blob', skill, 'SKILL.md')])
        submodule_commit = self.commit(self.mktree([('100644', 'blob', skill, 'SKILL.md')]),
                                       b'submodule\n')
        root = self.mktree([('40000', 'tree', inner, 'skill'),
                            ('160000', 'commit', submodule_commit, 'vendor')])
        result = self.export(self.commit(root), 'skill')
        self.assertEqual(result.payload, {'SKILL.md': b'hello\n'})
        self.assertEqual([r['path'] for r in result.inventory], ['SKILL.md'])

    def test_3_symlink_inside_selected_subtree_is_refused(self):
        """INSIDE the deploy subtree a symlink is still a hard failure."""
        skill = self.skill_blob()
        inner = self.mktree([('100644', 'blob', skill, 'SKILL.md'),
                             ('120000', 'blob', self.blob(b'elsewhere'), 'link.md')])
        root = self.mktree([('40000', 'tree', inner, 'skill')])
        with self.assertRaisesRegex(ab.BindingError, 'mode/link/gitlink'):
            self.export(self.commit(root), 'skill')

    def test_4_gitlink_inside_selected_subtree_is_refused(self):
        """INSIDE the deploy subtree a gitlink is still a hard failure."""
        skill = self.skill_blob()
        submodule_commit = self.commit(self.mktree([('100644', 'blob', skill, 'SKILL.md')]),
                                       b'submodule\n')
        inner = self.mktree([('100644', 'blob', skill, 'SKILL.md'),
                             ('160000', 'commit', submodule_commit, 'vendor')])
        root = self.mktree([('40000', 'tree', inner, 'skill')])
        with self.assertRaisesRegex(ab.BindingError, 'mode/link/gitlink'):
            self.export(self.commit(root), 'skill')

    def test_5_special_mode_deploy_component_is_refused(self):
        """A selected deploy.path component must be a tree, never a link."""
        skill = self.skill_blob()
        inner = self.mktree([('100644', 'blob', skill, 'SKILL.md')])
        submodule_commit = self.commit(inner, b'submodule\n')
        for label, spec in (('symlink', ('120000', 'blob', self.blob(b'skill'))),
                            ('gitlink', ('160000', 'commit', submodule_commit)),
                            ('file', ('100644', 'blob', skill))):
            with self.subTest(component=label):
                root = self.mktree([('40000', 'tree', inner, 'other'),
                                    (spec[0], spec[1], spec[2], 'skill')])
                with self.assertRaisesRegex(ab.BindingError, 'deploy subtree missing/not directory'):
                    self.export(self.commit(root), 'skill')

    def test_6_special_mode_siblings_still_take_part_in_validation(self):
        """Special-mode entries must not escape the name and ordering checks."""
        skill = self.skill_blob()
        inner = self.mktree([('100644', 'blob', skill, 'SKILL.md')])
        # (a) NFKC/casefold ambiguity: the colliding entry is a symlink, so it must
        #     still be seen by the alias check rather than skipped as an odd mode.
        ambiguous = self.mktree([('40000', 'tree', inner, 'skill'),
                                 ('100644', 'blob', skill, 'Foo'),
                                 ('120000', 'blob', self.blob(b'x'), 'foo')])
        with self.assertRaisesRegex(ab.BindingError, 'ambiguous Git tree name'):
            self.export(self.commit(ambiguous), 'skill')
        # (b) noncanonical ordering: hand-build a tree whose entries are out of
        #     order, with a symlink among them. Git orders trees as name + '/' and
        #     every other mode as name + '\0', so 'alpha\0' must precede 'zeta/';
        #     listing the tree first is therefore noncanonical. (An earlier version
        #     of this fixture used 'skill\0' vs 'skill-a/', which is already in
        #     order, because '\0' sorts before '-'.)
        raw = (b'40000 zeta\0' + bytes.fromhex(inner)
               + b'120000 alpha\0' + bytes.fromhex(self.blob(b'x')))
        noncanonical = self.git_run(['hash-object', '-t', 'tree', '-w', '--stdin', '--literally'],
                                    raw).decode().strip()
        with self.assertRaisesRegex(ab.BindingError, 'noncanonical Git tree ordering'):
            self.export(self.commit(noncanonical), '.')


if __name__ == "__main__":
    unittest.main()
