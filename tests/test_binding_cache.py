import pathlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import test_e2e as fixture

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import artifact_binding as ab


class BindingCache(unittest.TestCase):
    def setUp(self):
        self.fx = fixture.E2E()
        fixture.E2E.setUp(self.fx)

    def tearDown(self):
        fixture.E2E.tearDown(self.fx)

    def call(self, *args, **kwargs):
        return self.fx.call(*args, **kwargs)

    def test_materialize_rejects_mutated_bare_cache_config(self):
        self.fx.approve_lock_without_materialize()
        cache = next((self.fx.base / "runtime" / "sources").iterdir())
        config = cache / "config"
        original = config.read_bytes()
        marker = self.fx.base / "cache-hook-ran"
        config.write_bytes(original + b"\n[uploadpack]\n\tpackObjectsHook = cmd /c echo ran>" + str(marker).encode() + b"\n")
        before = self.fx.snapshot_tree()
        result = self.call("materialize", "fixture-safe", ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.read_bytes(), original + b"\n[uploadpack]\n\tpackObjectsHook = cmd /c echo ran>" + str(marker).encode() + b"\n")
        self.assertFalse(marker.exists())
        self.assertFalse((self.fx.base / "runtime" / "vault" / "skills" / "fixture-safe").exists())
        self.assertEqual(before, self.fx.snapshot_tree())

    def test_malformed_preexisting_digest_cache_is_refused_without_repair(self):
        sources = self.fx.base / "fixture-sources"
        sources.mkdir()
        origin = ab.file_origin(self.fx.up)
        cache = sources / ab.digest("accp-origin-v1", origin)
        cache.mkdir()
        (cache / "config").write_bytes(b"malformed cache")
        before = self.fx.snapshot_tree()
        with mock.patch.object(ab, '_bounded_git') as git_call:
            with self.assertRaises((ab.BindingError, OSError)):
                ab.acquire_cache(sources, origin)
            git_call.assert_not_called()
        self.assertEqual(before, self.fx.snapshot_tree())
        self.assertEqual(b"malformed cache", (cache / "config").read_bytes())

    def test_publish_bytes_collision_replace_and_failed_replace_are_atomic(self):
        target = self.fx.base / "publish" / "artifact.bin"
        target.parent.mkdir()
        target.write_bytes(b"original")
        with self.assertRaisesRegex(ab.BindingError, "publication collision"):
            ab.publish_bytes(target, b"new")
        self.assertEqual(b"original", target.read_bytes())
        ab.publish_bytes(target, b"replacement", replace=True)
        self.assertEqual(b"replacement", target.read_bytes())
        target.write_bytes(b"preserve")
        before = set(p.name for p in target.parent.iterdir())
        with mock.patch.object(ab.os, "replace", side_effect=OSError("injected replace failure")):
            with self.assertRaises(OSError):
                ab.publish_bytes(target, b"failed", replace=True)
        self.assertEqual(b"preserve", target.read_bytes())
        temps = [p for p in target.parent.iterdir() if p.name.startswith(".accp-write-")]
        self.assertEqual(1, len(temps))
        self.assertTrue(temps[0].name not in before)
        self.assertEqual(b"failed", temps[0].read_bytes())

    def test_git_acquisition_command_isolates_configuration_and_transport(self):
        injected={'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'remote.origin.url',
                  'GIT_CONFIG_VALUE_0':'ext::untrusted','GIT_CONFIG_GLOBAL':'untrusted',
                  'GIT_ASKPASS':'untrusted','HOME':'untrusted','HTTPS_PROXY':'untrusted'}
        with mock.patch.dict(os.environ,injected), \
                mock.patch.object(ab.subprocess,'Popen',wraps=ab.subprocess.Popen) as process:
            self.assertTrue(ab._bounded_git(self.fx.base,['--version'],256,transport='https').startswith(b'git version'))
        args=process.call_args.args[0]; env=process.call_args.kwargs['env']
        for setting in ('protocol.allow=never','protocol.https.allow=always','credential.helper=',
                        'http.followRedirects=false','http.sslVerify=true','core.fsmonitor=false',
                        'gc.auto=0','maintenance.auto=false'):
            self.assertIn(setting,args)
        for name in ('GIT_CONFIG_COUNT','GIT_CONFIG_KEY_0','GIT_CONFIG_VALUE_0','GIT_ASKPASS','HOME','HTTPS_PROXY'):
            self.assertNotIn(name,env)
        self.assertEqual(env['GIT_CONFIG_GLOBAL'],os.devnull)
        self.assertEqual(env['GIT_CONFIG_SYSTEM'],os.devnull)
        with mock.patch.object(ab.subprocess,'Popen') as process:
            with self.assertRaisesRegex(ab.BindingError,'unsupported transport'):
                ab._bounded_git(self.fx.base,['--version'],256,transport='ssh')
            process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
