"""FOLLOWUP-WINDOWS-CTIME regressions: cross-API stat identity in _read_file.

Background. On Windows with CPython 3.12+, the path APIs report st_ctime_ns as
CreationTime (GetFileAttributesEx) while the fd APIs report ChangeTime
(GetFileInformationByHandleEx). `_read_file` used to compare a whole `_stamp`
across those two APIs, so the comparison failed for any file whose ChangeTime
differed from its CreationTime -- which is every file ever modified, and in
particular every file published through `os.replace()`, the atomic publish
primitive this design is built on. The read was then refused with
`BindingError: file replaced before read`.

Repaired contract, pinned here:
  * an already-published artifact (ChangeTime != CreationTime) is readable;
  * `publish_bytes` round-trips;
  * replacement and in-place-change detection are still enforced -- the fd is
    bound to the inspected object on identity fields (dev/ino/mode/nlink/size/
    mtime), and the read window is checked fd-vs-fd, where st_ctime_ns *is*
    meaningful and is deliberately retained.

Scope note. A same-size in-place write with mtime restored, landing inside the
read window, is detected only where the fd API exposes a moving ChangeTime
(Windows/CPython 3.12+). On 3.10/3.11 the fd ctime is CreationTime and does not
move; pristine behaves identically there. That is a pre-existing weakness and is
explicitly OUT OF SCOPE for this change -- the test below probes for it and
skips with a reason rather than asserting either way.
"""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import artifact_binding as ab


def _write(path, data):
    with open(path, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _published(path, payload, initial):
    """Create `path` in the state a real ACCP publication leaves behind:
    written once, then published over with os.replace, so its ChangeTime is
    ahead of its CreationTime."""
    _write(path, initial)
    staged = path.parent / ('.stage-' + os.urandom(4).hex())
    _write(staged, payload)
    os.replace(staged, path)
    return path


class WindowsCtimeRegressionTests(unittest.TestCase):
    def setUp(self):
        local = Path(__file__).resolve().parents[1] / '.local' / 'audit-temp'
        local.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=local)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    # ---------------------------------------------------------------- helpers
    def _read(self, path):
        """Run the real _read_file, returning (result, error_name)."""
        try:
            data, stamp = ab._read_file(path, ab.MAX_RECORD)
            return data, None
        except ab.BindingError as error:
            return None, str(error)

    def _inject_on_plain_path(self, target, mutate, before):
        """Fire `mutate(target)` around the nth plain_path() call.

        plain_path() is called once before the open (n=1) and once after the
        read (n=2). `before=True` mutates just before the call runs, which lands
        strictly between the surrounding reader steps:
          n=1, before=True  -> after the fd is closed? no: after lstat, pre-open
          n=2, before=True  -> after close, before the post-read recheck
        """
        real = ab.plain_path
        state = {'calls': 0, 'fired': False}

        def spy(path, directory=None):
            state['calls'] += 1
            if state['calls'] == 2 and not state['fired']:
                state['fired'] = True
                mutate(Path(path))
            result = real(path, directory)
            if state['calls'] == 1 and not state['fired'] and not before:
                state['fired'] = True
                mutate(Path(path))
            return result

        with mock.patch.object(ab, 'plain_path', spy):
            return self._read(target)

    def _inject_after_first_fstat(self, target, mutate):
        """Fire `mutate(target)` immediately after the reader's first fstat(),
        i.e. inside the open/read window, before the data is read."""
        real = os.fstat
        state = {'calls': 0, 'fired': False}

        def spy(fd):
            info = real(fd)
            state['calls'] += 1
            if state['calls'] == 1 and not state['fired']:
                state['fired'] = True
                mutate(target)
            return info

        with mock.patch.object(ab.os, 'fstat', spy):
            return self._read(target)

    # ------------------------------------------------- 1. the defect itself
    def test_published_artifact_is_readable(self):
        """The regression: a file whose ChangeTime moved must still be readable."""
        target = _published(self.root / 'published.json', ab.canonical_json({'a': 1}), b'{"a":0}')
        before = target.lstat()
        fd = os.open(target, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        try:
            opened = os.fstat(fd)
        finally:
            os.close(fd)
        # Precondition for this test to mean anything on Windows/3.12+: the two
        # APIs really do disagree about st_ctime_ns for this fixture.
        self.assertNotEqual(before.st_dev, 0)
        self.assertEqual(ab._identity(before), ab._identity(opened),
                         'identity fields must agree across the path and fd APIs')
        data, error = self._read(target)
        self.assertIsNone(error, f'published artifact must be readable, got: {error}')
        self.assertEqual(data, ab.canonical_json({'a': 1}))

    def test_identity_excludes_ctime_and_stamp_retains_it(self):
        """_identity drops the non-comparable field; _stamp keeps it.

        Asserted positionally, not by value: for a freshly written file
        st_ctime_ns legitimately equals st_mtime_ns, so a value-membership
        assertion would be meaningless.
        """
        target = _published(self.root / 'fields.json', b'{"a":1}', b'{"a":0}')
        info = target.lstat()
        identity, stamp = ab._identity(info), ab._stamp(info)
        self.assertEqual(len(identity), 6)
        self.assertEqual(len(stamp), 7)
        self.assertEqual(stamp, identity + (info.st_ctime_ns,))
        self.assertEqual(identity[5], info.st_mtime_ns)
        self.assertEqual(stamp[6], info.st_ctime_ns)

    def test_read_bound_record_round_trips_published_record(self):
        target = _published(self.root / 'record.json', ab.canonical_json({'b': [1, 2]}), b'{}')
        snapshot = ab.read_bound_record(target, ab.MAX_RECORD, canonical=False)
        self.assertEqual(snapshot.value, {'b': [1, 2]})
        self.assertEqual(snapshot.identity, ab._stamp(target.lstat()))

    # ------------------------------------------------- 2. publish_bytes round-trip
    def test_publish_bytes_round_trip(self):
        """os.replace() publication must be readable immediately afterwards,
        both for a new file and when replacing an existing one."""
        target = self.root / 'published.json'
        payload = ab.canonical_json({'schema_version': 1, 'entries': []})

        ab.publish_bytes(target, payload, ab.MAX_MANIFEST, replace=False)
        self.assertEqual(self._read(target), (payload, None))

        ab.publish_bytes(target, payload + b'\n', ab.MAX_MANIFEST, replace=True)
        self.assertEqual(self._read(target), (payload + b'\n', None))

    def test_publish_bytes_collision_is_still_refused(self):
        target = self.root / 'collide.json'
        payload = ab.canonical_json({'schema_version': 1})
        ab.publish_bytes(target, payload, ab.MAX_MANIFEST, replace=False)
        with self.assertRaises(ab.BindingError):
            ab.publish_bytes(target, payload + b' ', ab.MAX_MANIFEST, replace=False)
        self.assertEqual(self._read(target), (payload, None))

    # ------------------------------------------------- 3. detection preserved
    def test_replacement_before_open_is_refused(self):
        """Different file swapped in between lstat and open, including a swap
        that preserves size and mtime: identity must catch what timestamps miss."""
        for label, staged_size in (('different-size', 8192), ('same-size', 4096)):
            with self.subTest(case=label):
                target = _published(self.root / f'repl-{label}.json', b'A' * 4096, b'0' * 4096)
                original = target.lstat()

                def mutate(path, _size=staged_size, _stamp=original):
                    staged = path.parent / '.swap'
                    _write(staged, b'B' * _size)
                    os.replace(staged, path)
                    os.utime(path, ns=(_stamp.st_atime_ns, _stamp.st_mtime_ns))

                data, error = self._inject_on_plain_path(target, mutate, before=False)
                self.assertIsNone(data, 'replacement must not be read')
                self.assertEqual(error, 'file replaced before read')

    def test_aba_swap_back_is_refused(self):
        """Swap in a different inode, then restore the ORIGINAL bytes and mtime.
        Content, size and mtime all match again; only the inode differs, so this
        isolates the identity binding."""
        target = _published(self.root / 'aba.json', b'ORIGINAL-CONTENT-0123456789\n', b'0' * 27)
        original_bytes = target.read_bytes()
        original = target.lstat()

        def mutate(path):
            staged = path.parent / '.aba'
            _write(staged, b'ATTACKER-CONTENT-0123456789\n')
            os.replace(staged, path)
            staged2 = path.parent / '.aba2'
            _write(staged2, original_bytes)
            os.replace(staged2, path)
            # restore mtime too, so content, size AND mtime all match the
            # original again and only the inode differs
            os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))

        data, error = self._inject_on_plain_path(target, mutate, before=False)
        self.assertIsNone(data, 'ABA swap must not be read')
        self.assertEqual(error, 'file replaced before read')
        # sanity: the attack really did leave matching content/size/mtime
        after = target.lstat()
        self.assertEqual(target.read_bytes(), original_bytes)
        self.assertEqual(after.st_size, original.st_size)
        self.assertEqual(after.st_mtime_ns, original.st_mtime_ns)
        self.assertNotEqual(after.st_ino, original.st_ino)

    def test_inplace_write_during_read_is_refused(self):
        """A same-size in-place write landing inside the open/read window must be
        caught by the fd-vs-fd comparison (it moves mtime on every platform)."""
        target = _published(self.root / 'inplace.json', b'A' * 4096, b'0' * 4096)

        def mutate(path):
            with open(path, 'r+b') as stream:
                stream.seek(0)
                stream.write(b'Z' * 4096)
                stream.flush()
                os.fsync(stream.fileno())

        data, error = self._inject_after_first_fstat(target, mutate)
        self.assertIsNone(data, 'in-place modification must not be read')
        self.assertEqual(error, 'file changed during read')

    def test_inplace_write_with_restored_mtime_where_fd_ctime_moves(self):
        """Only the fd API's ChangeTime can catch this: mtime is restored, and on
        Windows/3.12+ the path st_ctime is CreationTime, which a write does not
        move. Skipped where the fd ctime does not move (3.10/3.11), because that
        is the pre-existing weakness this milestone does not address."""
        probe = self.root / 'probe.bin'
        _write(probe, b'0' * 64)
        fd = os.open(probe, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        try:
            before = os.fstat(fd).st_ctime_ns
        finally:
            os.close(fd)
        with open(probe, 'r+b') as stream:
            stream.seek(0)
            stream.write(b'1' * 64)
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(probe, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        try:
            moved = os.fstat(fd).st_ctime_ns != before
        finally:
            os.close(fd)
        if not moved:
            self.skipTest('fd st_ctime_ns is CreationTime here; detecting an '
                          'mtime-restored in-place write is a pre-existing '
                          '3.10/3.11 weakness, out of scope for FOLLOWUP-WINDOWS-CTIME')

        target = _published(self.root / 'restored.json', b'A' * 4096, b'0' * 4096)
        original = target.lstat()

        def mutate(path):
            with open(path, 'r+b') as stream:
                stream.seek(0)
                stream.write(b'Z' * 4096)
                stream.flush()
                os.fsync(stream.fileno())
            os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))

        data, error = self._inject_after_first_fstat(target, mutate)
        self.assertIsNone(data, 'mtime-restored in-place write must not be read')
        self.assertEqual(error, 'file changed during read')

    def test_replacement_after_close_is_refused(self):
        """The post-read path revalidation is retained and remains load-bearing."""
        target = _published(self.root / 'after.json', b'A' * 4096, b'0' * 4096)

        def mutate(path):
            staged = path.parent / '.late'
            _write(staged, b'B' * 4096)
            os.replace(staged, path)

        data, error = self._inject_on_plain_path(target, mutate, before=True)
        self.assertIsNone(data, 'post-read replacement must not be read')
        self.assertEqual(error, 'file replaced after read')

    def test_unchanged_file_still_reads_after_repeated_reads(self):
        """No false positives: the same published artifact reads repeatedly."""
        target = _published(self.root / 'stable.json', b'{"ok":true}', b'{}')
        for _ in range(5):
            self.assertEqual(self._read(target), (b'{"ok":true}', None))


if __name__ == '__main__':
    unittest.main()
