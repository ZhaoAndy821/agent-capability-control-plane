"""Category-C regressions: filesystem stamp observation range and digest versioning.

Two coupled properties are pinned here.

1. A filesystem stamp cannot be assumed to fit signed 64-bit. On Windows st_dev and
   st_ino are unsigned 64-bit identities, and st_mtime_ns/st_ctime_ns are epoch
   nanosecond values that a file may legally carry beyond 2**64-1. The observation
   form therefore encodes dev/ino/mtime_ns/ctime_ns as canonical decimal strings
   (`artifact_binding.observed_stamp`) while mode/nlink/size stay integers. Without
   this, a runner volume whose identity is >= 2**63 made every activation proof and
   every tree digest fail with `JSON integer range`.

2. The unmanaged digest is explicitly versioned. A journal written before the
   version-2 encoding carries no marker and is validated with the legacy integer
   encoding; a journal written now declares version 2 and is validated only that way.
   There is deliberately no fallback: an unknown version is refused, and a version-2
   mismatch is never retried as version 1.
"""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import activation_context as observation
import artifact_binding as binding
import active_transaction as txn

MAX_U64 = 2**64 - 1
SIGNED_MAX = 2**63 - 1
FAR_FUTURE_NS = 32503680000000000000          # year 3000; > 2**64-1

BASE_STAMP = (647463021274208632, 74590868828351668, 33206, 1, 16,
              1790228341134964700, 1790228341134964700)


def stamp(dev=None, ino=None, mode=33206, nlink=1, size=16,
          mtime=1790228341134964700, ctime=1790228341134964700):
    return (BASE_STAMP[0] if dev is None else dev,
            BASE_STAMP[1] if ino is None else ino,
            mode, nlink, size, mtime, ctime)


def canonical(value):
    return binding.canonical_json({'identity': value})


class ObservedStampRangeTests(unittest.TestCase):
    """The four ranged positions must survive; the other three stay integers."""

    def test_01_dev_at_or_above_signed_max(self):                     # required 1
        for dev in (2**63, 2**63 + 1, SIGNED_MAX + 5):
            with self.subTest(dev=dev):
                observed = binding.observed_stamp(stamp(dev=dev))
                self.assertEqual(observed[0], str(dev))
                canonical(observed)                                       # must not raise

    def test_02_ino_at_or_above_signed_max(self):                     # required 2
        for ino in (2**63, 2**63 + 1):
            with self.subTest(ino=ino):
                observed = binding.observed_stamp(stamp(ino=ino))
                self.assertEqual(observed[1], str(ino))
                canonical(observed)

    def test_03_max_supported_identity_value(self):                   # required 3
        observed = binding.observed_stamp(stamp(dev=MAX_U64, ino=MAX_U64))
        self.assertEqual(observed[0], str(MAX_U64))
        self.assertEqual(observed[1], str(MAX_U64))
        canonical(observed)

    def test_04_mtime_beyond_uint64(self):                            # required 4
        observed = binding.observed_stamp(stamp(mtime=FAR_FUTURE_NS))
        self.assertEqual(observed[5], str(FAR_FUTURE_NS))
        self.assertGreater(FAR_FUTURE_NS, MAX_U64)
        canonical(observed)

    def test_05_ctime_large_positive(self):                           # required 5
        observed = binding.observed_stamp(stamp(ctime=FAR_FUTURE_NS))
        self.assertEqual(observed[6], str(FAR_FUTURE_NS))
        canonical(observed)

    def test_06_negative_timestamp(self):                             # required 6
        observed = binding.observed_stamp(stamp(mtime=-1, ctime=-1234567))
        self.assertEqual(observed[5], '-1')
        self.assertEqual(observed[6], '-1234567')
        canonical(observed)

    def test_07_unranged_fields_stay_integers(self):                  # scope guard
        observed = binding.observed_stamp(stamp(mode=33188, nlink=1, size=4096))
        self.assertIs(type(observed[2]), int)
        self.assertIs(type(observed[3]), int)
        self.assertIs(type(observed[4]), int)
        self.assertEqual(observed[2:5], [33188, 1, 4096])

    def test_08_distinct_large_values_stay_distinct(self):            # required 7
        values = [
            stamp(dev=MAX_U64, ino=MAX_U64),
            stamp(dev=MAX_U64, ino=MAX_U64 - 1),
            stamp(dev=MAX_U64 - 1, ino=MAX_U64),
            stamp(dev=2**63, ino=2**63),
            stamp(dev=2**63, ino=2**63 + 1),
            stamp(mtime=FAR_FUTURE_NS),
            stamp(mtime=FAR_FUTURE_NS, ctime=FAR_FUTURE_NS),
            stamp(mtime=-1),
            stamp(ctime=-1),
        ]
        encoded = [canonical(binding.observed_stamp(s)) for s in values]
        self.assertEqual(len(set(encoded)), len(values), 'distinct stamps collided')

    def test_09_legacy_inverse_round_trips(self):                     # V1 recomputation
        for original in (stamp(), stamp(dev=2**63, ino=2**63 + 7),
                         stamp(mtime=123, ctime=456), stamp(mtime=-9)):
            with self.subTest(stamp=original):
                self.assertEqual(
                    binding.legacy_observed_stamp(binding.observed_stamp(original)),
                    list(original))

    def test_10_non_stamp_inputs_refused(self):
        for bad in ([1, 2, 3], (1, 2, 3, 4, 5, 6), 'stamp', None):
            with self.subTest(bad=bad):
                with self.assertRaises(binding.BindingError):
                    binding.observed_stamp(bad)


class CanonicalTextRejectionTests(unittest.TestCase):                 # required 8

    def test_11_rejected_spellings(self):
        # identity_text/timestamp_text take ints, so the *string* side is exercised
        # through the legacy inverse, which re-validates whatever it parses.
        for bad in ('+1', '01', '1_0', '0x1F', '', '-0', ' 1', '1 ', '\u0661\u0662\u0663'):
            with self.subTest(identity=bad):
                with self.assertRaises((binding.BindingError, ValueError)):
                    binding.legacy_observed_stamp([bad, '2', 33206, 1, 16, '3', '4'])
            with self.subTest(timestamp=bad):
                with self.assertRaises((binding.BindingError, ValueError)):
                    binding.legacy_observed_stamp(['1', '2', 33206, 1, 16, bad, '4'])

    def test_12_rejected_integer_inputs(self):
        for bad in (0, -1):
            with self.subTest(value=bad):
                with self.assertRaises(binding.BindingError):
                    binding.identity_text(bad)
        for bad in ('1', 1.5, None):
            with self.subTest(value=bad):
                with self.assertRaises(binding.BindingError):
                    binding.timestamp_text(bad)

    def test_13_accepted_canonical_forms(self):
        self.assertEqual(binding.identity_text(1), '1')
        self.assertEqual(binding.identity_text(MAX_U64), '18446744073709551615')
        self.assertEqual(binding.timestamp_text(0), '0')
        self.assertEqual(binding.timestamp_text(-1), '-1')
        self.assertEqual(binding.timestamp_text(FAR_FUTURE_NS), str(FAR_FUTURE_NS))

    def test_14_deterministic_bytes(self):
        encoded = {canonical(binding.observed_stamp(stamp(dev=MAX_U64, ino=MAX_U64,
                                                         mtime=FAR_FUTURE_NS)))
                   for _ in range(200)}
        self.assertEqual(len(encoded), 1, 'observation encoding is not deterministic')


class DigestVersionTests(unittest.TestCase):
    """V1/V2 selection, refusal of the unknown, and no downgrade fallback."""

    ROWS_FILE = [{'path': 'SKILL.md', 'type': 'file',
                  'identity': [str(BASE_STAMP[0]), str(BASE_STAMP[1]), 33206, 1, 16,
                               str(BASE_STAMP[5]), str(BASE_STAMP[6])],
                  'sha256': 'ab' * 32, 'size': 16}]

    def test_15_v1_and_v2_are_different_digests(self):
        v1 = observation.unmanaged_observation(self.ROWS_FILE, set(), observation.UNMANAGED_DIGEST_V1)
        v2 = observation.unmanaged_observation(self.ROWS_FILE, set(), observation.UNMANAGED_DIGEST_V2)
        self.assertNotEqual(v1, v2, 'encoding change must be visible in the digest')
        self.assertEqual(len(v2), 64)

    def test_16_v1_reproduces_the_legacy_integer_encoding(self):
        """The V1 path must digest exactly what the old code digested."""
        legacy_rows = [dict(self.ROWS_FILE[0], identity=[
            int(self.ROWS_FILE[0]['identity'][0]), int(self.ROWS_FILE[0]['identity'][1]),
            33206, 1, 16, int(self.ROWS_FILE[0]['identity'][5]),
            int(self.ROWS_FILE[0]['identity'][6])])]
        expected = hashlib.sha256(
            b'accp-activation-unmanaged-v1\x00' + binding.canonical_json(legacy_rows)).hexdigest()
        self.assertEqual(
            observation.unmanaged_observation(self.ROWS_FILE, set(), observation.UNMANAGED_DIGEST_V1),
            expected)

    def test_17_unknown_version_refused(self):                        # required 13
        for bad in (0, 3, -1, '2', 2.0, True, None):
            with self.subTest(version=bad):
                with self.assertRaises(binding.BindingError):
                    observation.unmanaged_observation(self.ROWS_FILE, set(), bad)

    def test_18_absent_marker_means_version_one(self):
        self.assertEqual(txn.unmanaged_digest_version({}), observation.UNMANAGED_DIGEST_V1)
        self.assertEqual(txn.unmanaged_digest_version({'unmanaged_digest_version': 1}), 1)
        self.assertEqual(txn.unmanaged_digest_version({'unmanaged_digest_version': 2}), 2)

    def test_19_boolean_marker_never_equals_a_version(self):
        """True == 1 in Python; the accessor must reject it before any comparison."""
        with self.assertRaises(txn.JournalError):
            txn.unmanaged_digest_version({'unmanaged_digest_version': True})

    def test_19b_unknown_unmanaged_version_refused_by_the_accessor(self):
        """Membership is enforced at the accessor, not only at the use site.

        Without this the accessor would hand back an unknown version for a caller
        to interpret, which is the asymmetry that made the child-observation
        accessor stricter than its unmanaged counterpart.
        """
        for bad in (0, 3, -1, 99):
            with self.subTest(version=bad):
                with self.assertRaises(txn.JournalError):
                    txn.unmanaged_digest_version({'unmanaged_digest_version': bad})

    def test_20_activation_field_shapes(self):
        v1 = set(txn.ACTIVATION_FIELDS_V1)
        v2 = set(txn.ACTIVATION_FIELDS_V2)
        self.assertEqual(v2 - v1, {'unmanaged_digest_version'})
        self.assertNotIn('unmanaged_digest_version', v1)

    def test_21_observation_shape_is_positional_and_explicit(self):
        observed = binding.observed_stamp(stamp(dev=MAX_U64, ino=MAX_U64,
                                                mtime=FAR_FUTURE_NS, ctime=FAR_FUTURE_NS))
        self.assertEqual(len(observed), 7)
        self.assertEqual([type(v) for v in observed],
                         [str, str, int, int, int, str, str])
        self.assertEqual(json.loads(canonical(observed))['identity'], observed)


class RunnerShapedProducerTests(unittest.TestCase):
    """Drive the real producers with an out-of-range identity.

    The original defect could only be produced by a runner volume whose st_dev/st_ino
    happened to sit at or above 2**63 -- never by this project's development machine.
    These tests synthesise that identity and push it through the actual producer
    functions, so the regression is reproducible anywhere.
    """

    def setUp(self):
        self.root = Path(__file__).resolve().parents[1] / '.local' / 'audit-temp'
        self.root.mkdir(parents=True, exist_ok=True)

    def test_22_file_observation_digests_oversized_identity(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            path = Path(tmp) / 'SKILL.md'
            path.write_bytes(b'runner-shaped payload')
            real = binding._read_file
            runner_stamp = stamp(dev=MAX_U64, ino=MAX_U64, mtime=FAR_FUTURE_NS, ctime=FAR_FUTURE_NS)

            def fake(path_arg, limit, _stamp=runner_stamp):
                data, _ = real(path_arg, limit)
                return data, _stamp

            with mock.patch.object(binding, '_read_file', fake):
                row = observation.file_observation(path)
                self.assertEqual(row['identity'],
                                 [str(MAX_U64), str(MAX_U64), 33206, 1, 16,
                                  str(FAR_FUTURE_NS), str(FAR_FUTURE_NS)])
                # the real digest call that failed on the runner
                digest = observation.transaction_digest(
                    'accp-activation-child-v1', [dict(row, path='.', type='file')])
                self.assertEqual(len(digest), 64)
                # V2 represents it; V1 deliberately cannot (see test_23)
                self.assertEqual(len(observation.unmanaged_observation(
                    [dict(row, path='a/SKILL.md', type='file')], set(),
                    observation.UNMANAGED_DIGEST_V2)), 64)

    def test_23_legacy_encoding_of_an_oversized_identity_fails_closed(self):
        """V1 cannot represent an out-of-range identity; it must refuse, not mangle."""
        row = {'path': 'a/SKILL.md', 'type': 'file',
               'identity': [str(MAX_U64), str(MAX_U64), 33206, 1, 16,
                            str(FAR_FUTURE_NS), str(FAR_FUTURE_NS)],
               'sha256': 'ab' * 32, 'size': 16}
        with self.assertRaises(binding.BindingError):
            observation.unmanaged_observation([row], set(), observation.UNMANAGED_DIGEST_V1)

    def test_24_v2_accepts_what_v1_cannot(self):
        """The whole point: the same observation is representable under V2."""
        row = {'path': 'a/SKILL.md', 'type': 'file',
               'identity': [str(MAX_U64), str(MAX_U64), 33206, 1, 16,
                            str(FAR_FUTURE_NS), str(FAR_FUTURE_NS)],
               'sha256': 'ab' * 32, 'size': 16}
        digest = observation.unmanaged_observation([row], set(),
                                                   observation.UNMANAGED_DIGEST_V2)
        self.assertEqual(len(digest), 64)

    def test_25_directory_rows_are_unchanged_by_the_version_switch(self):
        """Only file rows differ between V1 and V2; directory identities were strings."""
        rows = [{'path': 'a', 'type': 'directory',
                 'identity': {'device': str(BASE_STAMP[0]), 'inode': str(BASE_STAMP[1])}}]
        self.assertEqual(
            observation.unmanaged_observation(rows, set(), observation.UNMANAGED_DIGEST_V1),
            observation.unmanaged_observation(rows, set(), observation.UNMANAGED_DIGEST_V2))


if __name__ == '__main__':
    unittest.main()
