"""F03 journal, lifecycle lock, deactivate recovery and bounded terminal cleanup.

The checkout and external store are trusted; concurrent hostile filesystem
replacement is outside this path-based boundary. Parsing proves record structure
and bindings, NOT that an on-disk lifecycle transition completed.
"""
import base64
import binascii
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
import unicodedata

import activation_context as activation_observation
import artifact_binding as binding

MAX_JOURNAL = 8 * 1024 * 1024
MAX_METADATA = 1024 * 1024
MAX_IDS = 4096
MAX_CLEANUP_ENTRIES = 65536
DIGEST = re.compile(r'[0-9a-f]{64}')
ID = re.compile(r'[a-z0-9][a-z0-9._-]{0,95}')
DEVICE = re.compile(r'(?i)(con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])')


class JournalError(ValueError):
    """Refusal; callers must not substitute an empty/default journal."""


class LifecycleUnavailable(JournalError):
    """OS ownership could not be obtained; this does not identify a live writer."""


class PublicationError(JournalError):
    """replacement_completed records a returned replace call, not durable commit.

    False is not permission to assume old bytes survived an ambiguous OS failure;
    callers must inspect retained authority under the lock before deciding anything.
    """
    def __init__(self, target, replacement_completed, cause):
        self.replacement_completed = replacement_completed
        super().__init__(f'publication failed: {target}; replacement_completed='
                         f'{replacement_completed}; inspect retained state: {cause}')


@contextmanager
def binding_checks():
    """Translate the strict binding validator's refusal, never suppress it."""
    try:
        yield
    except binding.BindingError as exc:
        raise JournalError(str(exc)) from exc


def regular_identity(path):
    plain_path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_dev > 0 and info.st_ino > 0, 'unsafe regular file identity')
    return info.st_dev, info.st_ino


def sync_directory(path):
    # Windows has no portable stdlib directory fsync. File fsync still applies;
    # do not claim directory-entry durability across machine power loss there.
    if os.name == 'nt':
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def os_lock(fd, acquire):
    if os.name == 'nt':
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK if acquire else msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, (fcntl.LOCK_EX | fcntl.LOCK_NB) if acquire else fcntl.LOCK_UN)


class Phase(str, Enum):
    PREPARING = 'PREPARING'
    PREPARED = 'PREPARED'
    APPLYING = 'APPLYING'
    COMMITTED = 'COMMITTED'
    ROLLING_BACK = 'ROLLING_BACK'
    ROLLED_BACK = 'ROLLED_BACK'
    CLEANING = 'CLEANING'
    DONE = 'DONE'


class RecordState(str, Enum):
    ABSENT = 'absent'
    PENDING = 'pending'
    INTERRUPTED = 'interrupted'
    CONFLICT = 'conflict'


@dataclass(frozen=True)
class Inspection:
    state: RecordState
    detail: str
    # Deliberately no journal/commit authorization in a status inspection.


def require(condition, message):
    if not condition:
        raise JournalError(message)


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'unexpected record fields')


def plain_path(path):
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode)
                and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'symlink/reparse path refused')
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                'special path refused')


def canonical(raw):
    raw = os.fspath(raw)
    require(type(raw) is str and bool(raw) and not any(ord(c) < 32 for c in raw),
            'invalid path')
    parts = raw.replace('\\', '/').split('/')
    require(not any(p in ('.', '..') for p in parts), 'traversal refused')
    if os.name == 'nt':
        require(bool(re.match(r'^[A-Za-z]:[\\/]', raw)) and ':' not in raw[2:],
                'absolute local drive path required')
        import ctypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        require(kernel.GetDriveTypeW(raw[:3].replace('/', '\\')) in (2, 3),
                'local drive required')
        for p in parts[1:]:
            require(not p or (not p.endswith(('.', ' '))
                    and not re.search(r'[<>"|?*]', p)
                    and not DEVICE.fullmatch(p.split('.')[0])), 'unsafe path component')
    else:
        require(Path(raw).is_absolute() and not raw.startswith('//') and '\\' not in raw,
                'absolute local path required')
    path = Path(raw)
    plain_path(path)
    result = Path(os.path.normcase(str(path.resolve())))
    require(result != Path(result.anchor), 'filesystem root refused')
    return result


def directory_identity(path):
    plain_path(path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_dev > 0 and info.st_ino > 0,
            'usable directory identity required')
    return {'device': str(info.st_dev), 'inode': str(info.st_ino)}


def validate_identity(value):
    exact(value, ('device', 'inode'))
    require(all(type(v) is str and re.fullmatch(r'[1-9][0-9]{0,39}', v)
                for v in value.values()), 'invalid directory identity')


def verify_directory(path, expected):
    validate_identity(expected)
    require(directory_identity(path) == expected, 'directory identity mismatch')


def transaction_id(value):
    require(type(value) is str, 'invalid transaction UUID')
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise JournalError('invalid transaction UUID') from exc
    require(parsed.version == 4 and str(parsed) == value, 'canonical UUID4 required')
    return parsed


def ids(value):
    require(type(value) is list and len(value) <= MAX_IDS, 'invalid ID inventory')
    for item in value:
        require(type(item) is str and ID.fullmatch(item) and not item.endswith('.')
                and not DEVICE.fullmatch(item.split('.')[0]), 'invalid managed ID')
    require(len(set(value)) == len(value), 'duplicate managed ID')


def strict_json(raw, limit=MAX_JOURNAL):
    require(type(raw) is bytes and len(raw) <= limit, 'invalid/oversized JSON bytes')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def invalid_constant(value):
        raise JournalError('non-JSON numeric constant')
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'),
                           object_pairs_hook=unique, parse_constant=invalid_constant)
        # Reject lone surrogate escapes as well as invalid input UTF-8.
        json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise JournalError('malformed or incomplete JSON') from exc
    require(type(value) is dict, 'JSON object required')
    return value


def snapshot(raw):
    if raw is None:
        return {'exists': False}
    require(type(raw) is bytes and len(raw) <= MAX_METADATA, 'invalid snapshot bytes')
    return {'exists': True, 'bytes_base64': base64.b64encode(raw).decode('ascii'),
            'sha256': hashlib.sha256(raw).hexdigest()}


def snapshot_bytes(value):
    require(type(value) is dict and type(value.get('exists')) is bool, 'invalid snapshot')
    if not value['exists']:
        exact(value, ('exists',))
        return None
    exact(value, ('exists', 'bytes_base64', 'sha256'))
    encoded = value['bytes_base64']
    require(type(encoded) is str and len(encoded) <= 4 * ((MAX_METADATA + 2) // 3),
            'oversized snapshot')
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise JournalError('invalid snapshot base64') from exc
    require(len(raw) <= MAX_METADATA and base64.b64encode(raw).decode('ascii') == encoded,
            'noncanonical snapshot base64')
    require(type(value['sha256']) is str and DIGEST.fullmatch(value['sha256'])
            and hashlib.sha256(raw).hexdigest() == value['sha256'], 'snapshot digest mismatch')
    return raw


def observed_tree(path):
    """Complete managed-tree fingerprint; no .git or manifest exclusions."""
    root_id = directory_identity(path)
    digest = hashlib.sha256()
    def visit(item):
        plain_path(item)
        info = item.lstat()
        is_dir = stat.S_ISDIR(info.st_mode)
        if not is_dir:
            regular_identity(item)  # managed hard links cannot become cleanup authority
        header = [item.relative_to(path).as_posix(), 'd' if is_dir else 'f',
                  stat.S_IMODE(info.st_mode), getattr(info, 'st_file_attributes', 0) & 1]
        digest.update(json.dumps(header, ensure_ascii=True, separators=(',', ':')).encode() + b'\n')
        if is_dir:
            for child in sorted(item.iterdir(), key=lambda p: p.name):
                visit(child)
        else:
            file_hash = hashlib.sha256()
            with item.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    file_hash.update(block)
            digest.update(file_hash.digest())
    visit(path)
    verify_directory(path, root_id)
    return {'identity': root_id, 'sha256': digest.hexdigest()}


FIELDS = set('schema_version kind transaction_id operation phase prepared '
             'control_plane_path control_plane_identity project_path project_identity '
             'scope base_path base_identity skills_before skills_created_identity '
             'workspace_identity old_ids new_ids old_children new_children '
             'old_manifest old_state new_manifest new_state'.split())

# Activation sub-record shapes. A version-1 journal predates the explicit unmanaged
# digest version marker; a version-2 journal always carries it. Validation accepts
# exactly one of these two shapes, so a missing or unexpected field is refused
# rather than ignored.
ACTIVATION_FIELDS_V1 = frozenset((
    'attempt_id', 'context_sha256', 'runtime_binding', 'providers',
    'unmanaged_sha256', 'old_metadata_identity', 'skills_mode_before'))
ACTIVATION_FIELDS_V2 = ACTIVATION_FIELDS_V1 | {'unmanaged_digest_version'}


def unmanaged_digest_version(activation):
    """Unmanaged digest version of an activation record; an absent marker is legacy.

    `type(...) is int` is required so that a boolean or string marker can never
    compare equal to a version number. Membership is checked here as well as at
    the use site, so an unknown version fails closed at the accessor instead of
    being handed back for a caller to interpret. This mirrors
    `observation_digest_version`, which has always enforced both.
    """
    version = activation.get('unmanaged_digest_version',
                             activation_observation.UNMANAGED_DIGEST_V1)
    require(type(version) is int
            and version in (activation_observation.UNMANAGED_DIGEST_V1,
                            activation_observation.UNMANAGED_DIGEST_V2),
            'unknown unmanaged digest version')
    return version


def observation_digest_version(record):
    """Child-observation digest version of a journal record; absent marker is legacy.

    This is a separate domain from the unmanaged digest version and is never
    inferred from it. The marker is journal-level because every persisted child
    observation in one transaction is necessarily produced together by a single
    observation pass, so the schema never carries independently-versioned child
    entries. `type(...) is int` is required so a boolean marker cannot compare
    equal to a version number, and membership is checked here so an unknown
    version fails closed rather than selecting an encoding.
    """
    version = record.get('observation_digest_version',
                         activation_observation.OBSERVATION_DIGEST_V1)
    require(type(version) is int
            and version in (activation_observation.OBSERVATION_DIGEST_V1,
                            activation_observation.OBSERVATION_DIGEST_V2),
            'unknown observation digest version')
    return version


class JournalAuthority:
    """Read-only bindings. user_base is explicit caller configuration, not record data."""
    def __init__(self, checkout, project, scope='project', user_base=None):
        require(scope in ('project', 'user') and type(scope) is str, 'invalid scope')
        require((scope == 'user') == (user_base is not None), 'unexpected/missing user base')
        self.checkout = canonical(checkout)
        self.project = canonical(project)
        self.scope = scope
        self.base = canonical(user_base if scope == 'user' else self.project / '.agents')
        self.store = canonical(self.checkout / '.local' / 'active-transactions')
        require(not (self.base == self.store or self.base in self.store.parents
                     or self.store in self.base.parents), 'authority-store overlap')
        require(not (self.base == self.checkout or self.base in self.checkout.parents
                     or self.base == self.project or self.base in self.project.parents),
                'base contains checkout/project')
        self.checkout_identity = directory_identity(self.checkout)
        self.project_identity = directory_identity(self.project)
        self.key = hashlib.sha256(str(self.base).encode('utf-8')).hexdigest()
        self.journal = self.store / (self.key + '.json')
        self.journal_pending = self.store / (self.key + '.json.pending')
        self.locator = self.base / '.accp-transaction.json'
        self.locator_pending = self.base / '.accp-transaction.json.pending'
        self.lock_path = self.base / '.accp-lifecycle.lock'
        self.legacy_lock = self.base / '.accp-activate.lock'
        self._held = None
        self._store_ids = None
        self._forward_attempt = None
        self._forward_record = None
        self._forward_expected = None

    @contextmanager
    def lifecycle_lock(self, create=True):
        """Nonblocking OS ownership; existing base required, lock file never removed."""
        require(self._held is None, 'lifecycle lock is not reentrant')
        binding = self.bindings()
        plain_path(self.legacy_lock)
        require(not os.path.lexists(self.legacy_lock), 'legacy lock requires manual inspection')
        plain_path(self.lock_path)
        expected = regular_identity(self.lock_path) if self.lock_path.exists() else None
        fd = os.open(self.lock_path, os.O_RDWR | (os.O_CREAT if create else 0), 0o600)
        acquired = False
        try:
            info = os.fstat(fd)
            opened = (info.st_dev, info.st_ino)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and opened == regular_identity(self.lock_path)
                    and (expected is None or expected == opened), 'lock identity changed')
            try:
                os_lock(fd, True)
            except OSError as exc:
                raise LifecycleUnavailable('lifecycle lock busy or unavailable') from exc
            acquired = True
            self._held = (fd, opened, binding['base_identity'])
            self._assert_locked()
            # Pin existing authority directories throughout this lock session.
            self._store_ids = {p: directory_identity(p) for p in (self.store.parent, self.store)
                               if p.exists()}
            yield self
        finally:
            self._held = None
            self._store_ids = None
            try:
                if acquired:
                    os_lock(fd, False)
            finally:
                os.close(fd)

    def _assert_locked(self):
        require(self._held is not None, 'publication requires lifecycle lock')
        fd, expected, base_id = self._held
        info = os.fstat(fd)
        require((info.st_dev, info.st_ino) == expected == regular_identity(self.lock_path),
                'lifecycle lock replaced')
        verify_directory(self.base, base_id)
        self.bindings()
        plain_path(self.legacy_lock)
        require(not os.path.lexists(self.legacy_lock), 'legacy lock appeared')
        for path, identity in (self._store_ids or {}).items():
            verify_directory(path, identity)

    def _no_pending(self):
        for path in (self.journal_pending, self.locator_pending):
            plain_path(path)
            require(not os.path.lexists(path), 'pending publication requires inspection')

    def _ensure_store(self):
        self._assert_locked()
        for path in (self.store.parent, self.store):
            plain_path(path)
            if not path.exists():
                path.mkdir()  # parents are bounded and checked individually
                sync_directory(path.parent)
            self._store_ids.setdefault(path, directory_identity(path))
        self._assert_locked()

    def _publish(self, target, pending, raw, previous, metadata_record=None):
        """Only fixed journal/locator slots; retain pending bytes on every failure."""
        if metadata_record is None:
            require((target, pending) in ((self.journal, self.journal_pending),
                                          (self.locator, self.locator_pending)), 'unknown publication slot')
        else:
            self.validate(metadata_record)
            activation = metadata_record['schema_version'] == 2
            if activation:
                if metadata_record['phase'] == 'APPLYING':
                    self._forward_switch_ready(metadata_record)
                else:
                    self._activation_restore_ready(metadata_record)
            else:
                require(metadata_record['operation'] == 'deactivate'
                        and metadata_record['phase'] in ('APPLYING', 'ROLLING_BACK'),
                        'metadata outside deactivate switch/restore')
            slots = self.metadata_slots(metadata_record)
            require((target, pending) in slots.values(), 'unknown metadata slot')
            name = next(k for k, v in slots.items() if v == (target, pending))
            if activation and metadata_record['phase'] == 'ROLLING_BACK' and name == 'manifest':
                require(self._activation_metadata(slots['state'][0])[0] == metadata_record['old_state'],
                        'state must be restored before manifest')
            if activation and metadata_record['phase'] == 'APPLYING' and name == 'state':
                require(self._activation_metadata(slots['manifest'][0])[0] == metadata_record['new_manifest'],
                        'manifest must be switched before state')
            old = snapshot_bytes(metadata_record['old_' + name])
            new = snapshot_bytes(metadata_record['new_' + name])
            if metadata_record['phase'] == 'APPLYING':
                require(raw == new and previous == old, 'metadata bytes outside recorded transition')
            else:
                require(old is not None and raw == old and previous in (old, new),
                        'metadata bytes outside recorded restoration')
            self._verify_authority(metadata_record)
            self._no_metadata_pending(metadata_record)
        self._assert_locked()
        self._no_pending()
        parent_id = directory_identity(target.parent)
        plain_path(target)
        prior_id = regular_identity(target) if target.exists() else None
        if previous is None:
            require(prior_id is None, 'publication collision')
        else:
            require(prior_id is not None and self._read(target, MAX_JOURNAL) == previous,
                    'stale publication expectation')
        replaced = False
        try:
            with pending.open('xb') as stream:
                pending_id = regular_identity(pending)
                require(stream.write(raw) == len(raw), 'short publication write')
                stream.flush()
                os.fsync(stream.fileno())
            self._assert_locked()
            verify_directory(target.parent, parent_id)
            require(regular_identity(pending) == pending_id
                    and self._read(pending, MAX_JOURNAL) == raw, 'pending publication changed')
            plain_path(target)
            if prior_id is None:
                require(not os.path.lexists(target), 'publication collision')
            else:
                require(regular_identity(target) == prior_id
                        and self._read(target, MAX_JOURNAL) == previous, 'publication target changed')
            os.replace(pending, target)
            replaced = True
            sync_directory(target.parent)
        except (OSError, JournalError) as exc:
            raise PublicationError(target, replaced, exc) from exc

    def metadata_slots(self, record):
        suffix = transaction_id(record['transaction_id']).hex
        return {key: (self.base / name, self.base / ('.' + name + '.' + suffix + '.pending'))
                for key, name in (('manifest', 'install-manifest.json'), ('state', 'active-state.json'))}

    def _no_metadata_pending(self, record):
        for _, pending in self.metadata_slots(record).values():
            plain_path(pending)
            require(not os.path.lexists(pending), 'pending metadata requires recovery')

    def _verify_authority(self, record):
        self._assert_locked()
        self._no_pending()
        require(self._read(self.journal, MAX_JOURNAL) == self.serialize(record), 'journal changed')
        self.validate_locator(strict_json(self._read(self.locator, 16384), 16384), record)

    def publish_journal(self, record, previous=None):
        """Publish initial PREPARING or compare-and-replace a validated prior record.

        previous is exact bytes read from the external authority, not a locator.
        This validates record transitions, not live-tree completion (future M2).
        """
        require(type(record) is dict, 'journal object required')
        self._assert_locked()
        raw = self.serialize(record)
        if record['schema_version'] == 2:
            if self._forward_attempt is not None:
                self._forward_publication(record, previous)
            else:
                self._activation_publication(record, previous)
        self._no_pending()
        if previous is None:
            require(record['phase'] == 'PREPARING', 'initial journal must be PREPARING')
            require(not os.path.lexists(self.locator), 'locator without initial authority')
        else:
            old = self.parse(previous)
            self._validate_transition(old, record)
            self.validate_locator(strict_json(self._read(self.locator, 16384), 16384), old)
        self._ensure_store()
        self._publish(self.journal, self.journal_pending, raw, previous)

    def publish_locator(self, record):
        """External journal must already exist and exactly match; never overwrite locator."""
        require(type(record) is dict, 'journal object required')
        self._assert_locked()
        raw = self.serialize(record)
        if record['schema_version'] == 2:
            require(record == self.load_activation() and record['phase'] == 'PREPARING'
                    and record['workspace_identity'] is None and not os.path.lexists(self.locator),
                    'locator publication requires pristine retained activation')
            self.classify_activation()
        require(self._read(self.journal, MAX_JOURNAL) == raw, 'external journal must be published first')
        locator = self.locator_record(record)
        encoded = (json.dumps(locator, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
        self._publish(self.locator, self.locator_pending, encoded, None)

    @staticmethod
    def _validate_transition(old, new):
        require(old['schema_version'] == new['schema_version'], 'transaction version changed')
        if old['schema_version'] == 2:
            require(old['operation'] == new['operation'] == 'activate', 'activation operation changed')
            if old['workspace_identity'] != new['workspace_identity'] or old['new_children'] != new['new_children']:
                require(old['phase'] == 'PREPARING' and new['phase'] in ('PREPARING', 'PREPARED'),
                        'registration outside preparation')
            if old['skills_created_identity'] != new['skills_created_identity']:
                require(old['phase'] == new['phase'] == 'APPLYING', 'skills allocation outside APPLYING')
        legal = {'PREPARING': {'PREPARED', 'ROLLING_BACK'},
                 'PREPARED': {'APPLYING', 'ROLLING_BACK'},
                 'APPLYING': {'COMMITTED', 'ROLLING_BACK'},
                 'COMMITTED': {'CLEANING'}, 'ROLLING_BACK': {'ROLLED_BACK'},
                 'ROLLED_BACK': {'CLEANING'}, 'CLEANING': {'DONE'}, 'DONE': set()}
        require(new['phase'] == old['phase'] or new['phase'] in legal[old['phase']],
                'illegal journal transition')
        mutable = {'phase', 'outcome', 'skills_created_identity'}
        if old['phase'] in ('COMMITTED', 'ROLLED_BACK') and new['phase'] == 'CLEANING':
            mutable.add('cleanup_entries')
        if old['phase'] == 'PREPARING':
            mutable |= {'prepared', 'workspace_identity', 'old_children', 'new_children'}
        for key in set(old) | set(new):
            if key not in mutable:
                require(old.get(key) == new.get(key), 'immutable transaction field changed: ' + key)
        if old['prepared'] != new['prepared']:
            require(old['phase'] == 'PREPARING' and new['phase'] == 'PREPARED',
                    'preparation can complete only at PREPARED')
        if old['skills_created_identity'] != new['skills_created_identity']:
            require(old['phase'] in ('PREPARING', 'PREPARED', 'APPLYING'),
                    'late skills allocation refused')
        for key in ('skills_created_identity', 'workspace_identity'):
            if old[key] is not None:
                require(old[key] == new[key], 'recorded directory identity changed')
        for key in ('old_children', 'new_children'):
            for child, value in old[key].items():
                if value != {'prepared': False}:
                    require(new[key][child] == value, 'recorded child changed')
        if new['phase'] in ('CLEANING', 'DONE'):
            outcome = old.get('outcome', 'committed' if old['phase'] == 'COMMITTED' else 'rolled_back')
            require(new['outcome'] == outcome, 'transaction outcome changed')

    def _deactivate_snapshot(self, preflight):
        manifest = preflight()  # existing F01 validation, including whole-tree containment
        managed = manifest['managed_ids']
        old = {}
        for key, name in (('manifest', 'install-manifest.json'), ('state', 'active-state.json')):
            path = self.base / name
            plain_path(path)
            old[key] = snapshot(self._read(path, MAX_METADATA) if path.exists() else None)
        self._metadata_pair(old['manifest'], old['state'], managed, True)
        skills = self.base / 'skills'
        children = {i: observed_tree(skills / i) for i in managed}
        return managed, old, children

    def _verify_deactivated(self, record):
        self._verify_authority(record)
        self._no_metadata_pending(record)
        verify_directory(self.base / 'skills', record['skills_before'])
        workspace = self.workspace(record['transaction_id'])
        require({p.name for p in workspace.iterdir()} == {'old', 'new', 'discard'},
                'unexpected workspace contents')
        for area, identity in record['workspace_identity'].items():
            verify_directory(workspace if area == 'root' else workspace / area, identity)
        require({p.name for p in (workspace / 'old').iterdir()} == set(record['old_ids']),
                'backup inventory mismatch')
        require(not any((workspace / 'new').iterdir()) and not any((workspace / 'discard').iterdir()),
                'unexpected deactivate staging content')
        for i, expected in record['old_children'].items():
            plain_path(self.base / 'skills' / i)
            require(not os.path.lexists(self.base / 'skills' / i), 'managed child reappeared')
            require(observed_tree(self.child_path(record['transaction_id'], 'old', i)) == expected,
                    'backup identity/digest mismatch')
        for key, (path, _) in self.metadata_slots(record).items():
            require(self._read(path, MAX_METADATA) == snapshot_bytes(record['new_' + key]),
                    'deactivated metadata changed')

    def deactivate(self, preflight, new_manifest, new_state, dry_run=False):
        """M2a only: commit deactivation, retain all backups for explicit M2b work.

        preflight is the trusted F01 reader, not a project-supplied callback.
        An exception never triggers guessed rollback or destructive cleanup.
        """
        if dry_run:
            return self.reader_report(preflight, lambda: None, operation='deactivate')
        status = self.inspect()
        require(status.state in (RecordState.ABSENT, RecordState.PENDING),
                'transaction requires recovery: ' + status.detail)
        if status.state == RecordState.PENDING:
            require(self.parse(self._read(self.journal, MAX_JOURNAL))['schema_version'] == 1,
                    'A1 v2 execution is disabled')
        # Read-only validation before creating the persistent lifecycle lock.
        if status.state == RecordState.ABSENT:
            self.require_no_transaction()
            managed, old, children = self._deactivate_snapshot(preflight)
            if not managed and not os.path.lexists(self.lock_path):
                plain_path(self.legacy_lock)
                require(not os.path.lexists(self.legacy_lock), 'legacy lock requires manual inspection')
                # Read-only no-op: do not opt an uninitialized installation into
                # the new lifecycle merely by creating a persistent lock file.
                return {'noop': True, 'dry_run': dry_run}
        if dry_run:
            require(status.state == RecordState.ABSENT, 'pending transaction requires locked verification')
            return {'dry_run': True, 'managed_ids': managed}
        with self.lifecycle_lock():
            status = self.inspect()
            if status.state == RecordState.PENDING:
                record = self.parse(self._read(self.journal, MAX_JOURNAL))
                require(record['operation'] == 'deactivate' and record['phase'] == 'COMMITTED',
                        'pending transaction requires M2b recovery')
                preflight()
                self._verify_deactivated(record)
                return {'committed': True, 'noop': True, 'backups_retained': True,
                        'transaction_id': record['transaction_id']}
            require(status.state == RecordState.ABSENT, 'transaction requires recovery: ' + status.detail)
            self.require_no_transaction()
            managed, old, children = self._deactivate_snapshot(preflight)
            if not managed:
                return {'noop': True, 'dry_run': False}
            self._assert_locked()
            record = dict(self.bindings(), schema_version=1, kind='accp-active-txn',
                          transaction_id=str(uuid.uuid4()), operation='deactivate', phase='PREPARING',
                          prepared=False, skills_before=directory_identity(self.base / 'skills'),
                          skills_created_identity=None, workspace_identity=None,
                          old_ids=managed, new_ids=[], old_children=children, new_children={},
                          old_manifest=old['manifest'], old_state=old['state'],
                          new_manifest=snapshot(new_manifest), new_state=snapshot(new_state))
            self.validate(record)
            try:
                self.publish_journal(record)  # BEGIN intent precedes every workspace/live mutation
                self.publish_locator(record)
                workspace = self.workspace(record['transaction_id'])
                workspace.mkdir()  # exclusive; an interrupted allocation is preserved, never adopted
                for name in ('old', 'new', 'discard'):
                    (workspace / name).mkdir()
                workspace_ids = {name: directory_identity(workspace if name == 'root' else workspace / name)
                                 for name in ('root', 'old', 'new', 'discard')}
                for path in (workspace, self.base):
                    sync_directory(path)
                before = self.serialize(record)
                record = dict(record, workspace_identity=workspace_ids, phase='PREPARED', prepared=True)
                self.publish_journal(record, previous=before)
                # Recheck every original child and exact metadata before switching anything.
                current_ids, current_old, current_children = self._deactivate_snapshot(preflight)
                require((current_ids, current_old, current_children) == (managed, old, children),
                        'Active Set changed during prepare')
                verify_directory(self.base / 'skills', record['skills_before'])
                before = self.serialize(record)
                record = dict(record, phase='APPLYING')
                self.publish_journal(record, previous=before)
                for i in managed:
                    self._verify_authority(record)
                    verify_directory(self.base / 'skills', record['skills_before'])
                    for area, expected in workspace_ids.items():
                        verify_directory(workspace if area == 'root' else workspace / area, expected)
                    source = self.base / 'skills' / i
                    destination = self.child_path(record['transaction_id'], 'old', i)
                    require(observed_tree(source) == children[i], 'managed child changed before move')
                    require(not os.path.lexists(destination), 'backup collision')
                    os.replace(source, destination)
                    sync_directory(source.parent)
                    sync_directory(destination.parent)
                for key, (path, pending) in self.metadata_slots(record).items():
                    self._publish(path, pending, snapshot_bytes(record['new_' + key]),
                                  snapshot_bytes(record['old_' + key]), metadata_record=record)
                self._verify_deactivated(record)
                before = self.serialize(record)
                record = dict(record, phase='COMMITTED')
                self.publish_journal(record, previous=before)
                # Cleanup/rollback are deliberately not part of M2a.
                return {'committed': True, 'backups_retained': True,
                        'transaction_id': record['transaction_id'], 'workspace': str(workspace)}
            except Exception as exc:
                raise JournalError(f'deactivate requires inspection/recovery; retained journal={self.journal}; '
                                   f'transaction={record["transaction_id"]}: {exc}') from exc

    def require_legacy_activation_safe(self):
        """Read-only refusal gate, NOT permission to resume a terminal record.

        The caller checks around legacy mutex creation. Recovery's loader owns
        record/identity/pending/orphan validation; no retained phase authorizes
        legacy activation, even DONE awaiting evidence finalization. Therefore
        no filesystem outcome classification or repair is needed here.
        """
        verify_directory(self.checkout, self.checkout_identity)
        verify_directory(self.project, self.project_identity)
        require(self._load_recovery(allow_cleanup=True) is None,
                'retained transaction authority; activation requires recovery/finalization')

    def _load_recovery(self, allow_cleanup=False, *, activation_model=False):
        """Read authority directly; diagnostic inspect() does not authorize recovery."""
        self._no_pending()
        plain_path(self.base)
        names = {p.name for p in self.base.iterdir()} if self.base.exists() else set()
        require(not any(name.endswith('.pending') and name.startswith(
            ('.install-manifest.json.', '.active-state.json.')) for name in names),
            'pending metadata requires manual inspection')
        plain_path(self.journal)
        plain_path(self.locator)
        if not self.journal.exists():
            require(not os.path.lexists(self.locator), 'locator without recovery authority')
            require(not any(name.startswith('.accp-txn-') for name in names),
                    'orphan workspace requires manual inspection')
            return None
        raw = self._read(self.journal, MAX_JOURNAL)
        record = self.parse(raw)
        require(raw == self.serialize(record), 'noncanonical recovery authority')
        if activation_model:
            require(record['schema_version'] == 2, 'not an activation v2 model')
            self._activation_locator(record)
            return record
        require(record['schema_version'] == 1, 'A1 v2 recovery/cleanup execution is disabled')
        require(record['operation'] == 'deactivate' and record['old_ids']
                and not record['new_ids'] and not record['new_children']
                and record['skills_created_identity'] is None,
                'unsupported recovery profile')
        validate_identity(record['skills_before'])
        require(record['old_manifest']['exists'] and record['old_state']['exists'],
                'unsupported absent recovery snapshots')
        for child in record['old_children'].values():
            exact(child, ('identity', 'sha256'))
        require(record['phase'] in ('PREPARING', 'PREPARED', 'APPLYING',
                                    'COMMITTED', 'ROLLING_BACK', 'ROLLED_BACK')
                or (allow_cleanup and record['phase'] in ('CLEANING', 'DONE')),
                'phase requires recover --cleanup')
        require(record['prepared'] or record['workspace_identity'] is None,
                'unsupported unprepared workspace profile')
        if self.locator.exists():
            self.validate_locator(strict_json(self._read(self.locator, 16384), 16384), record)
        else:
            require((record['phase'] == 'PREPARING' and record['workspace_identity'] is None)
                    or (allow_cleanup and record['phase'] == 'DONE'),
                    'missing recovery locator')
        return record

    def _classify_recovery(self, record, path_preflight):
        """All children and both files must be understood before any restoration."""
        self._assert_locked()
        self._no_pending()
        self._no_metadata_pending(record)
        skills = self.base / 'skills'
        verify_directory(skills, record['skills_before'])
        path_preflight()  # F01 whole-live-tree guard, without mixed-pair interpretation
        workspace = self.workspace(record['transaction_id'])
        workspace_ids = record['workspace_identity']
        if workspace_ids is None:
            require(not os.path.lexists(workspace), 'unregistered workspace requires manual inspection')
        else:
            for area, identity in workspace_ids.items():
                verify_directory(workspace if area == 'root' else workspace / area, identity)
            require({p.name for p in workspace.iterdir()} == {'old', 'new', 'discard'},
                    'unexpected recovery workspace content')
            require({p.name for p in (workspace / 'old').iterdir()} <= set(record['old_ids']),
                    'unexpected backup ID')
            require(not any((workspace / 'new').iterdir()) and not any((workspace / 'discard').iterdir()),
                    'unexpected deactivate staging content')
        positions = {}
        for i, expected in record['old_children'].items():
            live = skills / i
            plain_path(live)
            require(live.resolve().parent == skills.resolve(), 'live child escapes boundary')
            backup = self.child_path(record['transaction_id'], 'old', i)
            at_live, at_backup = os.path.lexists(live), os.path.lexists(backup)
            require(at_live != at_backup, 'missing or duplicated recovery child: ' + i)
            require(observed_tree(live if at_live else backup) == expected,
                    'recovery child identity/digest mismatch: ' + i)
            positions[i] = 'LIVE' if at_live else 'BACKUP'
        metadata = {}
        for key, (path, _) in self.metadata_slots(record).items():
            value = self._read(path, MAX_METADATA)
            require(value in (snapshot_bytes(record['old_' + key]), snapshot_bytes(record['new_' + key])),
                    'unknown recovery metadata bytes: ' + key)
            metadata[key] = value
        phase = record['phase']
        if phase in ('PREPARING', 'PREPARED', 'ROLLED_BACK', 'COMMITTED'):
            expected_position = 'BACKUP' if phase == 'COMMITTED' else 'LIVE'
            prefix = 'new_' if phase == 'COMMITTED' else 'old_'
            require(all(p == expected_position for p in positions.values()), 'phase/tree conflict')
            require(all(value == snapshot_bytes(record[prefix + key]) for key, value in metadata.items()),
                    'phase/metadata conflict')
        return positions, metadata

    def recover(self, preflight, path_preflight, dry_run=False):
        """M2b-1: restore an uncommitted deactivate; retain all terminal evidence."""
        if dry_run:
            return self.reader_report(preflight, path_preflight, operation='recover')
        if self._has_activation_recovery():
            return self._recover_activation(dry_run)
        record = self._load_recovery()
        if record is None and not os.path.lexists(self.lock_path):
            plain_path(self.legacy_lock)
            require(not os.path.lexists(self.legacy_lock), 'legacy lock requires manual inspection')
            self._deactivate_snapshot(preflight)
            return {'noop': True, 'dry_run': dry_run}
        with self.lifecycle_lock(create=False):
            record = self._load_recovery()
            if record is None:
                self._deactivate_snapshot(preflight)
                return {'noop': True, 'dry_run': dry_run}
            positions, metadata = self._classify_recovery(record, path_preflight)
            result = {'transaction_id': record['transaction_id'], 'evidence_retained': True}
            if dry_run:
                return dict(result, dry_run=True, phase=record['phase'], positions=positions,
                            action='retain' if record['phase'] in ('COMMITTED', 'ROLLED_BACK') else 'rollback')
            if record['phase'] in ('COMMITTED', 'ROLLED_BACK'):
                return dict(result, noop=True, committed=record['phase'] == 'COMMITTED',
                            rolled_back=record['phase'] == 'ROLLED_BACK')
            try:
                if not self.locator.exists():
                    # _load + classifier proved pristine PREPARING, original live
                    # generation, no allocated workspace and no pending slots.
                    self.publish_locator(record)
                self._verify_authority(record)
                if record['phase'] != 'ROLLING_BACK':
                    before = self.serialize(record)
                    record = dict(record, phase='ROLLING_BACK')
                    self.publish_journal(record, previous=before)
                for i in reversed(record['old_ids']):
                    self._verify_authority(record)
                    verify_directory(self.base / 'skills', record['skills_before'])
                    live = self.base / 'skills' / i
                    plain_path(live)
                    require(live.resolve().parent == (self.base / 'skills').resolve(), 'live restore escape')
                    backup = self.child_path(record['transaction_id'], 'old', i)
                    if positions[i] == 'LIVE':
                        require(not os.path.lexists(backup) and observed_tree(live) == record['old_children'][i],
                                'live recovery child changed')
                        continue
                    workspace = self.workspace(record['transaction_id'])
                    for area, identity in record['workspace_identity'].items():
                        verify_directory(workspace if area == 'root' else workspace / area, identity)
                    require(not os.path.lexists(live) and observed_tree(backup) == record['old_children'][i],
                            'backup changed or restore destination occupied')
                    os.replace(backup, live)
                    sync_directory(backup.parent)
                    sync_directory(live.parent)
                positions, metadata = self._classify_recovery(record, path_preflight)
                require(all(p == 'LIVE' for p in positions.values()), 'restore incomplete')
                # A previous attempt may have renamed the last child and failed
                # on its directory flush. Reflush even when every move is a no-op.
                sync_directory(self.base / 'skills')
                if record['workspace_identity'] is not None:
                    sync_directory(self.workspace(record['transaction_id']) / 'old')
                slots = self.metadata_slots(record)
                for key in ('state', 'manifest'):
                    old = snapshot_bytes(record['old_' + key])
                    if metadata[key] != old:
                        self._publish(*slots[key], old, metadata[key], metadata_record=record)
                positions, metadata = self._classify_recovery(record, path_preflight)
                require(all(p == 'LIVE' for p in positions.values()) and all(
                    value == snapshot_bytes(record['old_' + key]) for key, value in metadata.items()),
                    'restored generation verification failed')
                before = self.serialize(record)
                record = dict(record, phase='ROLLED_BACK')
                self.publish_journal(record, previous=before)
                return dict(result, rolled_back=True, committed=False)
            except Exception as exc:
                raise JournalError(f'recovery_required; retained journal={self.journal}; '
                                   f'transaction={record["transaction_id"]}: {exc}') from exc

    def _validate_cleanup_entries(self, record):
        entries = record['cleanup_entries']
        require(type(entries) is list and len(entries) <= MAX_CLEANUP_ENTRIES, 'invalid cleanup inventory size')
        require(record['operation'] == 'deactivate', 'cleanup supports deactivate only')
        if record['outcome'] == 'rolled_back':
            require(not entries, 'rolled-back cleanup cannot delete managed trees')
        by_key = {}
        aliases = set()
        for entry in entries:
            require(type(entry) is dict and entry.get('type') in ('file', 'directory'), 'invalid cleanup entry')
            keys = {'area', 'id', 'relative', 'type', 'identity'}
            if entry['type'] == 'file': keys |= {'sha256', 'readonly'}
            exact(entry, keys)
            ids([entry['id']])
            require(entry['area'] == 'old' and entry['id'] in record['old_ids'], 'unknown cleanup area/ID')
            relative = entry['relative']
            require(type(relative) is str, 'invalid cleanup relative path')
            try:
                size = len(relative.encode('utf-8'))
            except UnicodeError as exc:
                raise JournalError('invalid cleanup path encoding') from exc
            require(0 < size <= 4096 and '\\' not in relative, 'invalid cleanup path length/spelling')
            if relative == '.':
                require(entry['type'] == 'directory', 'cleanup root must be a directory')
            else:
                for part in relative.split('/'):
                    require(part not in ('', '.', '..') and not part.endswith(('.', ' '))
                            and not any(ord(c) < 32 for c in part)
                            and not re.search(r'[<>:"|?*]', part)
                            and not DEVICE.fullmatch(part.split('.')[0]), 'unsafe cleanup component')
            validate_identity(entry['identity'])
            key = (entry['id'], relative)
            alias = (entry['id'], os.path.normcase(relative))
            require(key not in by_key and alias not in aliases, 'duplicate cleanup target')
            by_key[key] = entry; aliases.add(alias)
            if entry['type'] == 'file':
                require(type(entry['readonly']) is bool and type(entry['sha256']) is str
                        and DIGEST.fullmatch(entry['sha256']), 'invalid cleanup file record')
        for (child_id, relative), entry in by_key.items():
            if relative != '.':
                parent = relative.rsplit('/', 1)[0] if '/' in relative else '.'
                require((child_id, parent) in by_key and by_key[(child_id, parent)]['type'] == 'directory',
                        'cleanup ancestor missing or not a directory')
        if record['outcome'] == 'committed':
            require({i for i, rel in by_key if rel == '.'} == set(record['old_ids']), 'cleanup roots incomplete')
            for i in record['old_ids']:
                require(by_key[(i, '.')]['identity'] == record['old_children'][i]['identity'],
                        'cleanup root identity mismatch')

    def cleanup_entry_path(self, record, entry):
        root = self.child_path(record['transaction_id'], 'old', entry['id'])
        path = root if entry['relative'] == '.' else root.joinpath(*entry['relative'].split('/'))
        plain_path(path)
        require(path == root or root.resolve() in path.resolve().parents, 'cleanup containment failure')
        return path

    @staticmethod
    def _file_digest(path):
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''): digest.update(block)
        return digest.hexdigest()

    def _capture_cleanup(self, record):
        entries = []
        def visit(child_id, root, path):
            plain_path(path)
            info = path.lstat()
            directory = stat.S_ISDIR(info.st_mode)
            identity = directory_identity(path) if directory else dict(zip(('device', 'inode'), map(str, regular_identity(path))))
            entry = {'area': 'old', 'id': child_id, 'relative': path.relative_to(root).as_posix(),
                     'type': 'directory' if directory else 'file', 'identity': identity}
            if not directory:
                entry.update(sha256=self._file_digest(path), readonly=bool(getattr(info, 'st_file_attributes', 0) & 1))
            entries.append(entry)
            require(len(entries) <= MAX_CLEANUP_ENTRIES, 'cleanup inventory exceeds limit')
            if directory:
                for child in sorted(path.iterdir(), key=lambda p: p.name): visit(child_id, root, child)
        if record['phase'] == 'COMMITTED':
            for i in record['old_ids']:
                root = self.child_path(record['transaction_id'], 'old', i)
                visit(i, root, root)
        return entries

    def _check_cleanup_entry(self, record, entry):
        path = self.cleanup_entry_path(record, entry)
        if not os.path.lexists(path): return path, False
        if entry['type'] == 'directory':
            verify_directory(path, entry['identity'])
        else:
            actual = dict(zip(('device', 'inode'), map(str, regular_identity(path))))
            require(actual == entry['identity'] and self._file_digest(path) == entry['sha256'],
                    'cleanup file identity/content mismatch')
            readonly = bool(getattr(path.lstat(), 'st_file_attributes', 0) & 1)
            require(entry['readonly'] or not readonly, 'unexpected readonly change')
        return path, True

    def _cleanup_authority(self, record):
        self._assert_locked(); self._no_pending(); self._no_metadata_pending(record)
        require(self._read(self.journal, MAX_JOURNAL) == self.serialize(record), 'cleanup journal changed')
        if os.path.lexists(self.locator):
            self.validate_locator(strict_json(self._read(self.locator, 16384), 16384), record)
        else:
            require(record['phase'] == 'DONE', 'cleanup locator missing before DONE')

    def _verify_cleanup(self, record, path_preflight):
        self._cleanup_authority(record)
        require('cleanup_entries' in record, 'legacy terminal record lacks cleanup authority')
        verify_directory(self.base / 'skills', record['skills_before']); path_preflight()
        for i, expected in record['old_children'].items():
            live = self.base / 'skills' / i; plain_path(live)
            if record['outcome'] == 'committed':
                require(not os.path.lexists(live), 'committed child reappeared live')
            else:
                require(observed_tree(live) == expected, 'restored generation changed')
        prefix = 'new_' if record['outcome'] == 'committed' else 'old_'
        for key, (path, _) in self.metadata_slots(record).items():
            require(self._read(path, MAX_METADATA) == snapshot_bytes(record[prefix + key]), 'terminal metadata changed')
        workspace = self.workspace(record['transaction_id'])
        workspace_ids = record['workspace_identity']
        require(workspace_ids is not None or not os.path.lexists(workspace), 'unregistered cleanup workspace')
        allowed = {}
        if workspace_ids is not None:
            for area, identity in workspace_ids.items():
                path = workspace if area == 'root' else workspace / area
                plain_path(path)
                if os.path.lexists(path): verify_directory(path, identity)
                allowed[path] = None
        for entry in record['cleanup_entries']:
            path, _ = self._check_cleanup_entry(record, entry)
            require(path not in allowed, 'cleanup target aliases fixed directory')
            allowed[path] = entry
        def scan(path):
            plain_path(path)
            require(path in allowed, 'unlisted cleanup content')
            if path.is_dir():
                for child in path.iterdir(): scan(child)
        if workspace.exists(): scan(workspace)
        if record['phase'] == 'DONE':
            require(not os.path.lexists(workspace), 'DONE workspace reappeared')

    def cleanup(self, preflight, path_preflight, dry_run=False):
        """Explicit terminal cleanup; never rolls back or cleans uncommitted work."""
        if dry_run:
            return self.reader_report(preflight, path_preflight, operation='cleanup')
        if self._has_activation_recovery():
            return self._cleanup_activation(dry_run)
        record = self._load_recovery(allow_cleanup=True)
        if record is None and not os.path.lexists(self.lock_path):
            return self.recover(preflight, path_preflight, dry_run=dry_run)
        with self.lifecycle_lock(create=False):
            record = self._load_recovery(allow_cleanup=True)
            if record is None:
                self._deactivate_snapshot(preflight)
                if not dry_run:
                    # Also covers retry after the journal unlink succeeded but
                    # its final directory flush reported failure.
                    sync_directory(self.base)
                    if self.store.exists(): sync_directory(self.store)
                return {'noop': True, 'dry_run': dry_run, 'finalized': True}
            require(record['phase'] in ('COMMITTED', 'ROLLED_BACK', 'CLEANING', 'DONE'),
                    'rollback must complete before cleanup')
            if record['phase'] in ('COMMITTED', 'ROLLED_BACK'):
                self._classify_recovery(record, path_preflight)
                entries = self._capture_cleanup(record)
                self._classify_recovery(record, path_preflight)  # complete digest check after capture
                next_record = dict(record, phase='CLEANING',
                    outcome='committed' if record['phase'] == 'COMMITTED' else 'rolled_back', cleanup_entries=entries)
                self.serialize(next_record)  # size/schema bounds before publication or deletion
            else:
                self._verify_cleanup(record, path_preflight)
                next_record = record
            if dry_run:
                return {'dry_run': True, 'phase': record['phase'], 'outcome': next_record['outcome'],
                        'cleanup_entries': len(next_record['cleanup_entries'])}
            try:
                if record is not next_record:
                    self.publish_journal(next_record, previous=self.serialize(record)); record = next_record
                self._verify_cleanup(record, path_preflight)
                if record['phase'] == 'CLEANING':
                    entries = sorted(record['cleanup_entries'], key=lambda e: (
                        0 if e['relative'] == '.' else len(e['relative'].split('/')), e['id'], e['relative']), reverse=True)
                    for entry in entries:
                        # Authority was fully validated under the held lock above.
                        # Recheck target and pinned filesystem boundaries per mutation.
                        self._assert_locked()
                        workspace = self.workspace(record['transaction_id'])
                        for area in ('root', 'old'):
                            path = workspace if area == 'root' else workspace / area
                            if path.exists(): verify_directory(path, record['workspace_identity'][area])
                        path, present = self._check_cleanup_entry(record, entry)
                        if not present: continue
                        if entry['type'] == 'file':
                            if os.name == 'nt' and getattr(path.lstat(), 'st_file_attributes', 0) & 1:
                                path.chmod(path.stat().st_mode | stat.S_IWRITE)
                                self._check_cleanup_entry(record, entry)
                            path.unlink()
                        else:
                            path.rmdir()
                        sync_directory(path.parent)
                    self._verify_cleanup(record, path_preflight)
                    workspace = self.workspace(record['transaction_id'])
                    if record['workspace_identity'] is not None:
                        for area in ('old', 'new', 'discard', 'root'):
                            path = workspace if area == 'root' else workspace / area
                            self._assert_locked(); plain_path(path)
                            if path.exists():
                                verify_directory(path, record['workspace_identity'][area])
                                path.rmdir(); sync_directory(path.parent)
                    # Reflush surviving parents even after interrupted/no-op removals.
                    sync_directory(self.base)
                    self._verify_cleanup(record, path_preflight)
                    next_record = dict(record, phase='DONE')
                    self.publish_journal(next_record, previous=self.serialize(record)); record = next_record
                self._verify_cleanup(record, path_preflight)
                if self.locator.exists():
                    raw = self._read(self.locator, 16384)
                    self.validate_locator(strict_json(raw, 16384), record)
                    self._unlink_evidence(self.locator, raw, record)
                sync_directory(self.base)
                self._verify_cleanup(record, path_preflight)  # DONE permits absent locator only
                self._unlink_evidence(self.journal, self.serialize(record), record)
                return {'finalized': True, 'outcome': record['outcome'], 'transaction_id': record['transaction_id']}
            except Exception as exc:
                raise JournalError(f'cleanup_pending; outcome={next_record["outcome"]}; '
                                   f'retained authority if present={self.journal}: {exc}') from exc

    def _unlink_evidence(self, path, expected, record):
        if record.get('schema_version') == 2:
            self._activation_current(record)
        require(path in (self.locator, self.journal), 'unknown evidence slot')
        require(record['phase'] == 'DONE' and 'cleanup_entries' in record, 'evidence requires inventoried DONE')
        self._cleanup_authority(record)
        require(not os.path.lexists(self.workspace(record['transaction_id'])), 'workspace remains at finalization')
        if path == self.journal:
            require(not os.path.lexists(self.locator), 'locator must be removed before journal')
        identity = regular_identity(path)
        require(self._read(path, MAX_JOURNAL) == expected and regular_identity(path) == identity,
                'evidence changed before finalization')
        path.unlink(); sync_directory(path.parent)

    def require_no_transaction(self):
        """Writer entry preflight, including absent local lifecycle indicators."""
        require(self._load_recovery(allow_cleanup=True) is None, 'retained transaction requires explicit recovery/cleanup')
        plain_path(self.legacy_lock)
        require(not os.path.lexists(self.legacy_lock), 'legacy lock requires manual inspection')
        if os.path.lexists(self.lock_path): regular_identity(self.lock_path)
        names = self._activation_names(self.base)
        require(not any(n.startswith(('.skills-stage-', '.skills-backup-')) for n in names),
                'legacy activation residue requires inspection')

    def forward_record(self, attempt):
        if self._forward_attempt is None: return None
        require(self._forward_attempt is attempt, 'foreign forward attempt')
        self._assert_locked()
        return self._forward_record

    def _forward_capability(self, record, phase):
        self._assert_locked()
        attempt = self._forward_attempt
        require(type(attempt) is activation_observation.ActivationAttempt and attempt.authority is self
                and attempt.api._activation_attempts.get(attempt) is attempt
                and attempt.phase == phase and attempt.runtime_held, 'current forward attempt required')
        require(record['transaction_id'] == attempt.nonce, 'forward attempt/transaction mismatch')

    def _forward_publication(self, record, previous):
        self._forward_capability(record, 'consumed' if record['phase'] == 'COMMITTED' else 'running')
        require(self._forward_expected == self.serialize(record), 'unissued forward publication')
        old = self._forward_record
        if old is None:
            require(previous is None and record['phase'] == 'PREPARING', 'invalid forward begin')
            self.require_no_transaction()
        else:
            require(previous == self.serialize(old), 'stale forward record')
            self._verify_authority(old)
            self._validate_transition(old, record)
            require((old['phase'], record['phase']) in {('PREPARING','PREPARING'),
                ('PREPARING','PREPARED'), ('PREPARED','APPLYING'), ('APPLYING','APPLYING'),
                ('APPLYING','COMMITTED')}, 'invalid forward transition')
        if record['phase'] == 'COMMITTED':
            self._forward_switch_ready(old)
            for key, (path, _) in self.metadata_slots(old).items():
                require(self._activation_metadata(path)[0] == old['new_' + key], 'commit metadata incomplete')

    def _publish_forward(self, record):
        raw = self.serialize(record)
        previous = None if self._forward_record is None else self.serialize(self._forward_record)
        self._forward_expected = raw
        try:
            self.publish_journal(record, previous)
            self._forward_record = self.parse(raw)
        finally:
            self._forward_expected = None
        return self._forward_record

    def _forward_switch_ready(self, record):
        self._forward_capability(record, 'consumed')
        require(record == self._forward_record and record['phase'] == 'APPLYING', 'foreign forward switch')
        layout = self._activation_current(record)
        require(all(p == 'BACKUP' for p in layout['old_positions'].values())
                and all(p == 'LIVE' for p in layout['new_positions'].values()), 'forward children incomplete')

    def _project_activation_cleanup(self, record):
        """Pre-switch live/cleanup bounds only; no deletion authority is published."""
        live=activation_observation.tree_observation(self.base/'skills') or []
        staged=activation_observation.tree_observation(self.workspace(record['transaction_id'])/'new')
        unmanaged=[row for row in live if row['path'] != '.'
                   and row['path'].split('/')[0] not in record['old_ids']]
        projected=unmanaged+staged[1:]
        require(1+len(projected) <= binding.MAX_ENTRIES, 'projected live tree count limit')
        require(sum(row['size'] for row in projected if row['type']=='file') <= binding.MAX_PAYLOAD,
                'projected live tree byte limit')
        for outcome, generation, area, parent in (
                ('committed', 'old', 'old', self.base / 'skills'),
                # All installed children may end in discard; its longer spelling
                # is the worst serialized size, including mixed rollback cuts.
                ('rolled_back', 'new', 'discard', self.workspace(record['transaction_id']) / 'new')):
            entries = []
            for ident in record[generation + '_ids']:
                root = parent / ident
                for row in activation_observation.tree_observation(root):
                    entry = dict(area=area, id=ident, relative=row['path'], type=row['type'],
                        identity=row['identity'] if row['type'] == 'directory' else
                            dict(zip(('device','inode'), map(str,row['identity'][:2]))))
                    if row['type'] == 'file':
                        path = root.joinpath(*row['path'].split('/'))
                        entry.update(sha256=row['sha256'], readonly=bool(getattr(path.lstat(),'st_file_attributes',0) & 1))
                    entries.append(entry)
                    require(len(entries) <= MAX_CLEANUP_ENTRIES, 'projected cleanup count limit')
            raw=self.serialize(dict(record, phase='CLEANING', outcome=outcome, cleanup_entries=entries))
            # An absent root is allocated only after APPLYING. Reserve the full
            # validated identity width without inventing an authority identity.
            reserve=0
            if record['skills_before']=={'exists':False} and record['skills_created_identity'] is None:
                reserve=len(json.dumps({'device':'9'*40,'inode':'9'*40},separators=(',',':')))-len('null')
            require(len(raw)+reserve <= MAX_JOURNAL, 'projected cleanup journal size limit')

    @binding_checks()
    def activate(self, attempt, args, plan, paths):
        """One issued F06 attempt produces one forward transaction; never resume."""
        require(type(attempt) is activation_observation.ActivationAttempt and attempt.authority is self
                and self._forward_attempt is None, 'issued activation attempt required')
        api = attempt.api
        fresh, context, prepared = attempt.validate(args, plan, paths)
        old_ids = sorted(api.read_install_manifest(*paths[:4], args.project, args.scope)['managed_ids'])
        self.activation_snapshot(old_ids, sorted(fresh['providers']))  # collision/bounds before enrollment
        if not os.path.lexists(self.base):
            binding.plain_path(self.base.parent, True)
            self.require_no_transaction()
            self.base.mkdir()
            sync_directory(self.base.parent)
            attempt.accept_enrollment()
        with self.lifecycle_lock():
            self.require_no_transaction()
            fresh, context, prepared = attempt.validate(args, plan, paths)
            old_ids = sorted(api.read_install_manifest(*paths[:4], args.project, args.scope)['managed_ids'])
            new_ids = sorted(fresh['providers'])
            snap = self.activation_snapshot(old_ids, new_ids)
            stamp = api.now()
            manifest = dict(schema_version=1,control_plane_path=str(self.checkout),scope=self.scope,
                project=str(self.project),managed_ids=new_ids,mode=args.mode,installed_at=stamp)
            state = dict(schema_version=1,control_plane_path=str(self.checkout),mode=args.mode,
                         active_ids=new_ids,activated_at=stamp)
            proof = json.loads(attempt.proof)
            providers = {}
            for ident in new_ids:
                ev = api.evidence_ok(ident, context['locks'][ident], strict=True)
                bound = proof['records'][ident]
                providers[ident] = dict(candidate_sha256=bound['candidate'], evidence_sha256=bound['evidence'],
                    lock_sha256=bound['lock'], artifact_tree_sha256=ev['candidate']['artifact_tree_sha256'],
                    invocation=context['idx'][ident]['invocation'], projection=binding.PROJECTION)
            record = dict(self.bindings(),schema_version=2,kind='accp-active-txn',operation='activate',
                transaction_id=attempt.nonce,phase='PREPARING',prepared=False,
                skills_before=snap['skills_before'],skills_created_identity=None,workspace_identity=None,
                # A newly created journal always declares the current encoding of
                # both digest domains; neither is ever written as legacy.
                observation_digest_version=activation_observation.OBSERVATION_DIGEST_V2,
                old_ids=old_ids,new_ids=new_ids,old_children=snap['old_children'],
                new_children={i:{'prepared':False} for i in new_ids},old_manifest=snap['old_manifest'],
                old_state=snap['old_state'],new_manifest=snapshot((json.dumps(manifest)+'\n').encode('utf-8')),
                new_state=snapshot((json.dumps(state)+'\n').encode('utf-8')),
                activation=dict(attempt_id=attempt.nonce,
                    context_sha256=activation_observation.transaction_digest('accp-activation-context-v1',proof),
                    runtime_binding=attempt.vault[0] if new_ids else None,providers=providers,
                    unmanaged_sha256=snap['unmanaged_sha256'],old_metadata_identity=snap['old_metadata_identity'],
                    unmanaged_digest_version=activation_observation.UNMANAGED_DIGEST_V2,
                    skills_mode_before=snap['skills_mode_before']))
            self._forward_attempt = attempt
            try:
                attempt.validate(args, plan, paths)
                record = self._publish_forward(record)
                self.publish_locator(record)
                workspace = self.workspace(attempt.nonce)
                self._activation_current(record)
                workspace.mkdir()
                for area in ('old','new','discard'): (workspace/area).mkdir()
                identities = {a:directory_identity(workspace if a=='root' else workspace/a)
                              for a in ('root','old','new','discard')}
                for path in (workspace,self.base): sync_directory(path)
                record = self._publish_forward(dict(record,workspace_identity=identities))
                attempt.stage=workspace/'new'; attempt.stage_id=directory_identity(attempt.stage)
                for ident in new_ids:
                    _, context, prepared = attempt.validate(args,plan,paths)
                    destination = self.child_path(attempt.nonce,'new',ident)
                    require(not os.path.lexists(destination), 'staging collision')
                    def copy_file(source, target):
                        data, _ = binding._read_file(Path(source), binding.MAX_FILE)
                        plain_path(Path(target))
                        with Path(target).open('xb') as stream:
                            require(stream.write(data) == len(data), 'short staged write')
                            stream.flush(); os.fsync(stream.fileno())
                        api.shutil.copystat(source,target)
                        return str(target)
                    api.shutil.copytree(prepared[ident],destination,copy_function=copy_file)
                    require(activation_observation.capture(api,args,plan,attempt.nonce)[2] == attempt.proof,
                            'activation context/binding changed during staging')
                    ev = api.evidence_ok(ident,context['locks'][ident],strict=True)
                    binding.validate_artifact_copy(destination,ev,context['locks'][ident]['evidence_sha256'],attempt.vault[0])
                    rows = activation_observation.tree_observation(destination)
                    for row in reversed(rows):
                        if row['type']=='directory': sync_directory(destination.joinpath(*row['path'].split('/')))
                    sync_directory(destination.parent)
                    children = dict(record['new_children'], **{ident:self._activation_child(destination)})
                    record = self._publish_forward(dict(record,new_children=children))
                attempt.staged=activation_observation.tree_observation(attempt.stage)
                attempt.validate(args,plan,paths)
                record = self._publish_forward(dict(record,phase='PREPARED',prepared=True))
                self._project_activation_cleanup(record)
                attempt.validate(args,plan,paths)
                record = self._publish_forward(dict(record,phase='APPLYING'))
                skills=self.base/'skills'
                if record['skills_before']=={'exists':False}:
                    self._activation_current(record)
                    skills.mkdir(); sync_directory(self.base)
                    record=self._publish_forward(dict(record,skills_created_identity=directory_identity(skills)))
                attempt.validate(args,plan,paths,stage=attempt.stage)
                attempt.phase='consumed'
                # Recompute every moved object under this record's own child-observation
                # encoding. Never inferred from the unmanaged digest version.
                child_version = observation_digest_version(record)
                for generation, source_parent, target_area in (('old',skills,'old'),('new',attempt.stage,None)):
                    for ident in record[generation+'_ids']:
                        self._forward_capability(record,'consumed'); self._activation_current(record)
                        source=source_parent/ident
                        target=self.child_path(attempt.nonce,target_area,ident) if target_area else skills/ident
                        plain_path(target)
                        require(target.resolve().parent==(self.workspace(attempt.nonce)/target_area if target_area else skills).resolve(),
                                'forward target escape')
                        require(not os.path.lexists(target) and self._activation_child(source,child_version)==record[generation+'_children'][ident],
                                'forward object changed or destination occupied')
                        os.replace(source,target); sync_directory(source.parent); sync_directory(target.parent)
                for key,(path,pending) in self.metadata_slots(record).items():
                    self._publish(path,pending,snapshot_bytes(record['new_'+key]),snapshot_bytes(record['old_'+key]),metadata_record=record)
                record=self._publish_forward(dict(record,phase='COMMITTED'))
                return dict(state,committed=True,evidence_retained=True,transaction_id=attempt.nonce,workspace=str(workspace))
            except (OSError, JournalError, binding.BindingError, RuntimeError) as exc:
                # A replace may have succeeded before a flush or injected failure.
                # Only retained authority determines the outcome; never retry forward.
                try:
                    retained=self.load_activation()
                    observed='absent' if retained is None else self.classify_activation()['phase']
                except (OSError, JournalError, binding.BindingError) as inspection:
                    observed='inspection-required: '+str(inspection)
                raise JournalError(f'activation requires inspection/recovery; authority={observed}; '
                                   f'retained journal={self.journal}: {exc}') from exc
            finally:
                self._forward_attempt=None; self._forward_record=None; self._forward_expected=None

    def _has_activation_recovery(self):
        """Strict read-only dispatch; local indicators never grant authority."""
        self._no_pending()
        plain_path(self.journal)
        if not self.journal.exists(): return False
        record = self.parse(self._read(self.journal, MAX_JOURNAL))
        if record['schema_version'] != 2: return False
        self.load_activation()
        return True

    def _activation_current(self, record):
        self._assert_locked()
        require(self.load_activation() == record, 'activation recovery authority changed')
        return self.classify_activation()

    def _activation_restore_ready(self, record):
        layout = self._activation_current(record)
        require(record['phase'] == 'ROLLING_BACK'
                and all(p == 'LIVE' for p in layout['old_positions'].values())
                and all(p != 'LIVE' for p in layout['new_positions'].values()),
                'metadata restoration before child restoration')

    def _activation_restored(self, record):
        self._activation_restore_ready(record)
        for key, (path, _) in self.metadata_slots(record).items():
            require(self._activation_metadata(path)[0] == record['old_' + key], 'old metadata not restored')
        require(os.path.lexists(self.base / 'skills') != (record['skills_before'] == {'exists': False}),
                'original skills existence not restored')

    def _activation_publication(self, record, previous):
        """A2 permits only recovery transitions of already retained authority."""
        require(previous is not None, 'A2 forward activation publication is disabled')
        old = self.load_activation()
        require(old is not None and self.serialize(old) == previous, 'stale activation publication')
        self._activation_current(old)
        require((old['phase'], record['phase']) in {
            ('PREPARING', 'ROLLING_BACK'), ('PREPARED', 'ROLLING_BACK'),
            ('APPLYING', 'ROLLING_BACK'), ('ROLLING_BACK', 'ROLLED_BACK'),
            ('COMMITTED', 'CLEANING'), ('ROLLED_BACK', 'CLEANING'), ('CLEANING', 'DONE')},
            'A2 forward activation publication is disabled')
        for key in set(old) | set(record):
            if key not in ('phase', 'outcome', 'cleanup_entries'):
                require(old.get(key) == record.get(key), 'recovery cannot register or change objects')
        self._validate_transition(old, record)
        if record['phase'] == 'ROLLED_BACK': self._activation_restored(old)
        if record['phase'] == 'CLEANING':
            require(record['cleanup_entries'] == self._capture_activation_cleanup(old),
                    'cleanup inventory differs from terminal objects')
        if record['phase'] == 'DONE':
            require(not os.path.lexists(self.workspace(record['transaction_id'])), 'cleanup incomplete')

    def _restore_activation_metadata(self, record, key):
        require(key in ('state', 'manifest'), 'unknown restoration slot')
        self._activation_restore_ready(record)
        slots = self.metadata_slots(record)
        path, pending = slots[key]
        if key == 'manifest':
            require(self._activation_metadata(slots['state'][0])[0] == record['old_state'],
                    'state must be restored before manifest')
        old = snapshot_bytes(record['old_' + key])
        current, identity = self._activation_metadata(path)
        current = snapshot_bytes(current)
        if current != old:
            if old is None:
                require(current == snapshot_bytes(record['new_' + key]), 'unknown metadata at unlink')
                self._activation_restore_ready(record)
                require(self._activation_metadata(path) == (snapshot(current), identity),
                        'metadata changed before unlink')
                path.unlink()  # only a fixed slot holding the recorded new bytes
            else:
                self._publish(path, pending, old, current, metadata_record=record)
        # Retry also flushes a completed unlink/replacement whose flush failed.
        sync_directory(self.base)

    @binding_checks()
    def _recover_activation(self, dry_run):
        with self.lifecycle_lock(create=False):
            record = self.load_activation()
            require(record is not None, 'activation authority disappeared')
            layout = self._activation_current(record)
            require(record['phase'] not in ('CLEANING', 'DONE'), 'phase requires recover --cleanup')
            result = dict(transaction_id=record['transaction_id'], evidence_retained=True)
            if dry_run: return dict(result, dry_run=True, **layout)
            if record['phase'] in ('COMMITTED', 'ROLLED_BACK'):
                return dict(result, noop=True, committed=record['phase'] == 'COMMITTED',
                            rolled_back=record['phase'] == 'ROLLED_BACK')
            try:
                if not os.path.lexists(self.locator): self.publish_locator(record)
                if record['phase'] != 'ROLLING_BACK':
                    next_record = dict(record, phase='ROLLING_BACK')
                    self.publish_journal(next_record, previous=self.serialize(record)); record = next_record
                child_version = observation_digest_version(record)
                for generation in ('new', 'old'):
                    for ident in reversed(record[generation + '_ids']):
                        layout = self._activation_current(record)
                        position = layout[generation + '_positions'][ident]
                        if (generation, position) not in (('new', 'LIVE'), ('old', 'BACKUP')): continue
                        live = self.base / 'skills' / ident
                        plain_path(live)
                        require(live.resolve().parent == (self.base / 'skills').resolve(), 'restore escape')
                        source, target = ((live, self.child_path(record['transaction_id'], 'discard', ident))
                            if generation == 'new' else
                            (self.child_path(record['transaction_id'], 'old', ident), live))
                        require(not os.path.lexists(target) and self._activation_child(source, child_version)
                                == record[generation + '_children'][ident], 'restore object changed')
                        os.replace(source, target)
                        sync_directory(source.parent); sync_directory(target.parent)
                self._activation_restore_ready(record)
                # Reflush every surviving move parent, including no-op retry cuts.
                parents = [self.base / 'skills']
                if record['workspace_identity'] is not None:
                    parents += [self.workspace(record['transaction_id']) / a for a in ('old', 'new', 'discard')]
                for path in parents:
                    if path.exists(): sync_directory(path)
                for key in ('state', 'manifest'): self._restore_activation_metadata(record, key)
                if record['skills_before'] == {'exists': False}:
                    self._activation_restore_ready(record)
                    skills = self.base / 'skills'
                    if os.path.lexists(skills):
                        verify_directory(skills, record['skills_created_identity'])
                        require(not any(skills.iterdir()), 'created skills is not empty')
                        skills.rmdir()
                    sync_directory(self.base)
                self._activation_restored(record)
                next_record = dict(record, phase='ROLLED_BACK')
                self.publish_journal(next_record, previous=self.serialize(record))
                return dict(result, rolled_back=True, committed=False)
            except (OSError, JournalError, binding.BindingError) as exc:
                raise JournalError(f'recovery_required; retained journal={self.journal}: {exc}') from exc

    def _capture_activation_cleanup(self, record):
        self._activation_current(record)
        require(record['phase'] in ('COMMITTED', 'ROLLED_BACK'), 'cleanup needs terminal outcome')
        entries = []
        areas = ('old',) if record['phase'] == 'COMMITTED' else ('new', 'discard')
        if record['workspace_identity'] is not None:
            for area in areas:
                parent = self.workspace(record['transaction_id']) / area
                rows = activation_observation.tree_observation(parent)
                for row in rows[1:]:
                    ident, _, relative = row['path'].partition('/')
                    entry = dict(area=area, id=ident, relative=relative or '.', type=row['type'],
                        identity=row['identity'] if row['type'] == 'directory' else
                            dict(zip(('device', 'inode'), map(str, row['identity'][:2]))))
                    if row['type'] == 'file':
                        path = parent.joinpath(*row['path'].split('/'))
                        entry.update(sha256=row['sha256'], readonly=bool(getattr(path.lstat(), 'st_file_attributes', 0) & 1))
                    entries.append(entry)
                    require(len(entries) <= MAX_CLEANUP_ENTRIES, 'cleanup count limit')
        self._activation_current(record)
        return entries

    def _activation_cleanup_path(self, record, entry):
        root = self.child_path(record['transaction_id'], entry['area'], entry['id'])
        path = root if entry['relative'] == '.' else root.joinpath(*entry['relative'].split('/'))
        plain_path(path)
        require(path == root or root.resolve() in path.resolve().parents, 'cleanup escape')
        return path

    @binding_checks()
    def _cleanup_activation(self, dry_run):
        with self.lifecycle_lock(create=False):
            record = self.load_activation()
            require(record is not None, 'activation authority disappeared')
            self._activation_current(record)
            require(record['phase'] in ('COMMITTED', 'ROLLED_BACK', 'CLEANING', 'DONE'),
                    'rollback must complete before cleanup')
            next_record = record
            if record['phase'] in ('COMMITTED', 'ROLLED_BACK'):
                next_record = dict(record, phase='CLEANING',
                    outcome='committed' if record['phase'] == 'COMMITTED' else 'rolled_back',
                    cleanup_entries=self._capture_activation_cleanup(record))
                self.serialize(next_record)
            if dry_run:
                return dict(dry_run=True, phase=record['phase'], outcome=next_record['outcome'],
                            cleanup_entries=len(next_record['cleanup_entries']))
            try:
                if record is not next_record:
                    self.publish_journal(next_record, previous=self.serialize(record)); record = next_record
                if record['phase'] == 'CLEANING':
                    entries = sorted(record['cleanup_entries'], key=lambda e: (
                        0 if e['relative'] == '.' else len(e['relative'].split('/')),
                        e['area'], e['id'], e['relative']), reverse=True)
                    for entry in entries:
                        self._activation_current(record)
                        path = self._activation_cleanup_path(record, entry)
                        if not os.path.lexists(path): continue
                        if entry['type'] == 'file':
                            if os.name == 'nt' and getattr(path.lstat(), 'st_file_attributes', 0) & 1:
                                path.chmod(path.stat().st_mode | stat.S_IWRITE)
                                self._activation_current(record)
                            path.unlink()
                        else: path.rmdir()
                        sync_directory(path.parent)
                    workspace = self.workspace(record['transaction_id'])
                    if record['workspace_identity'] is not None:
                        for area in ('old', 'new', 'discard', 'root'):
                            self._activation_current(record)
                            path = workspace if area == 'root' else workspace / area
                            if os.path.lexists(path):
                                verify_directory(path, record['workspace_identity'][area])
                                path.rmdir(); sync_directory(path.parent)
                    sync_directory(self.base)
                    self._activation_current(record)
                    next_record = dict(record, phase='DONE')
                    self.publish_journal(next_record, previous=self.serialize(record)); record = next_record
                self._activation_current(record)
                if os.path.lexists(self.locator):
                    self._unlink_evidence(self.locator, self._read(self.locator, 16384), record)
                sync_directory(self.base)
                self._activation_current(record)
                self._unlink_evidence(self.journal, self.serialize(record), record)
                return dict(finalized=True, outcome=record['outcome'], transaction_id=record['transaction_id'])
            except (OSError, JournalError, binding.BindingError) as exc:
                raise JournalError(f'cleanup_pending; retained authority if present={self.journal}: {exc}') from exc

    @staticmethod
    def _activation_digest(value):
        require(type(value) is str and DIGEST.fullmatch(value), 'invalid activation digest')

    @staticmethod
    def _activation_identity_key(value):
        validate_identity(value)
        return value['device'], value['inode']

    @staticmethod
    def _activation_child(path, version=activation_observation.OBSERVATION_DIGEST_V2):
        """Observe one child and digest it under an explicit encoding version.

        Write sites rely on the default, which is the current encoding. Every
        comparison site must instead pass the version taken from the record being
        validated, so that a legacy journal is recomputed with the encoding it was
        written under.

        The binding observation rejects streams/hardlinks and bounds the read
        before the legacy full-tree digest. It is repeated to detect read-time
        drift; that probe always compares two live reads, so it is independent of
        the persisted digest version.
        """
        rows = activation_observation.child_rows(path)
        digest = activation_observation.child_observation(rows, version)
        result = observed_tree(path)
        require(activation_observation.child_rows(path) == rows,
                'activation child changed during observation')
        return dict(result, observation_sha256=digest)

    @staticmethod
    def _activation_metadata(path):
        if not os.path.lexists(path):
            plain_path(path)
            return snapshot(None), None
        raw, stamp = binding._read_file(path, MAX_METADATA)
        return snapshot(raw), {'device': str(stamp[0]), 'inode': str(stamp[1])}

    @staticmethod
    def _activation_names(path):
        """Names of plain children, rejecting platform-independent aliases."""
        if not os.path.lexists(path):
            return set()
        binding.plain_path(path, True)
        binding._streams(path)
        names, aliases = set(), set()
        for child in path.iterdir():
            require(len(names) < binding.MAX_ENTRIES, 'activation directory count limit')
            alias = unicodedata.normalize('NFKC', child.name).casefold()
            require(alias not in aliases, 'activation child name alias')
            aliases.add(alias); names.add(child.name)
        return names

    @binding_checks()
    def activation_snapshot(self, old_ids, new_ids,
                           version=activation_observation.UNMANAGED_DIGEST_V2):
        """Pure snapshot, not a producer or permission to activate. No mkdir/lock.

        New records are always written with the current unmanaged digest version;
        validation of an existing record passes that record's version explicitly.
        """
        for values in (old_ids, new_ids):
            ids(values)
            require(values == sorted(values), 'activation IDs must be sorted')
        verify_directory(self.checkout, self.checkout_identity)
        verify_directory(self.project, self.project_identity)
        plain_path(self.base)
        skills = self.base / 'skills'
        rows = activation_observation.tree_observation(skills)
        names = self._activation_names(skills)
        require(set(old_ids) <= names, 'claimed old child missing')
        aliases = {unicodedata.normalize('NFKC', name).casefold(): name for name in names}
        for ident in new_ids:
            other = aliases.get(ident)
            require(other is None or (other == ident and ident in old_ids),
                    'new provider collides with unmanaged child')
        old = {key: self._activation_metadata(self.base / name) for key, name in
               (('manifest', 'install-manifest.json'), ('state', 'active-state.json'))}
        self._metadata_pair(old['manifest'][0], old['state'][0], old_ids, True)
        children = {ident: self._activation_child(skills / ident) for ident in old_ids}
        require(activation_observation.tree_observation(skills) == rows, 'snapshot tree drift')
        for key, name in (('manifest', 'install-manifest.json'), ('state', 'active-state.json')):
            require(self._activation_metadata(self.base / name) == old[key], 'snapshot metadata drift')
        return dict(old_ids=list(old_ids), old_children=children,
                    old_manifest=old['manifest'][0], old_state=old['state'][0],
                    old_metadata_identity={key: value[1] for key, value in old.items()},
                    skills_before=rows[0]['identity'] if rows is not None else {'exists': False},
                    skills_mode_before=rows[0]['mode'] if rows is not None else None,
                    unmanaged_sha256=activation_observation.unmanaged_observation(rows, old_ids, version))

    @binding_checks()
    def _validate_activation(self, record):
        phase = record.get('phase')
        require(type(phase) is str and phase in {p.value for p in Phase}, 'unknown activation phase')
        terminal = phase in ('CLEANING', 'DONE')
        # The child-observation digest marker is optional so that a journal written
        # before that digest was versioned still validates; when present it is
        # checked here and an unknown or malformed value fails closed.
        optional = {'observation_digest_version'} if 'observation_digest_version' in record else set()
        exact(record, FIELDS | {'activation'} | optional
              | ({'outcome', 'cleanup_entries'} if terminal else set()))
        observation_digest_version(record)
        require(type(record['schema_version']) is int and record['schema_version'] == 2
                and record['operation'] == 'activate' and record['kind'] == 'accp-active-txn',
                'invalid activation profile')
        transaction_id(record['transaction_id'])
        require(type(record['prepared']) is bool, 'invalid preparation state')
        prepared = record['prepared']
        require(phase != 'PREPARING' or not prepared, 'conflicting preparation state')
        require(phase not in ('PREPARED', 'APPLYING', 'COMMITTED') or prepared, 'unprepared phase')
        if terminal:
            require(record['outcome'] in ('committed', 'rolled_back'), 'invalid outcome')
            require(record['outcome'] != 'committed' or prepared, 'unprepared commit')
        for field, expected in self.bindings().items():
            require(record[field] == expected, 'activation binding mismatch: ' + field)
        all_identities = []
        for field in ('control_plane_identity', 'project_identity', 'base_identity'):
            validate_identity(record[field])
        # Checkout and project can legitimately be identical; transaction objects cannot.
        all_identities.extend(self._activation_identity_key(record[k]) for k in
                              ('control_plane_identity', 'project_identity', 'base_identity'))
        before = record['skills_before']
        absent = before == {'exists': False}
        if absent:
            exact(before, ('exists',)); require(before['exists'] is False, 'invalid absence')
        else:
            key = self._activation_identity_key(before)
            require(key not in all_identities, 'skills aliases authority'); all_identities.append(key)
        created = record['skills_created_identity']
        if created is not None:
            require(absent and prepared and phase not in ('PREPARING', 'PREPARED'), 'invalid skills creation')
            key = self._activation_identity_key(created)
            require(key not in all_identities, 'created skills identity alias'); all_identities.append(key)
        workspace = record['workspace_identity']
        require(not prepared or workspace is not None, 'prepared workspace missing')
        if workspace is not None:
            exact(workspace, ('root', 'old', 'new', 'discard'))
            for value in workspace.values():
                key = self._activation_identity_key(value)
                require(key not in all_identities, 'workspace identity alias'); all_identities.append(key)
        for prefix in ('old', 'new'):
            values = record[prefix + '_ids']; ids(values)
            require(values == sorted(values), 'activation IDs must be sorted')
            children = record[prefix + '_children']; exact(children, values)
            unprepared_seen = False
            for ident in values:
                value = children[ident]
                if value == {'prepared': False}:
                    exact(value, ('prepared',))
                    require(value['prepared'] is False and prefix == 'new' and not prepared,
                            'invalid unprepared child')
                    unprepared_seen = True
                else:
                    require(not unprepared_seen, 'non-prefix child preparation')
                    exact(value, ('identity', 'sha256', 'observation_sha256'))
                    self._activation_digest(value['sha256'])
                    self._activation_digest(value['observation_sha256'])
                    key = self._activation_identity_key(value['identity'])
                    require(key not in all_identities, 'activation object identity alias')
                    all_identities.append(key)
                    require(prefix == 'old' or workspace is not None, 'new child without workspace')
        require(not absent or not record['old_ids'], 'absent skills with old children')
        self._metadata_pair(record['old_manifest'], record['old_state'], record['old_ids'], True)
        self._metadata_pair(record['new_manifest'], record['new_state'], record['new_ids'], False)
        activation = record['activation']
        # An absent version marker means the legacy (version 1) unmanaged digest:
        # journals written before the version-2 stamp encoding predate the field.
        # Anything else is refused rather than guessed.
        require(type(activation) is dict
                and frozenset(activation) in (ACTIVATION_FIELDS_V1, ACTIVATION_FIELDS_V2),
                'unexpected/missing activation fields')
        require(unmanaged_digest_version(activation)
                in (activation_observation.UNMANAGED_DIGEST_V1,
                    activation_observation.UNMANAGED_DIGEST_V2),
                'unknown unmanaged digest version')
        require(activation['attempt_id'] == record['transaction_id'], 'attempt UUID mismatch')
        for key in ('context_sha256', 'unmanaged_sha256'): self._activation_digest(activation[key])
        mode = activation['skills_mode_before']
        require(mode is None if absent else type(mode) is int and 0 <= mode <= 4095,
                'invalid skills mode')
        exact(activation['old_metadata_identity'], ('manifest', 'state'))
        for key, value in activation['old_metadata_identity'].items():
            if record['old_' + key]['exists']:
                identity = self._activation_identity_key(value)
                require(identity not in all_identities, 'metadata identity alias')
                all_identities.append(identity)
            else: require(value is None, 'absent metadata identity')
        runtime = activation['runtime_binding']
        if record['new_ids']:
            binding.validate_runtime_binding(runtime)
            require(runtime['control_plane_path'] == str(self.checkout), 'foreign runtime binding')
            runtime_path = Path(runtime['runtime_path'])
            for boundary in (self.base, self.store):
                require(runtime_path != boundary and runtime_path not in boundary.parents
                        and boundary not in runtime_path.parents, 'runtime/activation authority overlap')
            for field in ('root_identity', 'vault_identity'):
                key = self._activation_identity_key(runtime[field])
                require(key not in all_identities, 'runtime/transaction identity alias')
                all_identities.append(key)
        else: require(runtime is None, 'empty activation has runtime binding')
        exact(activation['providers'], record['new_ids'])
        for provider in activation['providers'].values():
            exact(provider, ('candidate_sha256', 'evidence_sha256', 'lock_sha256',
                             'artifact_tree_sha256', 'invocation', 'projection'))
            for field in ('candidate_sha256', 'evidence_sha256', 'lock_sha256', 'artifact_tree_sha256'):
                self._activation_digest(provider[field])
            require(provider['invocation'] in ('explicit', 'implicit')
                    and provider['projection'] == binding.PROJECTION, 'unsupported invocation projection')
        if terminal: self._activation_cleanup_entries(record)
        self.workspace(record['transaction_id'])
        binding.canonical_json(record)  # bounded JSON domains, not a change to F03 encoding
        return record

    def _activation_cleanup_entries(self, record):
        entries = record['cleanup_entries']
        require(type(entries) is list and len(entries) <= MAX_CLEANUP_ENTRIES, 'cleanup count')
        committed = record['outcome'] == 'committed'
        children = record['old_children'] if committed else record['new_children']
        expected_ids = {ident for ident, value in children.items() if value != {'prepared': False}}
        table, aliases, identities, roots = {}, set(), set(), {}
        for entry in entries:
            require(type(entry) is dict and entry.get('type') in ('file', 'directory'), 'cleanup entry type')
            fields = {'area', 'id', 'relative', 'type', 'identity'}
            exact(entry, fields | ({'sha256', 'readonly'} if entry['type'] == 'file' else set()))
            ids([entry['id']]); area = entry['area']; relative = entry['relative']
            require(area in (('old',) if committed else ('new', 'discard'))
                    and entry['id'] in expected_ids, 'cleanup area/ID')
            binding.text(relative, 'cleanup relative path', 4096)
            require(0 < len(relative.encode('utf-8')) <= 4096
                    and '\\' not in relative, 'cleanup path')
            if relative == '.':
                require(entry['type'] == 'directory' and entry['id'] not in roots, 'duplicate cleanup root')
                require(entry['identity'] == children[entry['id']]['identity'], 'cleanup root identity')
                roots[entry['id']] = area
            else:
                for part in relative.split('/'):
                    normalized = unicodedata.normalize('NFKC', part)
                    require(part not in ('', '.', '..') and not part.endswith(('.', ' '))
                            and not any(ord(c) < 32 for c in part) and not re.search(r'[<>:"|?*]', part)
                            and normalized not in ('', '.', '..') and not normalized.endswith(('.', ' '))
                            and not re.search(r'[\\/<>:"|?*]', normalized)
                            and not DEVICE.fullmatch(normalized.split('.')[0]),
                            'unsafe cleanup component')
            key = (area, entry['id'], relative)
            alias = (area, entry['id'], unicodedata.normalize('NFKC', relative).casefold())
            identity = self._activation_identity_key(entry['identity'])
            require(key not in table and alias not in aliases and identity not in identities,
                    'duplicate cleanup object')
            table[key] = entry; aliases.add(alias); identities.add(identity)
            if entry['type'] == 'file':
                self._activation_digest(entry['sha256'])
                require(type(entry['readonly']) is bool, 'cleanup readonly type')
        require(set(roots) == expected_ids, 'cleanup roots incomplete')
        for (area, ident, relative) in table:
            if relative != '.':
                parent = relative.rsplit('/', 1)[0] if '/' in relative else '.'
                require(table.get((area, ident, parent), {}).get('type') == 'directory',
                        'cleanup ancestor missing')
        return table

    def _activation_locator(self, record):
        workspace = self.workspace(record['transaction_id'])
        names = self._activation_names(self.base)
        require(not any(name.startswith(('.skills-stage-', '.skills-backup-')) for name in names),
                'legacy activation residue')
        require(not any(name.startswith('.accp-txn-') and name != workspace.name for name in names),
                'foreign activation workspace')
        if os.path.lexists(self.locator):
            raw, _ = binding._read_file(self.locator, 16384)
            self.validate_locator(strict_json(raw, 16384), record)
        else:
            require((record['phase'] == 'PREPARING' and record['workspace_identity'] is None
                     and not os.path.lexists(workspace) and record['skills_created_identity'] is None)
                    or record['phase'] == 'DONE', 'missing activation locator')

    @binding_checks()
    def load_activation(self):
        """Read-only model loading. Does not enable recover/cleanup execution."""
        result = self._load_recovery(allow_cleanup=True, activation_model=True)
        if result is not None:
            raw, _ = binding._read_file(self.journal, MAX_JOURNAL)
            require(raw == self.serialize(result), 'activation authority drift')
        return result

    @staticmethod
    def _activation_order(values, alphabet):
        ranks = [alphabet.index(value) if value in alphabet else -1 for value in values]
        return -1 not in ranks and ranks == sorted(ranks)

    def _activation_cleanup_layout(self, record):
        """Validate partial deletion only against a complete frozen inventory."""
        table = self._activation_cleanup_entries(record)
        workspace = self.workspace(record['transaction_id'])
        allowed, remaining = {}, 0
        if record['workspace_identity'] is not None:
            for area, identity in record['workspace_identity'].items():
                path = workspace if area == 'root' else workspace / area
                allowed[path] = None
                if os.path.lexists(path):
                    binding.plain_path(path, True); binding._streams(path)
                    verify_directory(path, identity)
        else:
            require(not table and not os.path.lexists(workspace), 'unregistered cleanup workspace')
        for (area, ident, relative), entry in table.items():
            root = self.child_path(record['transaction_id'], area, ident)
            path = root if relative == '.' else root.joinpath(*relative.split('/'))
            plain_path(path)
            require(path == root or root.resolve() in path.resolve().parents, 'cleanup escape')
            allowed[path] = entry
            if not os.path.lexists(path): continue
            remaining += 1
            if entry['type'] == 'directory':
                binding.plain_path(path, True); binding._streams(path)
                verify_directory(path, entry['identity'])
            else:
                raw, stamp = binding._read_file(path, binding.MAX_FILE)
                require({'device': str(stamp[0]), 'inode': str(stamp[1])} == entry['identity']
                        and hashlib.sha256(raw).hexdigest() == entry['sha256'], 'cleanup file mismatch')
                require(entry['readonly'] or not getattr(path.lstat(), 'st_file_attributes', 0) & 1,
                        'cleanup readonly changed')
        def scan(path):
            require(path in allowed, 'unlisted activation cleanup object')
            if path.is_dir():
                for child in path.iterdir(): scan(child)
        if os.path.lexists(workspace): scan(workspace)
        require(record['phase'] != 'DONE' or not os.path.lexists(workspace), 'DONE workspace remains')
        return remaining

    @binding_checks()
    def classify_activation(self):
        """A1 read-only classification under an already held lifecycle lock.

        Never resumes forward admission, changes a phase, repairs a record,
        creates a lock, or mutates children. Execution uses separate guarded methods.
        """
        self._assert_locked()
        record = self.load_activation()
        require(record is not None, 'activation authority missing')
        raw = self.serialize(record)
        phase = record['phase']; terminal = phase in ('CLEANING', 'DONE')
        a = record['activation']; skills = self.base / 'skills'
        # Digest encodings are selected by the record's own versions, never by
        # which computation happens to succeed: a version-2 mismatch must not fall
        # back. The two domains are versioned independently -- the child
        # observation version is not inferred from the unmanaged one.
        version = unmanaged_digest_version(a)
        observation_version = observation_digest_version(record)
        rows = activation_observation.tree_observation(skills)
        present = rows is not None
        absent_before = record['skills_before'] == {'exists': False}
        if present:
            expected = record['skills_created_identity'] if absent_before else record['skills_before']
            require(expected is not None and rows[0]['identity'] == expected, 'unregistered/replaced skills')
            if not absent_before:
                require(rows[0]['mode'] == a['skills_mode_before'], 'skills mode changed')
        else:
            require(absent_before, 'original skills disappeared')
            require(record['skills_created_identity'] is None or phase in ('ROLLING_BACK', 'ROLLED_BACK')
                    or (terminal and record['outcome'] == 'rolled_back'), 'created skills disappeared')
        union = set(record['old_ids']) | set(record['new_ids'])
        names = self._activation_names(skills)
        for name in names:
            alias = unicodedata.normalize('NFKC', name).casefold()
            require(alias not in union or name == alias, 'managed child alias')
        require(activation_observation.unmanaged_observation(rows, union, version) == a['unmanaged_sha256'],
                'unmanaged state changed')
        metadata = {key: self._activation_metadata(self.base / name) for key, name in
                    (('manifest', 'install-manifest.json'), ('state', 'active-state.json'))}
        old_bytes = tuple(snapshot_bytes(record['old_' + key]) for key in ('manifest', 'state'))
        new_bytes = tuple(snapshot_bytes(record['new_' + key]) for key in ('manifest', 'state'))
        actual = tuple(snapshot_bytes(metadata[key][0]) for key in ('manifest', 'state'))
        old_meta = actual == old_bytes
        new_meta = actual == new_bytes
        require(actual in (old_bytes, (new_bytes[0], old_bytes[1]), new_bytes), 'unreachable metadata pair')
        workspace = self.workspace(record['transaction_id'])
        outcome = record.get('outcome') if terminal else ('committed' if phase == 'COMMITTED' else 'rolled_back')
        if terminal:
            live_children = record['new_children'] if outcome == 'committed' else record['old_children']
            require(new_meta if outcome == 'committed' else old_meta, 'terminal metadata mismatch')
            require(present if outcome == 'committed' or not absent_before else not present,
                    'terminal skills existence mismatch')
            require(names & union == set(live_children), 'terminal live IDs mismatch')
            for ident, expected in live_children.items():
                require(self._activation_child(skills / ident, observation_version) == expected,
                        'terminal live object changed')
            remaining = self._activation_cleanup_layout(record)
            result = dict(phase=phase, outcome=outcome, cleanup_remaining=remaining)
        else:
            if record['workspace_identity'] is None:
                require(not os.path.lexists(workspace), 'unregistered workspace')
            else:
                require(self._activation_names(workspace) == {'old', 'new', 'discard'}, 'workspace contents')
                for area, identity in record['workspace_identity'].items():
                    path = workspace if area == 'root' else workspace / area
                    binding.plain_path(path, True); binding._streams(path); verify_directory(path, identity)
            positions = {'old': {}, 'new': {}}
            # Enumerate every fixed-area object once; a same-ID live object must
            # match exactly one recorded generation, including its identity.
            areas = {'LIVE': skills, 'BACKUP': workspace / 'old',
                     'STAGED': workspace / 'new', 'DISCARD': workspace / 'discard'}
            area_rows = {area: activation_observation.tree_observation(path) for area, path in areas.items()}
            inventories = {area: self._activation_names(path) for area, path in areas.items()}
            for area, path in areas.items():
                for ident in inventories[area]:
                    if area == 'LIVE' and ident not in union: continue
                    require(ident in union, 'unrecorded workspace child')
                    actual_child = self._activation_child(path / ident, observation_version)
                    matches = []
                    for generation, legal in (('old', ('LIVE', 'BACKUP')), ('new', ('LIVE', 'STAGED', 'DISCARD'))):
                        expected = record[generation + '_children'].get(ident)
                        if area in legal and expected == actual_child: matches.append(generation)
                    require(len(matches) == 1, 'foreign/ambiguous activation object')
                    generation = matches[0]
                    require(ident not in positions[generation], 'duplicate activation object')
                    positions[generation][ident] = area
            for generation in ('old', 'new'):
                for ident, expected in record[generation + '_children'].items():
                    if expected == {'prepared': False}:
                        require(ident not in positions[generation], 'unregistered new object')
                        positions[generation][ident] = 'UNPREPARED'
                    else: require(ident in positions[generation], 'missing activation object')
            old = [positions['old'][ident] for ident in record['old_ids']]
            new = [positions['new'][ident] for ident in record['new_ids']]
            all_old_live = all(p == 'LIVE' for p in old)
            all_old_backup = all(p == 'BACKUP' for p in old)
            all_new_live = all(p == 'LIVE' for p in new)
            staged = all(p in ('STAGED', 'UNPREPARED') for p in new)
            require(self._activation_order(old, ('BACKUP', 'LIVE')), 'old move order conflict')
            if phase in ('PREPARING', 'PREPARED') or not record['prepared']:
                require(all_old_live and staged and old_meta, 'preparation changed live generation')
                require(record['skills_created_identity'] is None and present != absent_before,
                        'preparation skills state')
                for key in ('manifest', 'state'):
                    require(metadata[key][1] == a['old_metadata_identity'][key], 'old metadata replaced')
            elif phase == 'APPLYING':
                require(self._activation_order(new, ('LIVE', 'STAGED')), 'new move order conflict')
                require(all_old_backup or staged, 'new move before old moves complete')
                require(old_meta or (all_old_backup and all_new_live and present), 'early metadata switch')
                for index, key in enumerate(('manifest', 'state')):
                    if actual[index] == old_bytes[index] and old_bytes[index] != new_bytes[index]:
                        require(metadata[key][1] == a['old_metadata_identity'][key], 'unswitched metadata replaced')
            elif phase == 'ROLLING_BACK':
                require(self._activation_order(new, ('LIVE', 'DISCARD', 'STAGED')), 'rollback new order conflict')
                require(not any(p == 'LIVE' for p in new) or all_old_backup, 'old restored before new evacuation')
                require(not any(p == 'STAGED' for p in new) or old_meta, 'metadata advanced before all new moves')
                require(present or (all_old_live and old_meta), 'skills removed before restoration')
            elif phase == 'COMMITTED':
                require(present and all_old_backup and all_new_live and new_meta, 'commit layout conflict')
            elif phase == 'ROLLED_BACK':
                require(all_old_live and all(p in ('STAGED', 'DISCARD', 'UNPREPARED') for p in new)
                        and old_meta and present != absent_before, 'rollback incomplete')
                require(self._activation_order(new, ('DISCARD', 'STAGED', 'UNPREPARED')), 'rollback cut conflict')
            if not present:
                require(not names and (old_meta or phase == 'ROLLING_BACK'), 'metadata without skills')
            result = dict(phase=phase, old_positions=positions['old'], new_positions=positions['new'],
                          action='retain' if phase in ('COMMITTED', 'ROLLED_BACK') else 'rollback')
            require(all(self._activation_names(path) == inventories[area] for area, path in areas.items()),
                    'activation layout drift during classification')
            require(all(activation_observation.tree_observation(path) == area_rows[area]
                        for area, path in areas.items()), 'workspace drift during classification')
        require(activation_observation.tree_observation(skills) == rows, 'live drift during classification')
        for key, name in (('manifest', 'install-manifest.json'), ('state', 'active-state.json')):
            require(self._activation_metadata(self.base / name) == metadata[key], 'metadata drift during classification')
        require(self.load_activation() == record and self._read(self.journal, MAX_JOURNAL) == raw,
                'authority drift during classification')
        self._assert_locked()
        return result

    def bindings(self):
        verify_directory(self.checkout, self.checkout_identity)
        verify_directory(self.project, self.project_identity)
        plain_path(self.store)
        return {'control_plane_path': str(self.checkout),
                'control_plane_identity': self.checkout_identity,
                'project_path': str(self.project), 'project_identity': self.project_identity,
                'scope': self.scope, 'base_path': str(self.base),
                'base_identity': directory_identity(self.base)}

    def workspace(self, txn):
        path = self.base / ('.accp-txn-' + transaction_id(txn).hex)
        plain_path(path)
        require(path.resolve().parent == self.base.resolve(), 'workspace escape')
        return path

    def child_path(self, txn, area, child_id):
        require(area in ('old', 'new', 'discard'), 'invalid workspace area')
        ids([child_id])
        parent = self.workspace(txn) / area
        child = parent / child_id
        plain_path(child)
        require(child.resolve().parent == parent.resolve(), 'child escape')
        return child  # A derived name is NOT deletion authority.

    def _metadata_pair(self, manifest, state, expected_ids, allow_absent):
        im, active = snapshot_bytes(manifest), snapshot_bytes(state)
        if im is None or active is None:
            require(allow_absent and im is None and active is None and not expected_ids,
                    'missing/inconsistent metadata pair')
            return
        im, active = strict_json(im, MAX_METADATA), strict_json(active, MAX_METADATA)
        for record in (im, active):
            require(type(record.get('schema_version')) is int and record['schema_version'] == 1,
                    'invalid metadata schema')
            value = record.get('control_plane_path')
            require(type(value) is str and canonical(value) == self.checkout, 'foreign metadata')
        # Legacy F01 metadata uses native spelling, not normcase journal spelling.
        value = im.get('project')
        require(im.get('scope') == self.scope and type(value) is str
                and canonical(value) == self.project, 'foreign manifest binding')
        for value in (im.get('managed_ids'), active.get('active_ids')):
            ids(value)
            require(set(value) == set(expected_ids), 'metadata inventory mismatch')
        if 'mode' in im and 'mode' in active:
            require(im['mode'] == active['mode'], 'metadata mode mismatch')

    def validate(self, record):
        require(type(record) is dict, 'journal object required')
        if type(record.get('schema_version')) is int and record['schema_version'] == 2:
            return self._validate_activation(record)
        require(type(record.get('phase')) is str, 'phase string required')
        try:
            phase = Phase(record.get('phase'))
        except (ValueError, TypeError) as exc:
            raise JournalError('unknown phase') from exc
        terminal = phase in (Phase.CLEANING, Phase.DONE)
        extra = {'outcome'} if terminal else set()
        if terminal and 'cleanup_entries' in record:
            extra.add('cleanup_entries')
        exact(record, FIELDS | extra)
        require(type(record['schema_version']) is int and record['schema_version'] == 1,
                'invalid journal schema')
        require(record['kind'] == 'accp-active-txn', 'invalid journal kind')
        transaction_id(record['transaction_id'])
        require(record['operation'] in ('activate', 'deactivate'), 'invalid operation')
        require(type(record['prepared']) is bool, 'invalid preparation state')
        prepared = record['prepared']
        if phase == Phase.PREPARING:
            require(not prepared, 'conflicting preparation state')
        if phase in (Phase.PREPARED, Phase.APPLYING, Phase.COMMITTED):
            require(prepared, 'unprepared forward phase')
        if terminal:
            require(record['outcome'] in ('committed', 'rolled_back'), 'invalid outcome')
            require(record['outcome'] != 'committed' or prepared, 'unprepared commit')
        for field, value in self.bindings().items():
            require(record[field] == value, 'journal binding mismatch: ' + field)
        for field in ('control_plane_identity', 'project_identity', 'base_identity'):
            validate_identity(record[field])
        before = record['skills_before']
        if before != {'exists': False}:
            validate_identity(before)
        else:
            exact(before, ('exists',))
            require(before['exists'] is False, 'invalid absent identity')
        created = record['skills_created_identity']
        if created is not None:
            require(before == {'exists': False}, 'conflicting skills identities')
            validate_identity(created)
        workspace = record['workspace_identity']
        if workspace is None:
            require(not prepared, 'prepared workspace identity missing')
        else:
            exact(workspace, ('root', 'old', 'new', 'discard'))
            for value in workspace.values():
                validate_identity(value)
        for prefix in ('old', 'new'):
            inventory = record[prefix + '_ids']
            ids(inventory)
            children = record[prefix + '_children']
            exact(children, inventory)
            for value in children.values():
                if value == {'prepared': False}:
                    require(not prepared and value['prepared'] is False, 'unprepared child')
                else:
                    exact(value, ('identity', 'sha256'))
                    validate_identity(value['identity'])
                    require(type(value['sha256']) is str and DIGEST.fullmatch(value['sha256']),
                            'invalid child digest')
        require(record['operation'] != 'deactivate' or not record['new_ids'],
                'deactivate cannot install children')
        require(before != {'exists': False} or not record['old_ids'], 'absent old skills with IDs')
        self._metadata_pair(record['old_manifest'], record['old_state'], record['old_ids'], True)
        self._metadata_pair(record['new_manifest'], record['new_state'], record['new_ids'], False)
        if 'cleanup_entries' in record:
            self._validate_cleanup_entries(record)
        self.workspace(record['transaction_id'])
        return record

    def serialize(self, record):
        self.validate(record)
        try:
            raw = (json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False,
                              separators=(',', ':')) + '\n').encode('utf-8')
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise JournalError('unserializable journal') from exc
        require(len(raw) <= MAX_JOURNAL, 'oversized journal')
        return raw

    def parse(self, raw):
        return self.validate(strict_json(raw))

    def locator_record(self, record):
        self.validate(record)
        return {'schema_version': 1, 'transaction_id': record['transaction_id'],
                'control_plane_path': str(self.checkout), 'base_path': str(self.base),
                'key': self.key}

    def validate_locator(self, locator, journal):
        expected = self.locator_record(journal)
        exact(locator, expected)
        require(type(locator['schema_version']) is int and locator == expected,
                'foreign or mismatched locator')

    @staticmethod
    def _read(path, limit):
        plain_path(path)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
                'unsafe/oversized record file')
        with path.open('rb') as stream:
            raw = stream.read(limit + 1)
        require(len(raw) <= limit, 'oversized record file')
        return raw

    def _reader_record(self):
        """External authority first, including absent local indicators. No writes."""
        self._no_pending()
        plain_path(self.legacy_lock)
        require(not os.path.lexists(self.legacy_lock), 'legacy lock requires inspection')
        names = self._activation_names(self.base)
        require(not any(n.startswith(('.skills-stage-', '.skills-backup-')) for n in names),
                'legacy activation residue requires inspection')
        record = (self.load_activation() if self._has_activation_recovery()
                  else self._load_recovery(allow_cleanup=True))
        if record is None:
            self.require_no_transaction()
        else:
            # V1's loader predates the explicit foreign-workspace check.
            require(not any(n.startswith('.accp-txn-') and
                            n != self.workspace(record['transaction_id']).name for n in names),
                    'foreign transaction workspace')
        return record

    @contextmanager
    def reader_session(self):
        """Never enroll, create a lock/store, or derive safety from local absence."""
        record = self._reader_record()
        plain_path(self.lock_path)
        if not os.path.lexists(self.lock_path):
            require(record is None, 'retained authority without lifecycle lock')
            yield False
            return
        binding.plain_path(self.lock_path, False)
        binding._streams(self.lock_path)
        with self.lifecycle_lock(create=False):
            self._reader_record()
            yield True

    def reader_snapshot(self, preflight, path_preflight):
        """Locked classification only; returned observations grant no execution rights."""
        self._assert_locked()
        record = self._reader_record()
        paths = (self.base, self.base/'skills', self.base/'install-manifest.json',
                 self.base/'active-state.json', self.legacy_lock)
        live = activation_observation.live_observation(paths)
        evidence = tuple(activation_observation.file_observation(p, MAX_JOURNAL)
                         for p in (self.journal, self.locator))
        workspace = None if record is None else self.workspace(record['transaction_id'])
        tree = None if workspace is None else activation_observation.tree_observation(workspace)
        if record is None:
            managed = sorted(preflight()['managed_ids'])
            snap = self.activation_snapshot(managed, [])
            lifecycle, outcome, basis = 'SETTLED', None, 'current_metadata'
            metadata = (snap['old_manifest'], snap['old_state'])
        else:
            if record['schema_version'] == 2:
                self.classify_activation()
            elif record['phase'] in ('CLEANING', 'DONE'):
                self._verify_cleanup(record, path_preflight)
            else:
                self._classify_recovery(record, path_preflight)
            phase = record['phase']
            outcome = record.get('outcome', 'committed' if phase == 'COMMITTED' else
                                 'rolled_back' if phase == 'ROLLED_BACK' else None)
            lifecycle = ('FINALIZATION_REQUIRED' if phase in ('CLEANING', 'DONE') else
                         'TERMINAL_RETAINED' if outcome else 'RECOVERY_REQUIRED')
            prefix = 'new_' if outcome == 'committed' else 'old_'
            managed = record['new_ids'] if outcome == 'committed' else record['old_ids']
            metadata = (record[prefix+'manifest'], record[prefix+'state'])
            basis = 'retained_' + outcome if outcome else None
        generation = None
        if lifecycle != 'RECOVERY_REQUIRED':
            generation = dict(basis=basis, managed_ids=list(managed),
                skills_exists=live['tree'] is not None,
                install_manifest=None if not metadata[0]['exists'] else strict_json(snapshot_bytes(metadata[0]), MAX_METADATA),
                active_state=None if not metadata[1]['exists'] else strict_json(snapshot_bytes(metadata[1]), MAX_METADATA))
        require(activation_observation.live_observation(paths) == live, 'reader live state drift')
        require(tuple(activation_observation.file_observation(p, MAX_JOURNAL)
                      for p in (self.journal, self.locator)) == evidence, 'reader evidence drift')
        require(workspace is None or activation_observation.tree_observation(workspace) == tree,
                'reader workspace drift')
        require(self._reader_record() == record, 'reader authority drift')
        self._assert_locked()
        # Fingerprint is call-local only, never serialized or consumed by writers.
        return dict(lifecycle=lifecycle, current_generation=generation, transaction=None if record is None else
            dict(schema_version=record['schema_version'], operation=record['operation'],
                 transaction_id=record['transaction_id'], phase=record['phase'], outcome=outcome,
                 old_intent_ids=record['old_ids'], new_intent_ids=record['new_ids'])), (record, live, evidence, tree)

    @staticmethod
    def reader_exit(report):
        if report['preview'] is not None:
            return 2 if report['preview']['admission'] == 'blocked' else 0
        return 0 if report['lifecycle'] in ('SETTLED', 'TERMINAL_RETAINED', 'FINALIZATION_REQUIRED') else 2

    def reader_report(self, preflight, path_preflight, *, operation='status', admission=None):
        """The only public lifecycle reporting boundary; no fallback to raw metadata."""
        require(operation in ('status', 'activate', 'deactivate', 'recover', 'cleanup'), 'unknown reader operation')
        report = dict(schema_version=1, report_kind='active_set_status' if operation == 'status' else operation+'_preview',
            observed_at=None, project=str(self.project), scope=self.scope, base=str(self.base),
            consistency='unavailable', lifecycle='UNKNOWN', transaction=None, current_generation=None,
            preview=None if operation == 'status' else dict(operation=operation, admission='blocked', action=None,
                                                          reservation=False),
            reason_code='VALIDATION_FAILED', detail='', admission_authority=False)
        try:
            with self.reader_session() as coordinated:
                if not coordinated:
                    report.update(consistency='uncoordinated', lifecycle='UNCOORDINATED',
                                  reason_code='NO_EXISTING_LIFECYCLE_LOCK',
                                  detail='existing base is unenrolled' if self.base.exists() else 'base is absent')
                else:
                    view, before = self.reader_snapshot(preflight, path_preflight)
                    report.update(view, consistency='locked', reason_code='VALIDATED')
                    record = before[0]
                    if operation != 'status':
                        action = None
                        if operation == 'activate' and record is None:
                            require(callable(admission), 'activation preview admission required')
                            report['preview'].update(admission(self))
                            action = 'activation_inputs_validated'
                        elif record is None:
                            action = 'deactivate' if operation == 'deactivate' else 'noop'
                        elif operation == 'deactivate' and record['schema_version'] == 1 and record['phase'] == 'COMMITTED':
                            preflight(); self._verify_deactivated(record)
                            action = 'noop_committed'
                        elif operation == 'recover' and record['phase'] not in ('CLEANING', 'DONE'):
                            action = 'retain' if record['phase'] in ('COMMITTED', 'ROLLED_BACK') else 'rollback'
                        elif operation == 'cleanup' and record['phase'] in ('COMMITTED', 'ROLLED_BACK', 'CLEANING', 'DONE'):
                            if record['phase'] in ('COMMITTED', 'ROLLED_BACK'):
                                entries = (self._capture_activation_cleanup(record) if record['schema_version'] == 2
                                           else self._capture_cleanup(record))
                                self.serialize(dict(record, phase='CLEANING',
                                    outcome='committed' if record['phase'] == 'COMMITTED' else 'rolled_back', cleanup_entries=entries))
                                report['preview']['cleanup_entries'] = len(entries)
                            else:
                                report['preview']['cleanup_entries'] = len(record['cleanup_entries'])
                            action = 'finalize'
                        report['preview'].update(action=action, admission='validated_inputs' if action else 'blocked')
                        if action is None: report['reason_code'] = 'TRANSACTION_BLOCKS_OPERATION'
                    _, after = self.reader_snapshot(preflight, path_preflight)
                    require(before == after, 'reader snapshot drift before report')
                report['observed_at'] = datetime.now(timezone.utc).isoformat()
                raw = json.dumps(report, ensure_ascii=False, allow_nan=False).encode('utf-8')
                require(len(raw) <= MAX_JOURNAL, 'reader report size limit')
                result = strict_json(raw)  # detach while still holding ownership
            return result  # a release failure must not publish the successful snapshot
        except (LifecycleUnavailable, OSError, JournalError, binding.BindingError, RuntimeError,
                json.JSONDecodeError, UnicodeError) as exc:
            report.update(lifecycle='BUSY_OR_UNAVAILABLE' if isinstance(exc, LifecycleUnavailable) else 'UNKNOWN',
                          consistency='unavailable', transaction=None, current_generation=None,
                          reason_code='LOCK_BUSY_OR_UNAVAILABLE' if isinstance(exc, LifecycleUnavailable) else 'VALIDATION_FAILED',
                          detail=str(exc)[:1024], observed_at=datetime.now(timezone.utc).isoformat())
            if operation != 'status':
                report['preview'] = dict(operation=operation, admission='blocked', action=None, reservation=False)
            return report

    def inspect(self):
        """Internal presence hint, NOT installed-state health; use reader_report.

        Never promotes a pending file to authority. Writer semantics are unchanged.
        """
        try:
            verify_directory(self.checkout, self.checkout_identity)
            verify_directory(self.project, self.project_identity)
            for path in (self.journal, self.locator, self.journal_pending, self.locator_pending):
                plain_path(path)
            if self.journal_pending.exists() or self.locator_pending.exists():
                return Inspection(RecordState.INTERRUPTED, 'pending publication; inspection required')
            if not self.journal.exists():
                if self.locator.exists():
                    return Inspection(RecordState.CONFLICT, 'locator has no external authority')
                return Inspection(RecordState.ABSENT, 'no transaction records')
            journal = self.parse(self._read(self.journal, MAX_JOURNAL))
            if not self.locator.exists():
                state = RecordState.INTERRUPTED if journal['phase'] in ('PREPARING', 'DONE') else RecordState.CONFLICT
                return Inspection(state, 'journal without locator; no automatic action')
            self.validate_locator(strict_json(self._read(self.locator, 16384), 16384), journal)
            return Inspection(RecordState.PENDING, 'valid bound records; lifecycle verification still required')
        except (JournalError, OSError) as exc:
            return Inspection(RecordState.CONFLICT, str(exc))
