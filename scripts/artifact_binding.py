"""F06 v1 binding primitives. No resolver, CLI admission, fetch or publication.

Expected digests come from reviewed evidence, never from a writable Vault.
Callers must supply validated F02 authority and hold the existing locks in M2/M3.
Identity checks detect drift; they do not exclude a concurrent hostile writer.
"""
from __future__ import annotations

import configparser
import ctypes
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import threading
import unicodedata
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime

MAX_RECORD = 8 * 1024 * 1024
MAX_MANIFEST = 64 * 1024
MAX_ENTRY = 256 * 1024
MAX_DEPTH = 32
MAX_ENTRIES = 10_000
MAX_FILE = 32 * 1024 * 1024
MAX_PAYLOAD = 256 * 1024 * 1024
MAX_PATH = 1024
# Two distinct mode sets, deliberately not one. The parser must recognise every
# canonical Git mode so that a tree can be read at all, while the artifact may only
# ever contain trees, regular files and executables. Keeping them separate stops a
# later refactor from widening "a symlink sibling outside the selected path is
# ignored" into "a symlink inside the artifact is accepted".
GIT_MODE_TREE = b'40000'
GIT_MODE_FILE = b'100644'
GIT_MODE_EXECUTABLE = b'100755'
GIT_MODE_SYMLINK = b'120000'
GIT_MODE_GITLINK = b'160000'
PARSED_GIT_MODES = (GIT_MODE_TREE, GIT_MODE_FILE, GIT_MODE_EXECUTABLE,
                    GIT_MODE_SYMLINK, GIT_MODE_GITLINK)
ARTIFACT_GIT_MODES = (GIT_MODE_TREE, GIT_MODE_FILE, GIT_MODE_EXECUTABLE)
MANIFEST = '.accp-vault-manifest.json'
PROJECTION = 'accp-invocation-v1'
LABELS = frozenset(('accp-catalog-v1', 'accp-source-tree-v1',
                    'accp-artifact-tree-v1', 'accp-candidate-v1',
                    'accp-context-v1', 'accp-lock-record-v1', 'accp-origin-v1'))
ID_PATTERN = r'(?!con(?:\.|$)|prn(?:\.|$)|aux(?:\.|$)|nul(?:\.|$)|com[1-9](?:\.|$)|lpt[1-9](?:\.|$))[a-z0-9](?:[a-z0-9._-]{0,94}[a-z0-9_-])?'
CANDIDATE_FIELDS = frozenset(('binding_version', 'source_id', 'catalog_sha256',
    'origin', 'commit', 'source_tree_oid', 'deploy_path', 'source_tree_sha256',
    'artifact_tree_sha256', 'invocation', 'projection'))
EVIDENCE_FIELDS = frozenset(('schema_version', 'candidate', 'candidate_sha256',
    'source_inventory', 'artifact_inventory', 'status', 'reviewer', 'reviewed_at',
    'notes', 'executable_surface'))
LOCK_FIELDS = frozenset(('repo', 'commit', 'deploy_path', 'evidence',
                         'evidence_sha256', 'approval'))
RUNTIME_FIELDS = frozenset(('runtime_id', 'runtime_path', 'control_plane_path',
                           'principal', 'root_identity', 'vault_identity'))
VAULT_FIELDS = frozenset(('schema_version', 'source_id', 'candidate_sha256',
    'evidence_sha256', 'artifact_tree_sha256', 'invocation', 'projection',
    'runtime_binding', 'materialized_at'))


class BindingError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise BindingError(message)


def exact(value, fields, name):
    require(type(value) is dict and set(value) == set(fields), f'{name}: unexpected/missing fields')
    return value


def text(value, name, limit=MAX_PATH, empty=False):
    require(type(value) is str and (empty or bool(value)), f'{name}: string required')
    require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), f'{name}: surrogate')
    require(len(value.encode('utf-8')) <= limit, f'{name}: too long')
    return value


def _json_value(value, depth=0):
    require(depth <= MAX_DEPTH, 'JSON depth limit')
    if type(value) is dict:
        for key, child in value.items():
            text(key, 'JSON key', MAX_RECORD, empty=True)
            _json_value(child, depth + 1)
    elif type(value) is list:
        for child in value:
            _json_value(child, depth + 1)
    elif type(value) is str:
        text(value, 'JSON string', MAX_RECORD, empty=True)
    elif type(value) is int:
        require(-(2**63) <= value < 2**63, 'JSON integer range')
    else:
        require(value is None or type(value) is bool, 'unsupported JSON value')


def canonical_json(value):
    _json_value(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def parse_json(data, limit=MAX_RECORD, canonical=False):
    require(type(limit) is int and 0 <= limit <= MAX_RECORD and type(canonical) is bool,
            'invalid parser bounds/options')
    require(type(data) is bytes and len(data) <= limit, 'JSON byte limit/type')
    require(not data.startswith(b'\xef\xbb\xbf'), 'JSON BOM refused')
    try:
        source = data.decode('utf-8', errors='strict')
    except UnicodeDecodeError as ex:
        raise BindingError('invalid UTF-8') from ex
    # Bound structural depth before json.loads allocates nested containers.
    depth = 0
    quoted = escaped = False
    for c in source:
        if quoted:
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == '"':
                quoted = False
        elif c == '"':
            quoted = True
        elif c in '[{':
            depth += 1
            require(depth <= MAX_DEPTH, 'JSON depth limit')
        elif c in ']}':
            depth -= 1
            require(depth >= 0, 'malformed JSON nesting')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def no_number(value):
        raise BindingError('float/nonfinite JSON value refused')

    try:
        value = json.loads(source, object_pairs_hook=unique,
                           parse_float=no_number, parse_constant=no_number)
    except (ValueError, RecursionError) as ex:
        raise BindingError('malformed JSON') from ex
    _json_value(value)
    if canonical:
        require(data == canonical_json(value) + b'\n', 'noncanonical record bytes')
    return value


def digest(label, value):
    require(type(label) is str and label in LABELS, 'unknown digest domain')
    return hashlib.sha256(label.encode('ascii') + b'\0' + canonical_json(value)).hexdigest()


def hex_digest(value, length=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value),
            'invalid exact digest/object ID')
    return value


def provider_id(value):
    require(type(value) is str and re.fullmatch(ID_PATTERN, value), 'invalid provider ID')
    return value


def canonical_relative_path(value, allow_dot=False):
    require(type(allow_dot) is bool, 'path option must be boolean')
    text(value, 'relative path')
    if value == '.' and allow_dot:
        return value
    parts = value.split('/')
    require(len(parts) <= MAX_DEPTH, 'path depth limit')
    for part in parts:
        require(part not in ('', '.', '..'), 'noncanonical relative path')
        require(not any(ord(c) < 32 or ord(c) == 127 or c in '\\:<>"|?*' for c in part),
                'unsafe path component')
        require(not part.endswith(('.', ' ')), 'path alias')
        require(not re.fullmatch(r'(con|prn|aux|nul|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\..*)?',
                                unicodedata.normalize('NFKC', part), re.I),
                'reserved Windows path')
        require(part.casefold() not in ('.git', MANIFEST), 'reserved payload metadata')
    return value


def _absolute(path):
    raw = os.fspath(path)
    text(raw, 'absolute path', 32768)
    require(not raw.startswith(('\\\\', '//')) and not any(ord(c) < 32 or ord(c) == 127 for c in raw),
            'UNC/device path refused')
    if os.name == 'nt':
        require(re.match(r'^[A-Za-z]:[\\/]', raw), 'absolute local drive path required')
        tail = raw[3:].replace('\\', '/')
    else:
        require(raw.startswith('/') and '\\' not in raw and ':' not in raw,
                'absolute local path required')
        tail = raw[1:]
    if tail:
        # Absolute control directories may contain .git but never path aliases.
        for part in tail.split('/'):
            require(part not in ('', '.', '..') and not part.endswith(('.', ' ')), 'absolute path alias')
            require(not any(c in ':<>"|?*' for c in part), 'unsafe absolute path')
            require(not re.fullmatch(r'(con|prn|aux|nul|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\..*)?',
                                    unicodedata.normalize('NFKC', part), re.I),
                    'reserved absolute path')
    return pathlib.Path(raw)


def _identity(info):
    """The part of a stamp that the path APIs and the fd APIs report identically.

    st_dev/st_ino/st_mode/st_nlink/st_size/st_mtime_ns agree between lstat()/stat()
    and fstat() on every platform measured. st_ctime_ns does NOT: on Windows with
    CPython 3.12+ the path APIs expose CreationTime (GetFileAttributesEx) while the
    fd APIs expose ChangeTime (GetFileInformationByHandleEx). Comparing that field
    across the two APIs compares two different quantities, so it is excluded here
    and compared only within a single API (see _read_file).
    """
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns)


def _stamp(info):
    require(info.st_dev > 0 and info.st_ino > 0, 'unavailable filesystem identity')
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


# Serialized filesystem-stamp observation (version 2).
#
# _stamp() holds seven raw integers, and four of them cannot be assumed to fit the
# signed 64-bit integer range that canonical_json() accepts:
#
#   * st_dev and st_ino are filesystem identities. Windows reports a volume-derived
#     device and a 64-bit NTFS file index, both unsigned, so values at or above
#     2**63 occur in practice -- observed on CI runners, where the same commit
#     passes or fails depending on how the runner volume was provisioned.
#   * st_mtime_ns and st_ctime_ns are epoch-nanosecond values, and a file may carry
#     one beyond 2**64-1 as well: os.utime() accepts such a timestamp on NTFS today.
#     They are signed and must NOT be bounded by uint64.
#
# Those four positions are serialized as canonical decimal strings, which carry no
# range restriction. st_mode, st_nlink and st_size stay integers: mode is bounded by
# 16 bits, a plain file is required to have nlink == 1, and size is bounded by
# MAX_FILE / MAX_PAYLOAD.
#
# The identity text form matches the existing filesystem identity contract in
# validate_identity() below: canonical decimal, ASCII digits, no sign and no leading
# zero. Timestamps use the same rule but allow a leading '-' because the
# epoch-nanosecond model is signed.
IDENTITY_TEXT = re.compile(r'[1-9][0-9]{0,39}\Z')
TIMESTAMP_TEXT = re.compile(r'(?:0|-?[1-9][0-9]{0,39})\Z')


def identity_text(value, name='filesystem identity'):
    """Canonical decimal text for a positive filesystem identity field."""
    require(type(value) is int and value > 0, f'{name}: positive integer required')
    text = str(value)
    require(IDENTITY_TEXT.match(text) is not None and str(int(text)) == text,
            f'{name}: not canonical decimal text')
    return text


def timestamp_text(value, name='filesystem timestamp'):
    """Canonical signed decimal text for an epoch-nanosecond field.

    No upper bound is imposed: a legal timestamp may exceed 2**64-1 (see above).
    """
    require(type(value) is int, f'{name}: integer required')
    text = str(value)
    require(TIMESTAMP_TEXT.match(text) is not None and str(int(text)) == text,
            f'{name}: not canonical decimal text')
    return text


def observed_stamp(stamp):
    """_stamp() as canonical, JSON-safe observation values (version 2)."""
    require(type(stamp) is tuple and len(stamp) == 7, 'filesystem stamp shape')
    return [identity_text(stamp[0], 'device identity'),
            identity_text(stamp[1], 'inode identity'),
            stamp[2], stamp[3], stamp[4],
            timestamp_text(stamp[5], 'modification time'),
            timestamp_text(stamp[6], 'change time')]


def parse_canonical_text(pattern, text, name):
    """Strictly parse canonical decimal text; never normalizes a near miss.

    `int()` alone is not safe here: it accepts surrounding whitespace, '_'
    separators, a leading '+' and Unicode digits, so int('01') == int(' 1') == 1
    and int('\u0661') == 1. The pattern is checked first and the round trip is
    required, so an alternate spelling is refused rather than silently accepted.
    """
    require(type(text) is str and pattern.match(text) is not None
            and str(int(text)) == text, f'{name}: not canonical decimal text')
    return int(text)


def legacy_observed_stamp(observation):
    """Inverse of observed_stamp: the version-1 integer form.

    Used only to recompute a legacy unmanaged digest over live rows, so that a
    journal written before the version-2 encoding can still be validated. There is
    deliberately no fallback between the two encodings at the call site.
    """
    require(type(observation) is list and len(observation) == 7
            and all(type(observation[i]) is str for i in (0, 1, 5, 6))
            and all(type(observation[i]) is int for i in (2, 3, 4)),
            'filesystem stamp observation shape')
    return [parse_canonical_text(IDENTITY_TEXT, observation[0], 'device identity'),
            parse_canonical_text(IDENTITY_TEXT, observation[1], 'inode identity'),
            observation[2], observation[3], observation[4],
            parse_canonical_text(TIMESTAMP_TEXT, observation[5], 'modification time'),
            parse_canonical_text(TIMESTAMP_TEXT, observation[6], 'change time')]


def _plain_info(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and
            not getattr(info, 'st_file_attributes', 0) & 0x400, 'link/reparse point refused')
    require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'special file refused')
    if stat.S_ISREG(info.st_mode):
        require(info.st_nlink == 1, 'hard-linked file refused')
    _stamp(info)
    return info


def plain_path(path, directory=None):
    path = _absolute(path)
    if os.name == 'nt':
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        require(kernel.GetDriveTypeW(path.anchor) in (2, 3), 'accessible local drive required')
    for parent in reversed(path.parents):
        require(stat.S_ISDIR(_plain_info(parent).st_mode), 'ancestor not directory')
    info = _plain_info(path)
    if directory is not None:
        require(stat.S_ISDIR(info.st_mode) is directory, 'wrong filesystem type')
    return path, info


def _streams(path):
    """NTFS named streams must not disappear from an otherwise complete inventory."""
    if os.name != 'nt':
        return
    from ctypes import wintypes as w

    class StreamData(ctypes.Structure):
        _fields_ = [('size', ctypes.c_longlong), ('name', w.WCHAR * 296)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    first = kernel.FindFirstStreamW
    first.argtypes = [w.LPCWSTR, ctypes.c_int, ctypes.POINTER(StreamData), w.DWORD]
    first.restype = w.HANDLE
    next_stream = kernel.FindNextStreamW
    next_stream.argtypes = [w.HANDLE, ctypes.POINTER(StreamData)]
    next_stream.restype = w.BOOL
    close = kernel.FindClose
    close.argtypes = [w.HANDLE]
    close.restype = w.BOOL
    data = StreamData()
    handle = first(str(path), 0, ctypes.byref(data), 0)
    if handle == ctypes.c_void_p(-1).value:
        require(ctypes.get_last_error() == 38, 'stream enumeration unavailable/failed')
        return
    try:
        while True:
            require(data.name == '::$DATA', 'named stream refused')
            if not next_stream(handle, ctypes.byref(data)):
                require(ctypes.get_last_error() == 38, 'stream enumeration failed')
                break
    finally:
        close(handle)


def directory_identity(path):
    _, info = plain_path(path, True)
    return {'device': str(info.st_dev), 'inode': str(info.st_ino)}


def validate_identity(value):
    exact(value, ('device', 'inode'), 'identity')
    require(all(type(v) is str and re.fullmatch(r'[1-9][0-9]{0,39}', v)
                for v in value.values()), 'invalid filesystem identity')
    return value


def _read_file(path, limit):
    path, before = plain_path(path, False)
    _streams(path)
    require(before.st_size <= limit, 'file size limit')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as handle:
        opened = os.fstat(handle.fileno())
        # Bind the descriptor to the object the path inspection just validated.
        # Identity fields only: st_ctime_ns is not comparable across these two APIs
        # on Windows (path = CreationTime, fd = ChangeTime since CPython 3.12), and a
        # blanket stamp comparison therefore refused every published file.
        require(_identity(opened) == _identity(before), 'file replaced before read')
        data = handle.read(limit + 1)
        require(len(data) <= limit, 'file size limit')
        # Same API on both sides, so st_ctime_ns is meaningful and stays in: this is
        # the in-place change detection for the read window.
        require(_stamp(os.fstat(handle.fileno())) == _stamp(opened), 'file changed during read')
    _, after = plain_path(path, False)
    _streams(path)
    require(_stamp(after) == _stamp(before) and len(data) == before.st_size, 'file replaced after read')
    return data, _stamp(before)


@dataclass(frozen=True)
class RecordSnapshot:
    value: dict
    data: bytes
    sha256: str
    identity: tuple


def read_bound_record(path, limit=MAX_RECORD, canonical=True):
    data, identity = _read_file(path, limit)
    value = parse_json(data, limit, canonical)
    require(type(value) is dict, 'record object required')
    return RecordSnapshot(value, data, hashlib.sha256(data).hexdigest(), identity)


def evidence_path(root, ident, forbidden_roots=()):
    provider_id(ident)
    root, _ = plain_path(root, True)
    path = root / 'audit' / 'evidence' / (ident + '.json')
    plain_path(path, False)
    for blocked in forbidden_roots:
        blocked = _absolute(blocked)
        a = pathlib.Path(os.path.normcase(str(path)))
        b = pathlib.Path(os.path.normcase(str(blocked)))
        require(not (a.is_relative_to(b) or b.is_relative_to(a)), 'evidence/authority overlap')
    return path


def _file_url(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'file' and not parsed.netloc and not parsed.query and not parsed.fragment,
            'local file URI required')
    require(not re.search(r'%(?:2[fFeE]|5[cC]|00|25)', parsed.path), 'encoded path alias')
    try:
        decoded = urllib.parse.unquote(parsed.path, errors='strict')
    except UnicodeDecodeError as ex:
        raise BindingError('invalid file URI encoding') from ex
    if os.name == 'nt':
        require(re.match(r'^/[A-Za-z]:/', decoded), 'local drive URI required')
        decoded = decoded[1:]
    path = _absolute(decoded)
    require(path != pathlib.Path(path.anchor), 'root origin refused')
    path = pathlib.Path(os.path.normcase(str(path)))
    require(path.as_uri() == url, 'noncanonical file URI')
    return path


def file_origin(path):
    path, _ = plain_path(path, True)
    _streams(path)
    path = pathlib.Path(os.path.normcase(str(path)))
    url = path.as_uri()
    _file_url(url)
    return {'kind': 'file', 'url': url, 'root_identity': directory_identity(path)}


def canonical_origin(url):
    text(url, 'origin', 4096)
    if url.startswith('file:'):
        return file_origin(_file_url(url))
    require(url.isascii() and not any(c.isspace() or ord(c) < 32 for c in url), 'unsafe origin')
    require(not any(c in url for c in '\\%?#'), 'origin alias/parameters')
    try:
        parsed = urllib.parse.urlsplit(url)
        host, port = parsed.hostname, parsed.port
    except ValueError as ex:
        raise BindingError('malformed origin') from ex
    require(parsed.scheme == 'https' and parsed.username is None and parsed.password is None,
            'HTTPS origin required')
    require(host is not None and re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', host), 'invalid origin host')
    require(port is None or 1 <= port <= 65535, 'invalid port')
    authority = host + (f':{port}' if port is not None and port != 443 else '')
    require(parsed.path.startswith('/') and all(p not in ('', '.', '..') for p in parsed.path[1:].split('/')),
            'invalid origin path')
    require(re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@/-]+", parsed.path), 'invalid URI path characters')
    require(url == 'https://' + authority + parsed.path, 'noncanonical origin')
    return {'kind': 'https', 'url': url}


def validate_origin(origin, observe=False):
    require(type(origin) is dict, 'origin object required')
    if origin.get('kind') == 'file':
        exact(origin, ('kind', 'url', 'root_identity'), 'file origin')
        text(origin['url'], 'origin', 4096)
        _file_url(origin['url'])
        validate_identity(origin['root_identity'])
        if observe:
            require(canonical_origin(origin['url']) == origin, 'file origin identity changed')
    else:
        exact(origin, ('kind', 'url'), 'HTTPS origin')
        require(origin['kind'] == 'https' and type(origin['url']) is str and
                origin['url'].startswith('https:'), 'unknown origin kind')
        require(canonical_origin(origin['url']) == origin, 'origin mismatch')
    return origin


def catalog_digest(entry):
    require(type(entry) is dict, 'catalog entry object required')
    require(len(canonical_json(entry)) <= MAX_ENTRY, 'catalog entry size limit')
    return digest('accp-catalog-v1', entry)


def _invocation(value):
    require(type(value) is str and value in ('explicit', 'implicit'), 'invalid operational invocation')


def validate_candidate(value):
    exact(value, CANDIDATE_FIELDS, 'candidate')
    require(type(value['binding_version']) is int and value['binding_version'] == 1, 'candidate version')
    provider_id(value['source_id'])
    validate_origin(value['origin'])
    for key in ('catalog_sha256', 'source_tree_sha256', 'artifact_tree_sha256'):
        hex_digest(value[key])
    for key in ('commit', 'source_tree_oid'):
        hex_digest(value[key], 40)
    canonical_relative_path(value['deploy_path'], True)
    _invocation(value['invocation'])
    require(value['projection'] == PROJECTION, 'unknown projection')
    return value


def validate_inventory(inventory):
    require(type(inventory) is list and len(inventory) <= MAX_ENTRIES, 'inventory count/type')
    names, aliases, total = {}, set(), 0
    for record in inventory:
        require(type(record) is dict, 'inventory entry object')
        kind = record.get('type')
        require(kind in ('file', 'directory'), 'inventory type')
        exact(record, ('path', 'type', 'size', 'sha256') if kind == 'file' else ('path', 'type'), 'inventory entry')
        name = canonical_relative_path(record['path'])
        alias = unicodedata.normalize('NFKC', name).casefold()
        require(name not in names and alias not in aliases, 'duplicate/aliased inventory path')
        names[name] = kind
        aliases.add(alias)
        if kind == 'file':
            require(type(record['size']) is int and 0 <= record['size'] <= MAX_FILE, 'inventory file size')
            total += record['size']
            require(total <= MAX_PAYLOAD, 'inventory payload limit')
            hex_digest(record['sha256'])
    require([v['path'] for v in inventory] == sorted(names, key=lambda s: s.encode('utf-8')), 'inventory ordering')
    for name in names:
        parent = pathlib.PurePosixPath(name).parent
        while str(parent) != '.':
            require(names.get(str(parent)) == 'directory', 'missing/conflicting inventory parent')
            parent = parent.parent
    return inventory


def payload_inventory(payload):
    require(type(payload) is dict and len(payload) <= MAX_ENTRIES, 'payload type/count')
    entries, total = {}, 0
    for name, data in payload.items():
        canonical_relative_path(name)
        require(type(data) is bytes and len(data) <= MAX_FILE, 'payload bytes/size')
        total += len(data)
        require(total <= MAX_PAYLOAD, 'payload total size limit')
        entries[name] = {'path': name, 'type': 'file', 'size': len(data),
                         'sha256': hashlib.sha256(data).hexdigest()}
    for name in payload:
        for parent in pathlib.PurePosixPath(name).parents:
            if str(parent) == '.':
                continue
            require(str(parent) not in payload, 'payload parent is a file')
            entries[str(parent)] = {'path': str(parent), 'type': 'directory'}
            require(len(entries) <= MAX_ENTRIES, 'payload inventory count limit')
    return validate_inventory(sorted(entries.values(), key=lambda r: r['path'].encode('utf-8')))


def policy_bytes(invocation):
    _invocation(invocation)
    literal = 'false' if invocation == 'explicit' else 'true'
    return f'policy:\n  allow_implicit_invocation: {literal}\n'.encode('utf-8')


def projected_inventory(source_inventory, invocation):
    validate_inventory(source_inventory)
    out = {v['path']: dict(v) for v in source_inventory}
    require('agents' not in out or out['agents']['type'] == 'directory', 'agents is not a directory')
    target = 'agents/openai.yaml'
    require(target not in out or out[target]['type'] == 'file', 'policy path is not a file')
    data = policy_bytes(invocation)
    out['agents'] = {'path': 'agents', 'type': 'directory'}
    out[target] = {'path': target, 'type': 'file', 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    return validate_inventory(sorted(out.values(), key=lambda r: r['path'].encode('utf-8')))


def project_invocation(source_payload, invocation):
    expected = projected_inventory(payload_inventory(source_payload), invocation)
    result = dict(source_payload)
    result['agents/openai.yaml'] = policy_bytes(invocation)
    require(payload_inventory(result) == expected, 'projection inventory mismatch')
    return result


def inventory_tree(root, vault=False):
    require(type(vault) is bool, 'vault flag must be boolean')
    root, initial = plain_path(root, True)
    records, observations, total = [], [], 0

    def walk(directory, prefix):
        nonlocal total
        _, before = plain_path(directory, True)
        _streams(directory)
        children = sorted(directory.iterdir(), key=lambda p: p.name.encode('utf-8'))
        for child in children:
            name = prefix + child.name
            if vault and not prefix and child.name == MANIFEST:
                data, stamp = _read_file(child, MAX_MANIFEST)
                validate_vault_manifest(parse_json(data, MAX_MANIFEST, True))
                observations.append((child, stamp))
                continue
            canonical_relative_path(name)
            require(len(records) < MAX_ENTRIES, 'inventory count limit')
            _, info = plain_path(child)
            if stat.S_ISDIR(info.st_mode):
                records.append({'path': name, 'type': 'directory'})
                walk(child, name + '/')
            else:
                data, stamp = _read_file(child, MAX_FILE)
                total += len(data)
                require(total <= MAX_PAYLOAD, 'inventory payload limit')
                records.append({'path': name, 'type': 'file', 'size': len(data),
                                'sha256': hashlib.sha256(data).hexdigest()})
                observations.append((child, stamp))
        _, after = plain_path(directory, True)
        require(_stamp(before) == _stamp(after), 'directory changed during inventory')
        observations.append((directory, _stamp(before)))

    walk(root, '')
    if vault:
        require(any(p == root / MANIFEST for p, _ in observations), 'Vault manifest missing')
    for path, stamp in observations:
        _, info = plain_path(path)
        _streams(path)
        require(_stamp(info) == stamp, 'tree changed during inventory')
    require(_stamp(plain_path(root, True)[1]) == _stamp(initial), 'tree root replaced')
    return validate_inventory(sorted(records, key=lambda r: r['path'].encode('utf-8')))


def _timestamp(value):
    text(value, 'UTC timestamp', 40)
    require(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value), 'UTC timestamp spelling')
    try:
        datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as ex:
        raise BindingError('invalid timestamp') from ex


def validate_evidence(record):
    exact(record, EVIDENCE_FIELDS, 'evidence')
    require(type(record['schema_version']) is int and record['schema_version'] == 2, 'legacy/unknown evidence')
    candidate = validate_candidate(record['candidate'])
    source = validate_inventory(record['source_inventory'])
    require(any(r['path'] == 'SKILL.md' and r['type'] == 'file' for r in source),
            'reviewed source lacks SKILL.md')
    artifact = validate_inventory(record['artifact_inventory'])
    require(candidate['source_tree_sha256'] == digest('accp-source-tree-v1', source), 'source inventory digest mismatch')
    require(artifact == projected_inventory(source, candidate['invocation']), 'unbound artifact projection')
    require(candidate['artifact_tree_sha256'] == digest('accp-artifact-tree-v1', artifact), 'artifact inventory digest mismatch')
    require(record['candidate_sha256'] == digest('accp-candidate-v1', candidate), 'candidate digest mismatch')
    require(type(record['status']) is str and record['status'] in ('pending', 'approved'), 'evidence status')
    text(record['reviewer'], 'reviewer', 1024)
    require(bool(record['reviewer'].strip()), 'empty reviewer')
    _timestamp(record['reviewed_at'])
    text(record['notes'], 'notes', 16 * 1024, empty=True)
    surface = record['executable_surface']
    require(type(surface) is list and len(surface) <= MAX_ENTRIES, 'executable surface list')
    files = {r['path'] for r in source if r['type'] == 'file'}
    for name in surface:
        canonical_relative_path(name)
        require(name in files, 'executable surface outside source')
    require(surface == sorted(set(surface), key=lambda s: s.encode('utf-8')), 'executable surface ordering/duplicates')
    require(len(canonical_json(record)) + 1 <= MAX_RECORD, 'evidence size limit')
    return record


def encode_evidence(record):
    return canonical_json(validate_evidence(record)) + b'\n'


def decode_evidence(data):
    return validate_evidence(parse_json(data, MAX_RECORD, True))


def validate_lock_record(record, operational=False):
    require(type(operational) is bool and type(record) is dict, 'lock type')
    modern = 'binding' in record
    exact(record, LOCK_FIELDS | ({'binding'} if modern else set()), 'lock')
    for key in ('repo', 'deploy_path', 'evidence'):
        text(record[key], key, 4096)
        require(bool(record[key].strip()), 'empty lock text')
    hex_digest(record['commit'], 40)
    hex_digest(record['evidence_sha256'])
    approval = record['approval']
    require(type(approval) is dict and not set(approval) - {'partial_or_conditional', 'high_risk', 'approved_at'}, 'approval fields')
    for key in ('partial_or_conditional', 'high_risk'):
        if key in approval:
            require(type(approval[key]) is bool, 'approval must be literal boolean')
    if 'approved_at' in approval:
        text(approval['approved_at'], 'approved_at', 4096)
        require(bool(approval['approved_at'].strip()), 'empty approval time')
    if modern:
        binding = exact(record['binding'], ('schema_version', 'candidate_sha256'), 'lock binding')
        require(type(binding['schema_version']) is int and binding['schema_version'] == 1, 'lock binding version')
        hex_digest(binding['candidate_sha256'])
        canonical_relative_path(record['deploy_path'], True)
        if record['repo'].startswith('file:'):
            _file_url(record['repo'])
        else:
            canonical_origin(record['repo'])
        require(re.fullmatch(r'audit/evidence/(' + ID_PATTERN + r')\.json', record['evidence']), 'noncanonical evidence location')
    require(not operational or modern, 'legacy lock has no operational binding')
    return record


def validate_runtime_binding(record):
    exact(record, RUNTIME_FIELDS, 'runtime binding')
    text(record['runtime_id'], 'runtime UUID', 36)
    try:
        parsed = uuid.UUID(record['runtime_id'])
    except ValueError as ex:
        raise BindingError('runtime UUID') from ex
    require(parsed.version == 4 and str(parsed) == record['runtime_id'], 'runtime UUID spelling/version')
    for key in ('runtime_path', 'control_plane_path'):
        path = _absolute(record[key])
        require(str(path) == os.path.normcase(str(path)) and path != pathlib.Path(path.anchor), 'runtime path identity spelling')
    principal = text(record['principal'], 'principal', 256)
    require(re.fullmatch(r'(?:uid:(?:0|[1-9][0-9]*)|sid:S-[0-9]+(?:-[0-9]+)+)', principal), 'runtime principal')
    validate_identity(record['root_identity'])
    validate_identity(record['vault_identity'])
    return record


def validate_vault_manifest(record):
    exact(record, VAULT_FIELDS, 'Vault manifest')
    require(type(record['schema_version']) is int and record['schema_version'] == 2, 'legacy/unknown Vault schema')
    provider_id(record['source_id'])
    for key in ('candidate_sha256', 'evidence_sha256', 'artifact_tree_sha256'):
        hex_digest(record[key])
    _invocation(record['invocation'])
    require(record['projection'] == PROJECTION, 'unknown Vault projection')
    validate_runtime_binding(record['runtime_binding'])
    _timestamp(record['materialized_at'])
    require(len(canonical_json(record)) + 1 <= MAX_MANIFEST, 'Vault manifest size limit')
    return record


def load_review_binding(root, ident, entry, lock, forbidden_roots=()):
    """Record proof only. Does not grant F05 eligibility or call any runtime API."""
    provider_id(ident)
    validate_lock_record(lock, operational=True)
    require(lock['evidence'] == f'audit/evidence/{ident}.json', 'evidence/provider path mismatch')
    snapshot = read_bound_record(evidence_path(root, ident, forbidden_roots))
    ev = validate_evidence(snapshot.value)
    require(ev['status'] == 'approved', 'evidence not approved')
    require(snapshot.sha256 == lock['evidence_sha256'], 'evidence byte digest mismatch')
    b = ev['candidate']
    require(type(entry) is dict and entry.get('id') == ident == b['source_id'], 'catalog identity mismatch')
    require(catalog_digest(entry) == b['catalog_sha256'], 'catalog digest mismatch')
    require(canonical_origin(entry.get('source_url')) == b['origin'], 'catalog origin mismatch')
    require(type(entry.get('deploy')) is dict and entry['deploy'].get('path') == b['deploy_path'], 'catalog deploy mismatch')
    require(entry.get('invocation') == b['invocation'], 'catalog invocation mismatch')
    require((lock['repo'], lock['commit'], lock['deploy_path']) ==
            (b['origin']['url'], b['commit'], b['deploy_path']), 'lock/candidate mismatch')
    require(lock['binding']['candidate_sha256'] == ev['candidate_sha256'], 'lock candidate digest mismatch')
    return snapshot


def validate_artifact_copy(root, evidence, evidence_sha256, runtime_binding):
    """Check a derived copy against external proof; this grants no activation authority."""
    validate_evidence(evidence)
    require(evidence['status'] == 'approved', 'pending evidence')
    hex_digest(evidence_sha256)
    require(hashlib.sha256(encode_evidence(evidence)).hexdigest() == evidence_sha256,
            'parsed evidence differs from bound bytes')
    validate_runtime_binding(runtime_binding)
    root, _ = plain_path(root, True)
    root_id = directory_identity(root)
    snapshot = read_bound_record(root / MANIFEST, MAX_MANIFEST)
    manifest = snapshot.value
    validate_vault_manifest(manifest)
    b = evidence['candidate']
    for key, expected in (('source_id', b['source_id']), ('candidate_sha256', evidence['candidate_sha256']),
            ('evidence_sha256', evidence_sha256), ('artifact_tree_sha256', b['artifact_tree_sha256']),
            ('invocation', b['invocation']), ('projection', b['projection']), ('runtime_binding', runtime_binding)):
        require(manifest[key] == expected, f'Vault {key} binding mismatch')
    require(inventory_tree(root, vault=True) == evidence['artifact_inventory'], 'Vault artifact content mismatch')
    after = read_bound_record(root / MANIFEST, MAX_MANIFEST)
    require(after.identity == snapshot.identity and after.data == snapshot.data, 'Vault manifest changed')
    require(directory_identity(root) == root_id, 'artifact root replaced during validation')
    return manifest


def validate_vault_binding(root, evidence, evidence_sha256, runtime_binding):
    """Caller supplies fresh external F02 ready-receipt fields, not manifest fields."""
    validate_evidence(evidence)
    require(evidence['status'] == 'approved', 'pending evidence')
    hex_digest(evidence_sha256)
    require(hashlib.sha256(encode_evidence(evidence)).hexdigest() == evidence_sha256,
            'parsed evidence differs from bound bytes')
    validate_runtime_binding(runtime_binding)
    root, _ = plain_path(root, True)
    runtime = pathlib.Path(runtime_binding['runtime_path'])
    expected = runtime / 'vault' / 'skills' / evidence['candidate']['source_id']
    require(os.path.normcase(str(root)) == os.path.normcase(str(expected)), 'foreign Vault location')
    require(directory_identity(runtime) == runtime_binding['root_identity'] and
            directory_identity(runtime / 'vault') == runtime_binding['vault_identity'],
            'runtime/Vault directory identity mismatch')
    manifest = validate_artifact_copy(root, evidence, evidence_sha256, runtime_binding)
    require(directory_identity(runtime) == runtime_binding['root_identity'] and
            directory_identity(runtime / 'vault') == runtime_binding['vault_identity'],
            'runtime/Vault identity changed during validation')
    return manifest


@dataclass(frozen=True)
class Export:
    payload: dict
    inventory: list
    source_tree_oid: str
    executable_paths: tuple


def _git_environment():
    # Do not inherit GIT_*, HOME, credential/helper or config injection settings.
    names = ('SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'TEMP', 'TMP', 'TMPDIR')
    env = {name: os.environ[name] for name in names if name in os.environ}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM=os.devnull,
               GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0',
               GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0', LC_ALL='C')
    return env


def _bounded_git(repo, args, limit, transport=None):
    git = shutil.which('git')
    require(git is not None, 'Git executable unavailable')
    command = [git, '--no-replace-objects', f'--git-dir={repo}',
               '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=' + os.devnull,
               '-c', 'gc.auto=0', '-c', 'maintenance.auto=false',
               '-c', 'protocol.allow=never']
    if transport is not None:
        require(transport in ('https', 'file'), 'unsupported transport')
        command += ['-c', f'protocol.{transport}.allow=always', '-c', 'credential.helper=']
        if transport == 'https':
            command += ['-c', 'http.followRedirects=false', '-c', 'http.sslVerify=true']
    command += args
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               stdin=subprocess.DEVNULL, env=_git_environment(), cwd=repo)
    expired = threading.Event()

    def timeout():
        expired.set()
        process.kill()

    timer = threading.Timer(30, timeout)
    timer.daemon = True
    timer.start()
    try:
        data = process.stdout.read(limit + 1)
        if len(data) > limit:
            process.kill()
        code = process.wait()
        require(not expired.is_set(), 'Git object read timeout')
        # Keep these three conditions distinct. Collapsing them into one message
        # ("failed/limit") made a non-zero Git exit indistinguishable from an
        # oversized read, which sent diagnosis down the wrong path: stderr is
        # discarded here, so command progress output can never be the cause.
        require(len(data) <= limit, 'Git object read limit exceeded')
        require(code == 0, 'Git object read failed (exit code %d)' % code)
        return data
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def _bare_config(repo, origin):
    """Read-only validation, no network or adoption. Creation belongs to M2."""
    validate_origin(origin, observe=True)
    repo, before = plain_path(repo, True)
    _streams(repo)
    for name in ('objects', 'refs'):
        plain_path(repo / name, True)
    for name in ('commondir', 'gitdir', 'worktrees', 'shallow', 'config.worktree', 'info/grafts',
                 'objects/info/alternates', 'objects/info/http-alternates', 'refs/replace'):
        try:
            (repo / name).lstat()
        except FileNotFoundError:
            continue
        raise BindingError('unsupported/redirected Git object store: ' + name)
    data, config_stamp = _read_file(repo / 'config', MAX_MANIFEST)
    try:
        config = configparser.RawConfigParser(strict=True, interpolation=None)
        config.read_file(io.StringIO(data.decode('utf-8', errors='strict')))
    except (UnicodeDecodeError, configparser.Error) as ex:
        raise BindingError('malformed bare Git configuration') from ex
    require(not config.defaults() and set(config.sections()) == {'core', 'remote "origin"'}, 'unsafe Git config sections')
    core = dict(config['core'])
    require(set(core) <= {'repositoryformatversion', 'bare', 'filemode', 'ignorecase', 'symlinks', 'logallrefupdates'},
            'unsafe Git core configuration')
    require(core.get('repositoryformatversion') == '0' and core.get('bare') == 'true', 'bare SHA1 Git store required')
    require(all(v in ('true', 'false') for k, v in core.items() if k not in ('repositoryformatversion', 'bare')),
            'ambiguous Git config values')
    remote = dict(config['remote "origin"'])
    require(set(remote) <= {'url', 'fetch'} and remote.get('url') == origin['url'], 'Git origin mismatch/config')
    if 'fetch' in remote:
        require(remote['fetch'] == '+refs/heads/*:refs/remotes/origin/*', 'unsupported refspec')
    # Git's config grammar differs from ConfigParser. Restrict the actual syntax,
    # not only its parsed meaning, so comments/escapes/continuations cannot alias.
    for line in data.decode('utf-8').splitlines():
        s = line.strip()
        if not s:
            continue
        require(s in ('[core]', '[remote "origin"]') or
                re.fullmatch(r'[a-z]+\s*=\s*[^\s\\";#]+', s), 'unsupported Git config syntax')
    # Inspect the store before Git opens packs/loose objects; no link or ADS can
    # redirect a read. Inventory limits bound even malicious cache input.
    observations = []
    for base in (repo,):
        pending = [base]
        while pending:
            path = pending.pop()
            require(len(observations) < MAX_ENTRIES, 'Git store entry limit')
            _, info = plain_path(path)
            _streams(path)
            require(info.st_size <= MAX_PAYLOAD or stat.S_ISDIR(info.st_mode), 'Git store file limit')
            observations.append((path, _stamp(info)))
            if stat.S_ISDIR(info.st_mode):
                pending.extend(path.iterdir())
    if (repo / 'packed-refs').exists():
        packed, _ = _read_file(repo / 'packed-refs', MAX_RECORD)
        require(b'refs/replace/' not in packed, 'packed replacement refs refused')
    return repo, _stamp(before), config_stamp, observations


def export_locked_tree(bare_repo, commit, deploy_path, origin):
    """Return raw, hash-verified blobs; no checkout, fetch, file writes or filters."""
    hex_digest(commit, 40)
    canonical_relative_path(deploy_path, True)
    repo, repo_stamp, config_stamp, observations = _bare_config(bare_repo, origin)
    budget = 0

    def obj(oid, kind, limit):
        nonlocal budget
        hex_digest(oid, 40)
        require(_bounded_git(repo, ['cat-file', '-t', oid], 16) == kind.encode('ascii') + b'\n',
                'Git object type mismatch')
        size = _bounded_git(repo, ['cat-file', '-s', oid], 32)
        require(re.fullmatch(rb'(?:0|[1-9][0-9]*)\n', size), 'invalid Git object size')
        size = int(size)
        require(size <= limit and budget + size <= MAX_PAYLOAD + MAX_RECORD, 'Git object size limit')
        data = _bounded_git(repo, ['cat-file', kind, oid], limit)
        require(len(data) == size, 'Git object size changed')
        require(hashlib.sha1(kind.encode('ascii') + b' ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest() == oid,
                'raw Git object hash mismatch')
        budget += len(data)
        require(budget <= MAX_PAYLOAD + MAX_RECORD, 'Git export size limit')
        return data

    commit_bytes = obj(commit, 'commit', MAX_RECORD)
    match = re.match(rb'tree ([0-9a-f]{40})\n', commit_bytes)
    require(match is not None, 'malformed commit tree')
    tree_oid = match.group(1).decode('ascii')

    def entries(oid):
        """Parse a canonical Git tree; this is NOT the artifact-admission gate.

        Every canonical mode is recognised here, including symlink and gitlink,
        because resolving a deploy path has to read trees that may contain them as
        siblings. What may enter the artifact is enforced by ARTIFACT_GIT_MODES in
        walk(), and what may be traversed is enforced in the descent below.
        """
        data = obj(oid, 'tree', MAX_RECORD)
        result = []
        cursor = 0
        seen = set()
        while cursor < len(data):
            end = data.find(b'\0', cursor)
            require(end > cursor and end + 21 <= len(data), 'truncated Git tree')
            header = data[cursor:end].split(b' ', 1)
            require(len(header) == 2 and header[0] in PARSED_GIT_MODES, 'unsupported Git mode')
            try:
                name = header[1].decode('utf-8', errors='strict')
            except UnicodeDecodeError as ex:
                raise BindingError('non-UTF8 Git name') from ex
            canonical_relative_path(name)
            alias = unicodedata.normalize('NFKC', name).casefold()
            require('/' not in name and alias not in seen, 'ambiguous Git tree name')
            seen.add(alias)
            result.append((header[0], name, data[end+1:end+21].hex()))
            require(len(result) <= MAX_ENTRIES, 'Git tree count limit')
            cursor = end + 21
        # Trees sort as name + '/', every other mode as name + '\0'; symlinks and
        # gitlinks therefore take part in the ordering check rather than escaping it.
        order = lambda item: item[1].encode('utf-8') + (b'/' if item[0] == GIT_MODE_TREE else b'\0')
        require(result == sorted(result, key=order), 'noncanonical Git tree ordering')
        return result

    if deploy_path != '.':
        for component in deploy_path.split('/'):
            current = entries(tree_oid)
            matches = [(mode, oid) for mode, name, oid in current if name == component]
            # Only a tree may be traversed: a symlink or gitlink cannot be a
            # selected component, and neither can a regular file.
            require(len(matches) == 1 and matches[0][0] == GIT_MODE_TREE, 'deploy subtree missing/not directory')
            tree_oid = matches[0][1]
    payload, records, executables = {}, [], []

    def walk(oid, prefix):
        for mode, name, child_oid in entries(oid):
            # The artifact-admission gate. Inside the selected subtree only trees,
            # regular files and executables are permitted; a symlink or gitlink here
            # is refused outright, which is the property the parser deliberately no
            # longer enforces for siblings outside the selected path.
            require(mode in ARTIFACT_GIT_MODES, 'unsupported Git mode/link/gitlink')
            name = prefix + name
            canonical_relative_path(name)
            require(len(records) < MAX_ENTRIES, 'Git inventory count limit')
            if mode == GIT_MODE_TREE:
                records.append({'path': name, 'type': 'directory'})
                walk(child_oid, name + '/')
            else:
                data = obj(child_oid, 'blob', MAX_FILE)
                payload[name] = data
                records.append({'path': name, 'type': 'file', 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
                if mode == GIT_MODE_EXECUTABLE:
                    executables.append(name)

    walk(tree_oid, '')
    inventory = validate_inventory(sorted(records, key=lambda r: r['path'].encode('utf-8')))
    require(any(r['path'] == 'SKILL.md' and r['type'] == 'file' for r in inventory), 'source lacks SKILL.md')
    # Explicit directory records retain even empty Git trees. Consumers must
    # project the full inventory, not reconstruct it from the payload alone.
    validate_origin(origin, observe=True)
    require(_read_file(repo / 'config', MAX_MANIFEST)[1] == config_stamp, 'Git config changed')
    for path, stamp in observations:
        require(_stamp(plain_path(path)[1]) == stamp, 'Git object store changed')
    require(_stamp(plain_path(repo, True)[1]) == repo_stamp, 'Git root changed')
    return Export(payload, inventory, tree_oid, tuple(sorted(executables, key=lambda s: s.encode('utf-8'))))


def publish_bytes(path, data, limit=MAX_RECORD, replace=False):
    """Publish only a caller-derived immediate file; never create ancestor paths."""
    require(type(data) is bytes and len(data) <= limit, 'publication size/type')
    path = _absolute(path)
    parent, _ = plain_path(path.parent, True)
    parent_id = directory_identity(parent)
    try:
        path.lstat()
    except FileNotFoundError:
        previous = None
    else:
        require(replace, 'publication collision')
        previous = _read_file(path, limit)
    temp = parent / ('.accp-write-' + uuid.uuid4().hex)
    with open(temp, 'xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    # A failed publication retains its uniquely named temporary evidence.
    require(directory_identity(parent) == parent_id, 'publication parent replaced')
    if previous is None:
        require(not os.path.lexists(path), 'publication collision')
    else:
        require(_read_file(path, limit) == previous, 'publication destination changed')
    os.replace(temp, path)
    require(_read_file(path, limit)[0] == data, 'publication changed')


def _local_transport(origin):
    """Refuse executable/config redirection in a local upload-pack source."""
    validate_origin(origin, observe=True)
    root = _file_url(origin['url'])
    repo = root / '.git' if os.path.lexists(root / '.git') else root
    plain_path(repo, True)
    # Validate all Git administrative paths, including HEAD/config/hooks, before
    # the trusted Git binary can inspect them. No source-side config is executed.
    inventory_tree(repo)
    config = configparser.RawConfigParser(strict=True, interpolation=None)
    data, stamp = _read_file(repo / 'config', MAX_MANIFEST)
    try:
        config.read_string(data.decode('utf-8'))
    except (UnicodeDecodeError, configparser.Error) as ex:
        raise BindingError('unsafe local source config') from ex
    require(not config.defaults() and set(config.sections()) <= {'core', 'user'}, 'unsafe local source config sections')
    core = dict(config['core']) if 'core' in config else {}
    require(set(core) <= {'repositoryformatversion','bare','filemode','ignorecase','symlinks','logallrefupdates'} and
            core.get('repositoryformatversion') == '0' and core.get('bare') in ('true','false'), 'unsafe local source core')
    require(all(v in ('true','false') for k,v in core.items() if k != 'repositoryformatversion'), 'unsafe local source core value')
    if 'user' in config:
        require(set(config['user']) <= {'name','email'}, 'unsafe source user config')
    for line in data.decode('utf-8').splitlines():
        s=line.strip()
        require(not s or s in ('[core]','[user]') or re.fullmatch(r'[a-z]+\s*=\s*[^\s\\";#]+',s), 'ambiguous source config syntax')
    for name in ('commondir','gitdir','worktrees','shallow','config.worktree','info/grafts',
                 'objects/info/alternates','objects/info/http-alternates','refs/replace'):
        require(not os.path.lexists(repo/name), 'redirected local source store')
    if os.path.lexists(repo/'packed-refs'):
        require(b'refs/replace/' not in _read_file(repo/'packed-refs',MAX_RECORD)[0], 'local replacement refs refused')
    return repo, stamp


def acquire_cache(sources, origin, commit=None):
    """Caller holds F02 runtime mutex. No legacy slug or malformed cache adoption."""
    validate_origin(origin, observe=True)
    if commit is not None: hex_digest(commit,40)
    sources, _ = plain_path(sources, True)
    repo = sources / digest('accp-origin-v1', origin)
    local = _local_transport(origin) if origin['kind'] == 'file' else None
    if not os.path.lexists(repo):
        repo.mkdir()
        for name in ('objects','refs'): (repo/name).mkdir()
        config = ('[core]\n\trepositoryformatversion = 0\n\tbare = true\n\tfilemode = false\n'
                  '[remote "origin"]\n\turl = ' + origin['url'] + '\n')
        publish_bytes(repo/'config',config.encode('utf-8'),MAX_MANIFEST)
        publish_bytes(repo/'HEAD',b'ref: refs/heads/main\n',MAX_MANIFEST)
    _bare_config(repo,origin)
    wanted = commit if commit is not None else 'HEAD'
    _bounded_git(repo,['fetch','--no-tags','--no-auto-maintenance','--no-write-fetch-head',
                       'origin','+'+wanted+':refs/accp/fetched'],MAX_MANIFEST,transport=origin['kind'])
    _bare_config(repo,origin)
    if local is not None:
        require(_read_file(local[0]/'config',MAX_MANIFEST)[1] == local[1], 'local source config changed')
        _local_transport(origin)
    raw,_ = _read_file(repo/'refs/accp/fetched',41)
    require(re.fullmatch(rb'[0-9a-f]{40}\n',raw), 'invalid fetched commit')
    fetched=raw[:-1].decode('ascii')
    require(commit is None or fetched == commit,'fetched commit mismatch')
    return repo,fetched
