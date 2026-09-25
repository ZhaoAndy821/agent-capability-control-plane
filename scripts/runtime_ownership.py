"""Checkout-local authority for ACCP runtime namespaces.

The checkout/receipt store and executing principal are trusted. These path checks
reject existing redirection, not concurrent hostile filesystem replacement.
"""
import contextlib
import ctypes
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import uuid

COMPONENTS = ('sources', 'vault', 'install-manifest.json', 'active-state.json')
DIRECTORIES = COMPONENTS[:2]
MARKER = '.accp-runtime-owner.json'
BINDINGS = {'schema_version', 'runtime_id', 'runtime_path',
            'control_plane_path', 'principal', 'root_identity'}


def plain_path(path):
    path = pathlib.Path(path).absolute()
    for part in (*reversed(path.parents), path):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise RuntimeError(f'linked/reparse runtime path refused: {part}')
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise RuntimeError(f'non-regular runtime path refused: {part}')


def canonical(path):
    plain_path(path)
    return os.path.normcase(str(pathlib.Path(path).resolve()))


def identity(path):
    plain_path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or not info.st_dev or not info.st_ino:
        raise RuntimeError(f'unsupported directory identity: {path}')
    return {'device': str(info.st_dev), 'inode': str(info.st_ino)}


def valid_identity(value):
    return (isinstance(value, dict) and set(value) == {'device', 'inode'}
            and all(isinstance(v, str) and re.fullmatch(r'[1-9][0-9]*', v)
                    for v in value.values()))


def windows_identity():
    """Return token SID and OS profile; never trust USERNAME/USERPROFILE for SID."""
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    userenv = ctypes.WinDLL('userenv', use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                          w.DWORD, ctypes.POINTER(w.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(w.LPWSTR)]
    userenv.GetUserProfileDirectoryW.argtypes = [w.HANDLE, w.LPWSTR, ctypes.POINTER(w.DWORD)]
    token = w.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = w.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not size.value:
            raise RuntimeError('cannot obtain runtime principal')
        data = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, data, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))[0]
        sid_text = w.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            principal = 'sid:' + sid_text.value
        finally:
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        size = w.DWORD(32768)
        profile = ctypes.create_unicode_buffer(size.value)
        if not userenv.GetUserProfileDirectoryW(token, profile, ctypes.byref(size)):
            raise RuntimeError('cannot obtain OS profile for runtime ownership') from ctypes.WinError(ctypes.get_last_error())
        return principal, pathlib.Path(profile.value)
    finally:
        kernel.CloseHandle(token)


def principal_and_profile():
    if os.name == 'nt':
        return windows_identity()
    import pwd
    uid = os.getuid()
    return f'uid:{uid}', pathlib.Path(pwd.getpwuid(uid).pw_dir)


def system_roots(profile):
    if os.name != 'nt':
        return [pathlib.Path(p) for p in ('/bin', '/etc', '/usr', '/var', '/home')]
    # Known folders come from the OS, not overrideable environment strings.
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.SHGetFolderPathW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                      ctypes.c_ulong, ctypes.c_wchar_p]
    roots = [profile.parent]
    for csidl in (0x23, 0x24, 0x25, 0x26, 0x2A):
        buf = ctypes.create_unicode_buffer(32768)
        if shell.SHGetFolderPathW(None, csidl, None, 0, buf) != 0:
            raise RuntimeError('cannot determine protected Windows directory')
        roots.append(pathlib.Path(buf.value))
    return roots


def regular_file(path):
    plain_path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError(f'non-regular or multiply linked runtime file: {path}')
    return info


def read_record(path):
    if regular_file(path).st_size > 16384:
        raise RuntimeError(f'oversized ownership metadata: {path}')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError(f'duplicate ownership field: {key}')
            result[key] = value
        return result
    with path.open('rb') as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise RuntimeError('oversized ownership metadata')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise RuntimeError('ownership metadata must be an object')
    return value, hashlib.sha256(raw).hexdigest()


def exclusive_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + '\n')


class RuntimeOwnership:
    def __init__(self, raw_root, control_plane, project=None):
        self.raw_root = os.fspath(raw_root)
        self.control_plane = pathlib.Path(canonical(control_plane))
        self.store = self.control_plane / '.local' / 'runtime-owners'
        self.project = project
        self.principal, self.profile = principal_and_profile()
        self.root = self._checked_root()
        key = hashlib.sha256(str(self.root).encode('utf-8')).hexdigest()
        self.marker_path = self.root / MARKER
        self.receipt_path = self.store / (key + '.json')
        self.lock_path = self.store / (key + '.lock')

    def _checked_root(self):
        raw = self.raw_root
        if not raw or '\0' in raw:
            raise RuntimeError('empty/invalid runtime path')
        # Check original spelling, before pathlib normalizes away components.
        parts = raw.replace('\\', '/').split('/')
        if any(p in ('.', '..') for p in parts):
            raise RuntimeError('runtime traversal refused')
        if os.name == 'nt':
            if not re.match(r'^[A-Za-z]:[\\/]', raw) or ':' in raw[2:]:
                raise RuntimeError('runtime must be an absolute local drive path')
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
            if kernel.GetDriveTypeW(raw[:3].replace('/', '\\')) not in (2, 3):
                raise RuntimeError('runtime requires an accessible local drive')
            for p in parts[1:]:
                if p and (p.endswith(('.', ' ')) or re.search(r'[<>"|?*]', p)
                          or re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])', p.split('.')[0])):
                    raise RuntimeError('unsafe Windows runtime component')
        elif not pathlib.Path(raw).is_absolute() or raw.startswith('//'):
            raise RuntimeError('runtime must be an absolute local path')
        root = pathlib.Path(canonical(raw))
        if root == pathlib.Path(root.anchor):
            raise RuntimeError('runtime drive/filesystem root refused')
        protected = [self.control_plane, pathlib.Path.home(), self.profile,
                     pathlib.Path.cwd(), self.store,
                     pathlib.Path(os.environ.get('ACCP_USER_SCOPE_ROOT', pathlib.Path.home()/'.agents'))]
        if self.project is not None:
            protected.append(pathlib.Path(self.project))
        if 'ACCP_USER_HOME' in os.environ:
            protected.append(pathlib.Path(os.environ['ACCP_USER_HOME']))
        protected.extend(system_roots(self.profile))
        for p in protected:
            # Protected paths may themselves be aliases: protect their destination.
            target = pathlib.Path(os.path.normcase(str(p.resolve())))
            if root == target or root in target.parents:
                raise RuntimeError(f'protected runtime root/ancestor refused: {root}')
        plain_path(self.store)
        if self.store in root.parents:
            raise RuntimeError('runtime overlaps receipt store')
        for name in ('.git', '.codex-skillset.json', '.agents', '.codex'):
            if os.path.lexists(root/name):
                raise RuntimeError(f'project directory cannot be a runtime: {root}')
        return root

    def _bindings(self):
        return {'schema_version': 1, 'runtime_path': str(self.root),
                'control_plane_path': str(self.control_plane),
                'principal': self.principal, 'root_identity': identity(self.root)}

    def validate(self):
        if self._checked_root() != self.root:
            raise RuntimeError('runtime target changed')
        plain_path(self.marker_path)
        plain_path(self.receipt_path)
        if not self.root.exists() and not self.receipt_path.exists():
            return None
        if not self.root.is_dir() or not self.marker_path.exists() or not self.receipt_path.exists():
            raise RuntimeError(f'unowned/incomplete runtime: {self.root}; rebuild at a fresh absent path')
        marker, marker_hash = read_record(self.marker_path)
        receipt, _ = read_record(self.receipt_path)
        if set(marker) != BINDINGS | {'kind'} or set(receipt) != BINDINGS | {'kind', 'marker_sha256', 'state', 'components'}:
            raise RuntimeError('unexpected ownership metadata fields')
        if marker['kind'] != 'accp-runtime-owner' or receipt['kind'] != 'accp-runtime-receipt':
            raise RuntimeError('invalid ownership metadata kind')
        for record in (marker, receipt):
            if type(record['schema_version']) is not int or record['schema_version'] != 1:
                raise RuntimeError('unsupported ownership schema')
            if not isinstance(record['runtime_id'], str):
                raise RuntimeError('invalid runtime ID')
            try:
                parsed = uuid.UUID(record['runtime_id'])
            except ValueError:
                raise RuntimeError('invalid runtime ID') from None
            if parsed.version != 4 or str(parsed) != record['runtime_id']:
                raise RuntimeError('invalid runtime ID')
            if not valid_identity(record['root_identity']):
                raise RuntimeError('invalid runtime directory identity')
            for field, value in self._bindings().items():
                if record[field] != value:
                    raise RuntimeError(f'ownership binding mismatch: {field}')
        if any(marker[k] != receipt[k] for k in BINDINGS):
            raise RuntimeError('marker/receipt binding mismatch')
        if receipt['marker_sha256'] != marker_hash:
            raise RuntimeError('ownership marker hash mismatch')
        if receipt['state'] not in ('ready', 'deleting', 'retired'):
            raise RuntimeError('invalid ownership state')
        components = receipt['components']
        if not isinstance(components, dict) or set(components) != set(COMPONENTS):
            raise RuntimeError('invalid owned component inventory')
        for name in COMPONENTS:
            spec = components[name]
            if name in DIRECTORIES:
                if not isinstance(spec, dict) or set(spec) != {'type', 'identity'} or spec['type'] != 'directory' or not valid_identity(spec['identity']):
                    raise RuntimeError('invalid owned directory record')
            elif spec != {'type': 'file'}:
                raise RuntimeError('invalid owned file record')
            child = self._child(name)
            if child.exists():
                if receipt['state'] == 'retired':
                    raise RuntimeError('retired runtime has reappearing components')
                if name in DIRECTORIES:
                    if identity(child) != spec['identity']:
                        raise RuntimeError(f'owned directory identity mismatch: {name}')
                else:
                    regular_file(child)
            elif receipt['state'] == 'ready':
                raise RuntimeError(f'owned component missing: {name}')
        return receipt

    def _child(self, name):
        if name not in COMPONENTS:
            raise RuntimeError('unknown runtime component')
        plain_path(self.root)
        child = self.root/name
        plain_path(child)
        if child.resolve().parent != self.root.resolve():
            raise RuntimeError('runtime component escapes immediate-child boundary')
        return child

    @contextlib.contextmanager
    def _mutex(self):
        plain_path(self.store)
        self.store.mkdir(parents=True, exist_ok=True)
        fd = None
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise RuntimeError(f'runtime lock already held: {self.lock_path}') from None
        try:
            os.write(fd, str(os.getpid()).encode('ascii'))
            os.close(fd)
            fd = None
            yield
        finally:
            if fd is not None:
                os.close(fd)
            self.lock_path.unlink()

    def _create(self):
        if self.validate() is not None or self.root.exists() or self.receipt_path.exists():
            raise RuntimeError('runtime cannot be adopted/reinitialized')
        plain_path(self.root.parent)
        if not self.root.parent.is_dir():
            raise RuntimeError('runtime parent must already exist')
        self.root.mkdir(exist_ok=False)
        components = {}
        for name in DIRECTORIES:
            child = self.root/name
            child.mkdir()
            components[name] = {'type': 'directory', 'identity': identity(child)}
        for name in COMPONENTS[2:]:
            exclusive_json(self.root/name, {})
            components[name] = {'type': 'file'}
        marker = dict(self._bindings(), runtime_id=str(uuid.uuid4()), kind='accp-runtime-owner')
        exclusive_json(self.marker_path, marker)
        _, marker_hash = read_record(self.marker_path)
        receipt = dict(marker, kind='accp-runtime-receipt', marker_sha256=marker_hash,
                       state='ready', components=components)
        # Publish authority last; failed setup is intentionally not auto-adopted.
        self._write_receipt(receipt, initial=True)

    def _write_receipt(self, receipt, initial=False):
        plain_path(self.receipt_path)
        if initial:
            if self.receipt_path.exists():
                raise RuntimeError('receipt already exists')
        else:
            regular_file(self.receipt_path)
        tmp = self.store/(self.receipt_path.name + '.tmp-' + uuid.uuid4().hex)
        try:
            exclusive_json(tmp, receipt)
            os.replace(tmp, self.receipt_path)
        finally:
            if tmp.exists():
                tmp.unlink()

    @contextlib.contextmanager
    def session(self, create=False, dry_run=False):
        receipt = self.validate()
        if receipt is None and not create:
            raise RuntimeError('owned runtime missing; fetch/materialize into a fresh path first')
        if receipt is None:
            plain_path(self.root.parent)
            if not self.root.parent.is_dir():
                raise RuntimeError('runtime parent must already exist')
        if receipt is not None and receipt['state'] != 'ready':
            raise RuntimeError('runtime is deleting/retired; use a fresh runtime path')
        if dry_run:
            yield self
            return
        with self._mutex():
            receipt = self.validate()
            if receipt is None and create:
                self._create()
                receipt = self.validate()
            if receipt is None or receipt['state'] != 'ready':
                raise RuntimeError('runtime is not ready')
            yield self

    def _tree(self, path):
        plain_path(path)
        if not path.exists():
            return
        if path.is_dir():
            for child in path.iterdir():
                self._tree(child)
        else:
            regular_file(path)

    def _plan(self, receipt):
        if receipt:
            for name in COMPONENTS:
                self._tree(self._child(name))
        return {'runtime': str(self.root),
                'state': receipt['state'] if receipt else 'absent',
                'remove': [str(self.root/n) for n in COMPONENTS if (self.root/n).exists()],
                'preserve': sorted(p.name for p in self.root.iterdir() if p.name not in COMPONENTS) if self.root.exists() else []}

    def _delete_directory(self, path):
        def readonly_file_retry(function, failing, exc_info):
            failing = pathlib.Path(failing)
            if (os.name != 'nt' or function not in (os.unlink, os.remove)
                    or not isinstance(exc_info[1], PermissionError)
                    or path not in failing.parents):
                raise exc_info[1]
            self.validate()
            before = regular_file(failing)
            if not getattr(before, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_READONLY:
                raise exc_info[1]
            plain_path(failing)
            after = regular_file(failing)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise RuntimeError('file changed during deletion')
            failing.chmod(before.st_mode | stat.S_IWRITE)
            function(failing)
        shutil.rmtree(path, onerror=readonly_file_retry)

    def uninstall(self, yes=False, dry_run=False):
        if not yes and not dry_run:
            raise RuntimeError('uninstall requires --yes (confirmation, not ownership)')
        receipt = self.validate()
        plan = self._plan(receipt)
        if dry_run or receipt is None or receipt['state'] == 'retired':
            return dict(plan, dry_run=dry_run)
        with self._mutex():
            receipt = self.validate()
            plan = self._plan(receipt)
            if receipt is None or receipt['state'] == 'retired':
                return plan
            receipt['state'] = 'deleting'
            self._write_receipt(receipt)
            completed = []
            try:
                for name in COMPONENTS:
                    self.validate()
                    child = self._child(name)
                    self._tree(child)
                    if child.exists():
                        if name in DIRECTORIES:
                            self._delete_directory(child)
                        else:
                            child.unlink()
                    completed.append(name)
                receipt['state'] = 'retired'
                self._write_receipt(receipt)
            except Exception as ex:
                raise RuntimeError(f'uninstall incomplete; completed={completed}; '
                                   f'pending={[n for n in COMPONENTS if n not in completed]}: {ex}') from ex
            return dict(plan, state='retired', completed=completed)
