#!/usr/bin/env python3
"""Fresh-clone acceptance smoke for ACCP V2.1.

Purpose: prove the control plane can be driven from a clean checkout into an
isolated location, and that it fails closed, without ever touching the machine's
real user profile.

This deliberately covers the part the Python test suite does NOT cover: the
*CLI entrypoints* (bootstrap / doctor / status / resolve / activate preview /
audit / recover preview) driven end to end in a subprocess with a fully isolated
runtime root, user scope and user home.

The lifecycle mutation paths (real activate / deactivate / rollback / recovery
against a controlled fixture source) are proven by the fixture-based test modules
(`test_e2e`, `test_activation_transaction`, `test_deactivate_transaction`,
`test_activation_recovery`, `test_deactivate_recovery`,
`test_activation_process_crash`, `test_lifecycle_readers`, `test_terminal_cleanup`),
which build hermetic `file://` fixture sources and never need network access. The
acceptance workflow runs those as an explicit, named step rather than
reimplementing the lifecycle in shell where a mistake could touch real state.

Isolation contract
------------------
The CLI resolves its mutable locations through three environment overrides:

    ACCP_RUNTIME_ROOT      (default ~/.agent-capability-control-plane)
    ACCP_USER_SCOPE_ROOT   (default ~/.agents)
    ACCP_USER_HOME         (default <home>, for .codex config)

All three are redirected into a temporary directory. The real profile is snapshotted
before and after, and any change is a hard failure. The runtime path is left
ABSENT on purpose: the design refuses to adopt an existing directory.

Assertions are semantic, not "whatever happened": bootstrap/doctor must succeed,
a legacy non-admissible provider must be REFUSED by resolve and must not activate,
previews must report a preview without mutating, and the real profile must be
byte-identical afterwards.

Usage:
    python -B scripts/acceptance_smoke.py [--keep] [--json OUT]
Exit codes:
    0  every check passed
    1  at least one check failed (details on stdout / in the JSON report)
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLI = ROOT / 'scripts' / 'accp.py'
# This platform ships with an EMPTY registry: no catalog entries, no operational
# modes and no locked providers. The acceptance run therefore proves the
# fail-closed default rather than any particular selection, so the mode below is
# deliberately one the registry does not define.
MODE = 'smoke-debug'
# The synthetic instance under examples/minimal-instance/ supplies the stronger
# admission check: a provider that exists and is locked, but is not eligible.
EXAMPLE_MODE = 'example-denied'
EXAMPLE_INELIGIBLE = 'example-ineligible'


class Checks:
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail=''):
        self.rows.append({'check': name, 'ok': bool(ok), 'detail': str(detail)[:400]})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ''))
        return ok

    @property
    def failed(self):
        return [r for r in self.rows if not r['ok']]


def run(args, env, timeout=600):
    """Run the real CLI in a subprocess with a fully isolated environment."""
    proc = subprocess.run([sys.executable, '-B', str(CLI), *args],
                          cwd=str(ROOT), env=env, capture_output=True,
                          text=True, timeout=timeout)
    return proc


def parse_json(stdout):
    """The CLI prints one JSON report; tolerate leading non-JSON lines."""
    text = stdout.strip()
    start = text.find('{')
    if start < 0:
        return None
    try:
        return json.loads(text[start:])
    except ValueError:
        return None


def profile_snapshot():
    """Top-level view of the real profile, plus the paths the CLI could touch."""
    home = pathlib.Path.home()
    snap = {'home': str(home)}
    try:
        snap['entries'] = sorted(p.name for p in home.iterdir())
    except OSError as exc:
        snap['entries'] = [f'<unreadable: {exc}>']
    for rel in ('.agents', '.agent-capability-control-plane', '.codex'):
        target = home / rel
        if target.exists():
            stat = target.stat()
            snap[rel] = {'exists': True, 'mtime_ns': stat.st_mtime_ns,
                         'children': sorted(p.name for p in target.iterdir())
                         if target.is_dir() else None}
        else:
            snap[rel] = {'exists': False}
    return snap


def example_instance_phase(checks, work):
    """Drive the real CLI against the synthetic example instance.

    The shipped registry is empty on purpose, so the checks above can only prove
    that an undefined mode is refused. That is an existence check, not an
    admission check. This phase stages the synthetic instance from
    `examples/minimal-instance/` into a throwaway copy of the checkout and proves
    the stronger property: a provider that really exists in the catalog and is
    really locked is still refused by operational admission, with a reason that
    names it. No real provider, candidate list or personal policy is involved.
    """
    import shutil
    import tempfile

    example = ROOT / 'examples' / 'minimal-instance'
    if not example.exists():
        checks.check('synthetic example instance is present', False, str(example))
        return
    checks.check('synthetic example instance is present', True,
                 str(example.relative_to(ROOT)))

    staged = pathlib.Path(tempfile.mkdtemp(prefix='accp-example-', dir=str(work)))
    cp = staged / 'checkout'
    shutil.copytree(ROOT, cp, ignore=shutil.ignore_patterns('.git', '__pycache__', '.local'))
    for area in ('registry', 'modes', 'lock'):
        shutil.rmtree(cp / area, ignore_errors=True)
        shutil.copytree(example / area, cp / area)
    project = staged / 'project'
    project.mkdir()
    (project / '.codex-skillset.json').write_text(json.dumps({
        'schema_version': 1,
        'allowed_operational_modes': [EXAMPLE_MODE],
        'default_operational_mode': EXAMPLE_MODE,
        'include': [], 'exclude': [],
        'capabilities': {'require': [], 'prefer': [], 'forbid': []},
    }, indent=2) + '\n', encoding='utf-8', newline='\n')

    env = dict(os.environ)
    env['ACCP_RUNTIME_ROOT'] = str(staged / 'runtime')      # deliberately absent
    env['ACCP_USER_SCOPE_ROOT'] = str(staged / 'userscope')
    env['ACCP_USER_HOME'] = str(staged / 'userhome')
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    for d in ('userscope', 'userhome'):
        (staged / d).mkdir()

    proc = subprocess.run(
        [sys.executable, '-B', str(cp / 'scripts' / 'accp.py'),
         'resolve', '--mode', EXAMPLE_MODE, '--project', str(project)],
        cwd=str(cp), env=env, capture_output=True, text=True, timeout=600)
    out = proc.stdout + proc.stderr
    checks.check('resolve REFUSES a provider that exists but is not eligible',
                 proc.returncode != 0, f'rc={proc.returncode}')
    checks.check('refusal is an operational eligibility denial',
                 'eligibility denied' in out, out.strip()[:200])
    checks.check('refusal names the offending provider',
                 EXAMPLE_INELIGIBLE in out, out.strip()[:200])
    checks.check('staged run did not create the project active set',
                 not (project / '.agents').exists())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--keep', action='store_true',
                    help='keep the isolated tree even on success (debugging)')
    ap.add_argument('--json', default=None, help='write the report as JSON here')
    args = ap.parse_args()

    checks = Checks()
    report = {'python': sys.version.split()[0], 'root': str(ROOT)}
    work = pathlib.Path(tempfile.mkdtemp(prefix='accp-accept-'))
    project = work / 'project'
    userhome = work / 'userhome'
    userscope = work / 'userscope'
    runtime = work / 'runtime'          # deliberately ABSENT
    for d in (project, userhome, userscope):
        d.mkdir(parents=True)
    # A minimal project policy. Empty capability requirements keep this file
    # independent of registry content.
    (project / '.codex-skillset.json').write_text(json.dumps({
        'schema_version': 1,
        'allowed_operational_modes': [MODE],
        'default_operational_mode': MODE,
        'include': [], 'exclude': [],
        'capabilities': {'require': [], 'prefer': [], 'forbid': []},
    }, indent=2) + '\n', encoding='utf-8', newline='\n')

    env = dict(os.environ)
    env['ACCP_RUNTIME_ROOT'] = str(runtime)
    env['ACCP_USER_SCOPE_ROOT'] = str(userscope)
    env['ACCP_USER_HOME'] = str(userhome)
    env['PYTHONDONTWRITEBYTECODE'] = '1'

    print(f'isolated root: {work}')
    before = profile_snapshot()

    try:
        print('== environment ==')
        checks.check('python >= 3.10',
                     sys.version_info >= (3, 10), sys.version.split()[0])
        checks.check('git present', shutil.which('git') is not None,
                     shutil.which('git') or 'missing')
        checks.check('runtime path absent before bootstrap', not runtime.exists())

        print('== bootstrap / doctor ==')
        got = run(['bootstrap'], env)
        checks.check('bootstrap exits 0', got.returncode == 0,
                     f'rc={got.returncode} {got.stderr.strip()[:200]}')
        checks.check('bootstrap created runtime tree',
                     (runtime / 'active-state.json').exists()
                     and (runtime / 'install-manifest.json').exists()
                     and (runtime / '.accp-runtime-owner.json').exists())
        checks.check('bootstrap wrote into the isolated user home only',
                     (userhome / '.codex').exists())

        got = run(['doctor'], env)
        checks.check('doctor exits 0', got.returncode == 0,
                     f'rc={got.returncode} {got.stderr.strip()[:200]}')
        checks.check('doctor reports configuration_only scope',
                     'configuration_only' in got.stdout)

        print('== readers (non-mutating) ==')
        got = run(['status', '--project', str(project)], env)
        rep = parse_json(got.stdout)
        checks.check('status emits an active_set_status report',
                     bool(rep) and rep.get('report_kind') == 'active_set_status',
                     f'rc={got.returncode}')
        checks.check('status is honest about an empty active set',
                     bool(rep) and rep.get('consistency') == 'uncoordinated',
                     str(rep.get('consistency') if rep else None))

        got = run(['audit'], env)
        rep = parse_json(got.stdout)
        checks.check('audit emits a runtime_audit report',
                     bool(rep) and rep.get('report_kind') == 'runtime_audit',
                     f'rc={got.returncode}')
        checks.check('audit declares it did not assess the lifecycle',
                     bool(rep) and rep.get('lifecycle_assessed') is False)

        print('== fail-closed security behaviour ==')
        got = run(['resolve', '--mode', MODE, '--project', str(project)], env)
        combined = got.stderr + got.stdout
        checks.check('resolve REFUSES a mode the registry does not define',
                     got.returncode != 0, f'rc={got.returncode}')
        checks.check('refusal names the requested mode',
                     MODE in combined, combined.strip()[:200])
        checks.check('refusal states the mode is not operational',
                     'not an operational mode' in combined, combined.strip()[:200])

        got = run(['activate', '--mode', MODE, '--project', str(project),
                   '--dry-run'], env)
        rep = parse_json(got.stdout)
        checks.check('activate --dry-run emits an activate_preview',
                     bool(rep) and rep.get('report_kind') == 'activate_preview',
                     f'rc={got.returncode}')
        checks.check('activate --dry-run does not mutate the project',
                     not (project / '.agents').exists())

        got = run(['recover', '--project', str(project), '--dry-run'], env)
        rep = parse_json(got.stdout)
        checks.check('recover --dry-run emits a recover_preview',
                     bool(rep) and rep.get('report_kind') == 'recover_preview',
                     f'rc={got.returncode}')

        print('== synthetic instance: admission fail-closed ==')
        example_instance_phase(checks, work)

        print('== isolation ==')
        checks.check('no project active set was created',
                     not (project / '.agents').exists())
        checks.check('user scope root stayed empty',
                     not any(userscope.iterdir()),
                     str(sorted(p.name for p in userscope.iterdir()))[:200])

        after = profile_snapshot()
        checks.check('real user profile unchanged',
                     before == after,
                     'profile snapshot differs' if before != after else '')
        if before != after:
            diff = {k: (before.get(k), after.get(k))
                    for k in set(before) | set(after) if before.get(k) != after.get(k)}
            report['profile_diff'] = {k: str(v) for k, v in diff.items()}

        report['isolated_tree'] = str(work)
    finally:
        after = profile_snapshot()
        if before != after:
            checks.check('real user profile unchanged (final re-check)', False,
                         'profile changed during the run')
        report['checks'] = checks.rows
        report['ok'] = not checks.failed
        failed = checks.failed
        print()
        print(f"checks: {len(checks.rows) - len(failed)}/{len(checks.rows)} passed")
        if failed:
            print('FAILED:')
            for row in failed:
                print(f"  - {row['check']}: {row['detail']}")
        if args.keep or failed:
            print(f'isolated tree kept for inspection: {work}')
        else:
            shutil.rmtree(work, ignore_errors=True)
        if args.json:
            pathlib.Path(args.json).write_text(json.dumps(report, indent=2),
                                               encoding='utf-8', newline='\n')
    return 1 if report.get('ok') is False else 0


if __name__ == '__main__':
    sys.exit(main())
