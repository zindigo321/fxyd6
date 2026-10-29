"""Version-exact isolated 202/89 suites and the unchanged 26-case binder."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from src.round13.common import read, write, record, require, sha, fingerprint
from .binding import ROOT, starting

DEFAULT_R14 = Path('G:/gpt-file/Codex/outputs/bd-fmb/round14/20261029T063900_offline')
R14_MANIFEST_SHA = '07604d5753d83ef20ddad3c435254213e3b548167bef09be63c3fe6c33d1aa62'

# This generated adapter selects the existing R14 tests only.  The copied
# production code, test files, test IDs, and assertions are never rewritten.
R14_SITE = '''from guard_impl import install
install()
import json, os, unittest
_discover = unittest.defaultTestLoader.discover
_calls = []
def _round15_discover(start_dir, pattern='test*.py', top_level_dir=None):
    if str(start_dir) == 'tests' and pattern == 'test*.py' and top_level_dir is None and not _calls:
        _calls.append(1)
        with open(os.environ['ROUND15_SELECTION_LOG'], 'w', encoding='utf8') as stream:
            json.dump(dict(source='unchanged src.round9.regression.worker', start_dir='tests',
                requested_pattern='test*.py', selected_pattern='test_round14*.py', test_files_modified=False), stream)
        return _discover(start_dir, pattern='test_round14*.py', top_level_dir=top_level_dir)
    return _discover(start_dir, pattern=pattern, top_level_dir=top_level_dir)
unittest.defaultTestLoader.discover = _round15_discover
'''


def relative(row, root=ROOT):
    return row.get('relative_path') or Path(row['path']).relative_to(root).as_posix()


def subset168(rows, root=ROOT):
    result = []
    for row in rows:
        name = relative(row, root)
        if (name.startswith('src/round14/') or name.startswith('tests/test_round14') or
                name in {'tools/run_round14.py', 'configs/round14.json', 'docs/round14.md'}):
            continue
        result.append({key: row[key] for key in ['path', 'bytes', 'sha256']})
    require(len(result) == 168, 'REGRESSION_SUBSET168_COUNT')
    return result


def verify_mapping(root, repo, subset, check=lambda: None):
    root, repo = Path(root), Path(repo)
    mapping = []
    for source in subset:
        check()
        name = relative(source, root)
        current = record(source['path'], check)
        require((current['bytes'], current['sha256']) == (source['bytes'], source['sha256']), 'REGRESSION_SOURCE_VERSION_MISMATCH')
        target = repo/name
        require(target.resolve().is_relative_to(repo.resolve()) and not target.is_symlink(), 'REGRESSION_COPY_PATH')
        copied = record(target, check)
        require((copied['bytes'], copied['sha256']) == (source['bytes'], source['sha256']), 'REGRESSION_COPY_VERSION_MISMATCH')
        mapping.append(dict(relative_path=name, source=current, executed_copy=copied))
    return mapping


def test_ids(log):
    rows = []
    for line in Path(log).read_text(encoding='utf8').splitlines():
        # An assertion can deliberately exercise argparse, which writes its
        # usage to stderr in the middle of unittest's pending status line.
        # Successful completion is checked independently in tests.json.
        match = re.match(r'^\w+ \(([^)]+)\) \.\.\.', line)
        if match:
            rows.append(match.group(1))
    require(len(rows) == len(set(rows)), 'DUPLICATED_ACTUAL_TEST_IDS')
    return rows


def verify_ids(log, expected_log, count):
    actual, expected = test_ids(log), test_ids(expected_log)
    require(len(actual) == len(expected) == count and set(actual) == set(expected), 'HISTORICAL_TEST_ID_SET_MISMATCH')
    return dict(status='PASS', count=count, ids=actual, identity=fingerprint(sorted(actual)), expected_log=record(expected_log))


def bound_historical_log(r14, relative_name):
    sealed=Path(r14)/'sealed';manifest=sealed/'artifact_manifest.json'
    require(sha(manifest)==R14_MANIFEST_SHA,'REGRESSION_R14_MANIFEST_ANCHOR')
    members={row['path']:row for row in read(manifest)['files']}
    require(relative_name in members,'REGRESSION_HISTORICAL_LOG_NOT_BOUND')
    expected=members[relative_name];path=sealed/relative_name
    require(path.stat().st_size==expected['bytes'] and sha(path)==expected['sha256'],'REGRESSION_HISTORICAL_LOG_BYTES')
    return path


def run_old202(work, out, life):
    from src.round9 import regression as old
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    subset = subset168(starting(work))
    write(out/'subset168.json', subset)
    original = old.subprocess.run
    check = lambda: life.check(True)

    def observed_run(argv, **kwargs):
        if '--regression-worker' not in argv:
            return original(argv, **kwargs)
        repo = out/'regression/repo'
        write(out/'mapping_before.json', verify_mapping(ROOT, repo, subset, check))
        kwargs['timeout'] = min(kwargs.get('timeout', 170), life.timeout())
        try:
            return original(argv, **kwargs)
        finally:
            write(out/'mapping_after.json', verify_mapping(ROOT, repo, subset, check))

    old.subprocess.run = observed_run
    try:
        result = old.run_regression(ROOT, out, subset)
    finally:
        old.subprocess.run = original
    require(result['status'] == 'PASS' and result['tests'] == 202 and
            not any(result[key] for key in ['failures', 'errors', 'skipped']), 'ORIGINAL_202_TEST_FAILURE')
    cfg = read(ROOT/'configs/round15.json')
    r14 = Path(cfg.get('r14_delivery', DEFAULT_R14))
    ids = verify_ids(out/'regression/stderr.log', bound_historical_log(r14,'legacy/regression/stderr.log'), 202)
    write(out/'test_id_verification.json', ids)
    return result


def run_r14_89(work, out, life):
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    repo, guard, tmp = out/'repo', out/'guard', out/'tmp'
    for directory in [repo, guard, tmp, repo/'work']:
        directory.mkdir(parents=True)
    subset = starting(work)
    require(len(subset) == 185, 'ROUND14_REGRESSION_SUBSET185_COUNT')
    check = lambda: life.check(True)
    for row in subset:
        check()
        name = relative(row)
        dest = repo/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        require(record(row['path'], check) == {key: row[key] for key in ['path', 'bytes', 'sha256']}, 'ROUND14_SUBSET_SOURCE_CHANGED')
        shutil.copyfile(row['path'], dest)
    write(out/'subset185.json', subset)
    write(out/'mapping_before.json', verify_mapping(ROOT, repo, subset, check))
    shutil.copyfile(ROOT/'src/round9/guard.py', guard/'guard_impl.py')
    (guard/'sitecustomize.py').write_text(R14_SITE, encoding='utf8')
    write(out/'suite_selection_adapter.json', dict(profile='ROUND15_ISOLATED_R14_TEST_SELECTION_V1',
        content=R14_SITE, sitecustomize=record(guard/'sitecustomize.py'), guard=record(guard/'guard_impl.py'),
        consumer_adapter=record(Path(__file__)), modifications_to_185_copied_files=False))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8',
        PYTHONPATH=str(guard)+os.pathsep+str(repo), TMP=str(tmp), TEMP=str(tmp), MPLCONFIGDIR=str(out/'mpl'),
        ROUND9_REGRESSION='1', ROUND9_WRITE_ROOTS=json.dumps([str(out)]), ROUND9_GUARD_LOG=str(out/'guard.jsonl'),
        ROUND14_TEST_ROOT=str(tmp), ROUND13_TEST_ROOT=str(tmp), ROUND15_SELECTION_LOG=str(out/'suite_selection.json'))
    argv = [sys.executable, '-B', str(repo/'tools/run_round9.py'), '--regression-worker', '--result', str(out/'tests.json')]
    start = time.perf_counter()
    timeout = life.timeout()
    try:
        with (out/'stdout.log').open('wb') as stdout, (out/'stderr.log').open('wb') as stderr:
            proc = subprocess.run(argv, cwd=repo, env=env, stdout=stdout, stderr=stderr, timeout=timeout)
    finally:
        write(out/'mapping_after.json', verify_mapping(ROOT, repo, subset, check))
    result = read(out/'tests.json') if (out/'tests.json').exists() else dict(successful=False, tests=0)
    events = [json.loads(line) for line in (out/'guard.jsonl').read_text(encoding='utf8').splitlines()]
    denied = [event for event in events if event['kind'] == 'denied']
    result.update(status='PASS' if proc.returncode == 0 and result['successful'] and not denied else 'FAIL',
        argv=argv, exit_code=proc.returncode, elapsed_s=time.perf_counter()-start, enforced_timeout_s=timeout,
        guard_denials=denied, guard_installations=sum(event['kind'] == 'guard_installed' for event in events),
        stdout=record(out/'stdout.log'), stderr=record(out/'stderr.log'), guard=record(out/'guard.jsonl'),
        subset_files=185, source_files_modified=False, selected_test_pattern='test_round14*.py')
    write(out/'result.json', result)
    require(result['status'] == 'PASS' and result['tests'] == 89 and
            not any(result[key] for key in ['failures', 'errors', 'skipped']), 'ROUND14_89_TEST_FAILURE')
    require(read(out/'suite_selection.json')['selected_pattern'] == 'test_round14*.py', 'ROUND14_TEST_SELECTION_NOT_BOUND')
    cfg = read(ROOT/'configs/round15.json')
    r14 = Path(cfg.get('r14_delivery', DEFAULT_R14))
    ids = verify_ids(out/'stderr.log', bound_historical_log(r14,'tests/tests.log'), 89)
    write(out/'test_id_verification.json', ids)
    return result


def run_binding26(work, out, life):
    from src.round10.binding import bind
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    cfg = read(ROOT/'configs/round15.json')
    prior = Path(cfg['prior'])/'executed_closure'
    frozen = read(prior/'starting_code_manifest.json')['files']
    require(len(frozen) == 142, 'FROZEN142_COUNT')
    mapping = []
    for row in frozen:
        life.check(True)
        require(record(row['path']) == row, 'FROZEN142_CHANGED')
        mapping.append(dict(relative_path=Path(row['path']).relative_to(ROOT).as_posix(),
            source=row, actual_read_path=row['path'], isolation='read-only fixed historical binder; no source copy'))
    write(out/'subset142.json', frozen); write(out/'source_mapping.json', mapping)
    binding, cases = bind(Path(read(ROOT/'configs/round12.json')['k9']), ROOT, frozen, out, out)
    require(binding['status'] == cases['status'] == 'PASS' and len(cases['cases']) == 26, 'HISTORICAL_BINDING_COUNTEREXAMPLES')
    for row in frozen:
        require(record(row['path']) == row, 'FROZEN142_CHANGED_AFTER_BINDING')
    return dict(status='PASS', cases=26, binding=binding, historical_stage_map=binding['historical_stage_map'])


def run_regressions(work, out, life):
    out = Path(out)
    old = run_old202(work, out/'old202', life)
    r14 = run_r14_89(work, out/'round14_89', life)
    historical = run_binding26(work, out/'binding26', life)
    result = dict(status='PASS', regression_tests=202, old_tests=202, round14_tests=89,
        original_test_total=291, binding_counterexamples=26, regression=old,
        round14_regression=r14, historical_binding=historical,
        untouched_source_files=185, generated_adapter_changes_test_selection_only=True)
    write(out/'regression_summary.json', result)
    return result
