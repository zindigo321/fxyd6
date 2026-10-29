"""ROUND18 source policy and exact executed-attempt version binding."""
import hashlib
from pathlib import Path
import sys
import zipfile

from src.round13.archive import safe_name, safe_inventory
from src.round13.common import read, write, record, require, sha, fingerprint

ROOT = Path(__file__).resolve().parents[2]
JOBS = {'science', 'tests', 'legacy', 'regression', 'r14regression', 'guards', 'checker', 'certificate'}


def allowed_new(name):
    try:
        name = safe_name(name)
    except ValueError:
        return False
    return (name.startswith('src/round18/') and name.endswith('.py')
            or name.startswith('tests/test_round18') and name.endswith('.py') and Path(name).parent.as_posix() == 'tests'
            or name in {'tools/run_round18.py', 'configs/round18.json', 'docs/round18.md', 'tools/export_round18.py'})


def starting(work):
    work = Path(work)
    for name in ['starting_code_manifest.json', 'starting_tracked_manifest.json', 'r14_code_before.json']:
        if (work/name).exists():
            data = read(work/name)
            return data['files'] if isinstance(data, dict) else data
    raise FileNotFoundError('ROUND18_STARTING_SOURCE_MANIFEST_MISSING')


def source_files(work):
    old = starting(work)
    old_names = {row.get('relative_path', Path(row['path']).relative_to(ROOT).as_posix()) for row in old}
    names = set(old_names)
    names.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'src/round18').rglob('*.py'))
    names.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'tests').glob('test_round18*.py'))
    names.update(['tools/run_round18.py', 'tools/export_round18.py', 'configs/round18.json', 'docs/round18.md'])
    actual = {p.relative_to(ROOT).as_posix() for folder in ['src', 'tools', 'tests', 'configs', 'docs']
              for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    require(all(allowed_new(n) for n in actual-old_names), 'ADDITION_OUTSIDE_ROUND18')
    require(old_names.issubset(actual | {n for n in old_names if '/' not in n}), 'STARTING_SOURCE_MISSING')
    return [ROOT/name for name in sorted(names)]


def manifest(paths, check=lambda: None):
    return [dict(record(path, check), relative_path=Path(path).relative_to(ROOT).as_posix()) for path in paths]


def verify_sources(rows, check=lambda: None):
    require(bool(rows), 'EMPTY_CONSUMER_SOURCE_MANIFEST')
    names = [safe_name(row['relative_path']) for row in rows]
    require(len({name.casefold() for name in names}) == len(rows), 'DUPLICATE_SOURCE_PATH')
    resolved = set()
    for row, name in zip(rows, names):
        check()
        path = ROOT/name
        target = path.resolve()
        require(target.is_relative_to(ROOT.resolve()), 'SOURCE_PATH_ESCAPE')
        require(not path.is_symlink() and all(not p.is_symlink() for p in path.parents if p.is_relative_to(ROOT)), 'SOURCE_LINK_REJECTED')
        require(target == Path(row['path']).resolve(), 'SOURCE_ABSOLUTE_PATH')
        require(str(target).casefold() not in resolved, 'DUPLICATE_RESOLVED_SOURCE_PATH')
        resolved.add(str(target).casefold())
        require(record(row['path'], check) == {k: row[k] for k in ['path', 'bytes', 'sha256']}, 'FROZEN_SOURCE_CHANGED: '+name)


def freeze(work, cfg, metadata, check=lambda: None):
    work = Path(work)
    old = starting(work)
    require(len(old) == 245, 'STARTING_R17_SOURCE_COUNT')
    for row in old:
        require(record(row['path'], check) == {k: row[k] for k in ['path', 'bytes', 'sha256']}, 'R17_SOURCE_BYTES_CHANGED')
    rows = manifest(source_files(work), check)
    verify_sources(rows, check)
    old_names = {row.get('relative_path', Path(row['path']).relative_to(ROOT).as_posix()) for row in old}
    additions = sorted(row['relative_path'] for row in rows if row['relative_path'] not in old_names)
    require(all(allowed_new(name) for name in additions), 'ADDITION_OUTSIDE_ROUND18')
    frozen = work/'frozen'
    require(not frozen.exists(), 'FROZEN_CONTRACT_ALREADY_EXISTS')
    frozen.mkdir()
    write(frozen/'change_policy.json', dict(profile='ROUND18_V1', unchanged_prior_files=245,
        allowed_modified=[], additions=additions, historical_profiles_modified=False))
    contract = dict(profile='ROUND18_V1', config=cfg, metadata=metadata,
        source_manifest_identity=fingerprint(rows), frozen_before_new_candidate=True,
        declared_candidates=231066, fixed_remove=1284, excluded_donor=705,
        anchor_donors=[28,218,1801,2021], anchor_identities=metadata['anchor_identities'],
        original_baseline_identity=cfg['baseline_identity'],
        enumeration='r ascending from B except1284; unordered (a,b) numeric lexicographic from D except705; at least one A4',
        certificate_priority=['T100','T90','FULL'],
        thresholds=dict(tau100='replayed original baseline mask T100 +1e-6',
            tau90='replayed original baseline mask T90 +1e-6',n=43070,k90=38763),
        anchor_selection='Four existing R16 only-T90-failed anchors 28/218/1801/2021, all replayed; none is admissible reference',
        numerical_policy=dict(absolute_tolerance_s=1e-6,relative_tolerance=0,interval_merge_s=1e-6,
            substantive_improvement='original_baseline_Tmax - candidate_Tmax - 1e-6 >= 1'),
        constraints=['28 unique legal states at their own saved altitudes 500..700km',
            'each of three targets >=2 merged visits','exact full mask coverage',
            'T100 finite <=604800','mask T90/T100 and pooled internal Tavg <= original baseline +1e-6'],
        ranking=['Tmax','Tavg','T100','T90','identity'],
        certificate_semantics='Known infeasible on exactly one verified necessary gate; all uncomputed full metrics null/NOT_EVALUATED',
        shared_boundary='Validated decoder, coordinates, mask, state tokens; independent minima, order statistic, regional merge, Boolean certificates, selection and exact enumeration',
        research_scope='Conditional saved mixed altitudes; remaining four anchors excluding R17 intersection; no protocol change, native run or expanded neighborhood',
        physical_protocol_identity=cfg['native_protocol_hash'],
        input_anchors={k:cfg[k] for k in ['archive_sha256','matrix_sha256','catalog_sha256','promotion_sha256']})
    write(frozen/'consumer_code.json', rows)
    write(frozen/'contract.json', contract)
    with zipfile.ZipFile(frozen/'consumer_code.zip', 'w', zipfile.ZIP_DEFLATED) as snapshot:
        for row in rows:
            snapshot.write(row['path'], row['relative_path'])
    return rows


def artifacts(out, check=lambda: None):
    out = Path(out)
    result = []
    for path in sorted(out.rglob('*')):
        if path.is_file():
            check()
            require(not path.is_symlink(), 'OUTPUT_LINK_REJECTED')
            result.append(dict(relative_path=path.relative_to(out).as_posix(), bytes=path.stat().st_size, sha256=sha(path, check)))
    return result


def verify_attempt(attempt, final_rows, check=lambda: None):
    attempt = Path(attempt).resolve()
    require(attempt.parent.name == 'attempts', 'ATTEMPT_SCOPE')
    consumer = read(attempt/'consumer_code.json')
    command = read(attempt/'command_result.json')
    require(consumer == final_rows == command['code_manifest'], 'ATTEMPT_CONSUMER_VERSION_MISMATCH')
    verify_sources(final_rows, check)
    out = attempt/'output'
    require(command['attempt_id'] == attempt.name and Path(command['output']).resolve() == out, 'ATTEMPT_PATH_MISMATCH')
    job = command['job']
    require(job in JOBS, 'ATTEMPT_UNKNOWN_JOB')
    expected = [sys.executable, '-X', 'utf8', '-B', '-m', 'src.round18.worker',
        '--work', str(attempt.parent.parent), '--out', str(out), '--job', job]
    require(command['command'] == expected, 'ATTEMPT_COMMAND_MISMATCH')
    require(command['output_artifacts'] == artifacts(out, check), 'ATTEMPT_OUTPUT_ARTIFACT_MISMATCH')
    result = read(out/'job_result.json')
    require(result['attempt_id'] == attempt.name and result['job'] == job and
            result['consumer_identity'] == fingerprint(final_rows), 'WORKER_ATTEMPT_BINDING')
    require(result['status'] == 'PASS' and result['exit_code'] == 0 and
            command['python_exit_code'] == 0 and command.get('timeout') is False, 'ATTEMPT_NOT_COMPLETED_PASS')
    require(read(attempt/'supervised_result.json') == result and command['supervised_result_exit_code'] == 0,
            'ATTEMPT_SUPERVISED_RESULT_BINDING')
    with zipfile.ZipFile(attempt/'consumer_code.zip') as snapshot:
        safe_inventory(snapshot.infolist())
        require(set(snapshot.namelist()) == {row['relative_path'] for row in final_rows}, 'ATTEMPT_SNAPSHOT_SET')
        for row in final_rows:
            check()
            blob = snapshot.read(row['relative_path'])
            require(len(blob) == row['bytes'] and hashlib.sha256(blob).hexdigest() == row['sha256'], 'ATTEMPT_SNAPSHOT_BYTES')
    return dict(status='PASS', profile='ROUND18_V1', attempt_id=attempt.name, job=job,
        command=command['command'], consumer_identity=fingerprint(final_rows),
        output_artifacts_identity=fingerprint(command['output_artifacts']),
        code_snapshot_sha256=sha(attempt/'consumer_code.zip', check))
