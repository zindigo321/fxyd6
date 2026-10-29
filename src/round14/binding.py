"""Round14 profile and exact source/attempt/output binding."""
import difflib
from pathlib import Path
import sys
import zipfile
from src.round13.common import read, write, record, require, sha, fingerprint
from src.round13.archive import safe_inventory

ROOT = Path(__file__).resolve().parents[2]
MODIFIED = {'src/round13/run.py','src/round13/seal.py'}


def allowed_new(name):
    return (name.startswith('src/round14/') and name.endswith('.py')
            or name.startswith('tests/test_round14') and name.endswith('.py')
            or name in {'tools/run_round14.py','configs/round14.json','docs/round14.md'})


def source_files(work):
    old = read(work/'starting_tracked_manifest.json')['files']
    paths = {r['relative_path'] for r in old}
    paths.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'src/round14').rglob('*.py'))
    paths.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'tests').glob('test_round14*.py'))
    paths.update(['tools/run_round14.py','configs/round14.json','docs/round14.md'])
    actual={p.relative_to(ROOT).as_posix() for folder in ['src','tools','tests','configs','docs']
            for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    require(all(allowed_new(n) for n in actual-{r['relative_path'] for r in old}), 'ADDITION_OUTSIDE_ROUND14')
    return [ROOT/p for p in sorted(paths)]


def manifest(paths, check=lambda:None):
    return [dict(record(p,check),relative_path=Path(p).relative_to(ROOT).as_posix()) for p in paths]


def verify_sources(rows, check=lambda:None):
    require(len({r['relative_path'].casefold() for r in rows})==len(rows), 'DUPLICATE_SOURCE_PATH')
    for row in rows:
        require((ROOT/row['relative_path']).resolve().is_relative_to(ROOT), 'SOURCE_PATH_ESCAPE')
        require(Path(row['path']).resolve()==(ROOT/row['relative_path']).resolve(), 'SOURCE_ABSOLUTE_PATH')
        require(record(row['path'],check)=={k:row[k] for k in ('path','bytes','sha256')}, 'FROZEN_SOURCE_CHANGED: '+row['relative_path'])


def freeze(work, cfg, metadata, check):
    rows=manifest(source_files(work),check)
    old=read(work/'starting_tracked_manifest.json')['files']
    now={r['relative_path']:r for r in rows}
    changes=[]
    with zipfile.ZipFile(work/'starting_tracked_source.zip') as original:
        for before in old:
            name=before['relative_path']; after=now[name]
            if (before['bytes'],before['sha256']) != (after['bytes'],after['sha256']):
                require(name in MODIFIED,'UNAUTHORIZED_TRACKED_MODIFICATION: '+name)
                changes.append(dict(relative_path=name,before=before,after=after))
                diff=''.join(difflib.unified_diff(original.read(name).decode('utf-8-sig').splitlines(True),
                     (ROOT/name).read_text(encoding='utf-8-sig').splitlines(True),fromfile='starting/'+name,tofile='round14/'+name))
                dest=work/'frozen'/(Path(name).stem+'.diff');dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(diff,encoding='utf8')
    additions=set(now)-{r['relative_path'] for r in old}
    require(all(allowed_new(n) for n in additions),'ADDITION_OUTSIDE_ROUND14')
    write(work/'frozen/change_policy.json',dict(profile='ROUND14_V1',changes=changes,additions=sorted(additions),
          unchanged_starting_files=len(old)-len(changes),allowed_modified=sorted(MODIFIED)))
    contract=dict(profile='ROUND14_V1',config=cfg,metadata=metadata,neighborhood=metadata['neighborhood'],
        source_manifest_identity=fingerprint(rows),frozen_before_any_new_candidate=True,
        numerical_policy=dict(absolute_tolerance_s=1e-6,relative_tolerance=0,interval_merge_s=1e-6,
          improvement_minimum_s=1,improvement_ambiguous_band_s=1e-6,classification='exact; near 1-second threshold conservatively rejected'),
        constraints=['28 legal unique states','all 3 targets have >=2 merged visits','mask exactly fully covered',
          'T100 finite <=604800','T90/T100/Tavg <= replay baseline +1e-6'],
        ranking=['Tmax','Tavg','T100','T90','identity'],search_expansion_permitted=False,
        parsing_independence='Shared validated loader/schema/mask; separate minimum, order-statistic, interval, feasibility and selection algorithms')
    write(work/'frozen/consumer_code.json',rows);write(work/'frozen/contract.json',contract)
    with zipfile.ZipFile(work/'frozen/consumer_code.zip','w',zipfile.ZIP_DEFLATED) as z:
        for row in rows:z.write(row['path'],row['relative_path'])
    return rows


def artifacts(out):
    return [dict(relative_path=p.relative_to(out).as_posix(),bytes=p.stat().st_size,sha256=sha(p))
            for p in sorted(Path(out).rglob('*')) if p.is_file()]


def verify_attempt(attempt, final_rows, check=lambda:None):
    attempt=Path(attempt); consumer=read(attempt/'consumer_code.json'); command=read(attempt/'command_result.json')
    require(consumer==final_rows==command['code_manifest'],'ATTEMPT_CONSUMER_VERSION_MISMATCH')
    verify_sources(final_rows,check)
    require(command['attempt_id']==attempt.name and Path(command['output']).resolve()==(attempt/'output').resolve(),'ATTEMPT_PATH_MISMATCH')
    argv=command['command']
    expected=[sys.executable,'-X','utf8','-B','-m','src.round14.worker','--work',str(attempt.parent.parent),
              '--out',str(attempt/'output'),'--job',command['job']]
    require(argv==expected,'ATTEMPT_COMMAND_MISMATCH')
    require(command['output_artifacts']==artifacts(attempt/'output'),'ATTEMPT_OUTPUT_ARTIFACT_MISMATCH')
    result=read(attempt/'output/job_result.json')
    require(result['attempt_id']==attempt.name and result['job']==command['job'] and result['consumer_identity']==fingerprint(final_rows),'WORKER_ATTEMPT_BINDING')
    require(result['exit_code']==command['python_exit_code'],'WORKER_EXIT_BINDING')
    require(command['job'] in {'science','tests','legacy','guards'} and command.get('timeout') is False,
            'ATTEMPT_INCOMPLETE_OR_UNKNOWN_JOB')
    require(result['status']=='PASS' and result['exit_code']==0, 'ATTEMPT_NOT_PASS')
    require(read(attempt/'supervised_result.json')==result and command['supervised_result_exit_code']==0,
            'ATTEMPT_SUPERVISED_RESULT_BINDING')
    with zipfile.ZipFile(attempt/'consumer_code.zip') as z:
        safe_inventory(z.infolist())
        require(set(z.namelist())=={r['relative_path'] for r in final_rows},'ATTEMPT_SNAPSHOT_SET')
        for row in final_rows:
            blob=z.read(row['relative_path'])
            require(len(blob)==row['bytes'] and __import__('hashlib').sha256(blob).hexdigest()==row['sha256'],
                    'ATTEMPT_SNAPSHOT_BYTES')
    return dict(status='PASS',attempt_id=attempt.name,job=command['job'],command=argv,
                consumer_identity=fingerprint(final_rows),output_artifacts_identity=fingerprint(command['output_artifacts']))
