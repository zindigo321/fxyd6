"""Isolate code and complete small boundary inputs; preserve no test identities."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from .common import file_record, read, write


def run_regression(root,work,k_manifest):
    base=work/'regression';repo=base/'repo';guard=base/'guard';tmp=base/'tmp'
    for p in [repo,guard,tmp,repo/'work']:p.mkdir(parents=True,exist_ok=True)
    for row in k_manifest:
        p=Path(row['path']);dest=repo/p.relative_to(root);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
    data=[]
    for path in (root/'data').rglob('*'):
        if path.is_file() and path.suffix in {'.geojson','.at'}:
            dest=repo/path.relative_to(root);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dest);data.append(file_record(path))
    if sum(Path(x['path']).suffix=='.at' for x in data)!=3 or sum(Path(x['path']).suffix=='.geojson' for x in data)!=2:
        raise ValueError('REGRESSION_BOUNDARY_AT_INPUTS_MISSING')
    shutil.copyfile(root/'src/round8/guard.py',guard/'guard_impl.py')
    (guard/'sitecustomize.py').write_bytes(b'from guard_impl import install\ninstall()\n')
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8',PYTHONPATH=str(guard)+os.pathsep+str(repo),
             TMP=str(tmp),TEMP=str(tmp),MPLCONFIGDIR=str(base/'mpl'),ROUND8_REGRESSION='1',
             ROUND8_WRITE_ROOTS=__import__('json').dumps([str(base)]),ROUND8_GUARD_LOG=str(base/'guard.jsonl'))
    argv=[sys.executable,'-B',str(repo/'tools/run_round8.py'),'--regression-worker','--result',str(base/'tests.json')]
    start=time.perf_counter()
    with (base/'stdout.log').open('wb') as stdout,(base/'stderr.log').open('wb') as stderr:
        proc=subprocess.run(argv,cwd=repo,env=env,stdout=stdout,stderr=stderr)
    result=read(base/'tests.json') if (base/'tests.json').exists() else dict(successful=False,tests=0)
    guards=[__import__('json').loads(x) for x in (base/'guard.jsonl').read_text(encoding='utf-8').splitlines()]
    denied=[x for x in guards if x['kind']=='denied']
    result.update(status='PASS' if proc.returncode==0 and result['successful'] and not denied else 'FAIL',
                  argv=argv,exit_code=proc.returncode,elapsed_s=time.perf_counter()-start,data_inputs=data,guard_denials=denied,
                  child_guard_installations=sum(x['kind']=='guard_installed' for x in guards),
                  test_fixture='Only test detector defaults to controlled missing-install result; explicit error/missing fixtures preserved; source modules unchanged. Native imports/processes denied in every child.',
                  stdout=file_record(base/'stdout.log'),stderr=file_record(base/'stderr.log'),guard=file_record(base/'guard.jsonl'))
    write(base/'result.json',result)
    return result


def worker(result_path):
    import unittest
    suite=unittest.defaultTestLoader.discover('tests')
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    write(result_path,dict(tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),successful=result.wasSuccessful(),
                           failures_detail=[dict(test=str(t),traceback=e) for t,e in result.failures+result.errors]))
    return 0 if result.wasSuccessful() else 1
