"""Strict K9 -> K10 transition, retaining the fixed round9 checker upstream."""
import ast
import difflib
from pathlib import Path
from src.round8.common import read, sha, text, write
from src.round9 import binding as legacy, header_cases
from .bounds import identity


def allowed_addition(name):
    return (name.startswith('src/round10/') and name.endswith('.py')
            or name.startswith('tests/test_round10') and name.endswith('.py')
            or name in {'tools/run_round10.py','configs/round10.json','docs/round10.md'})


def transition(old, new):
    errors=[]
    if any(new.get(n)!=b for n,b in old.items()):errors.append('K9_RAW_BYTES_CHANGED')
    additions=set(new)-set(old)
    if any(not allowed_addition(n) for n in additions):errors.append('K10_ADDITION_NOT_ALLOWED')
    for name, blob in old.items():
        if name.endswith('.py') and name.startswith(('src/','tools/')):
            tree=ast.parse(blob.decode('utf-8-sig'))
            for node in ast.walk(tree):
                if isinstance(node,(ast.Import,ast.ImportFrom)) and 'round10' in ast.unparse(node):
                    errors.append('PRODUCTION_IMPORTS_ROUND10')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,original_files=len(old),
                unchanged_files=sum(new.get(n)==b for n,b in old.items()),additions=sorted(additions),
                checker=identity(transition),raw_bytes_required=True,normalization_used=False)


def require_transition(function):
    if function is not transition:raise ValueError('CHECKER_ROUTE_NOT_ROUND10_TRANSITION')
    return identity(function)


def bind(k9, root, manifest, out, work):
    policy=read(k9/'config.json')['policy']; previous=work/'legacy_route';previous.mkdir()
    result,checker,s,v=legacy.bind(policy,root,read(k9/'code_manifest.json')['files'],previous)
    legacy.require_checker(checker)
    old,verified=legacy.snapshot(k9,root)
    new={Path(r['path']).relative_to(root).as_posix():Path(r['path']).read_bytes() for r in manifest}
    require_transition(transition)
    current=transition(old,new)
    if verified['status']!='PASS':raise ValueError('K9_SNAPSHOT_INVALID')
    transitions=dict(result['transitions'],K9_to_K10=current)
    answer=dict(status='PASS' if result['status']=='PASS' and current['status']=='PASS' else 'FAIL',
                transitions=transitions,upstream_checker=result['actual_checker'],transition_checker=current['checker'],
                route='src.round9.binding fixed S/V/C/K8/K9; src.round10.binding.transition strict K9/K10',
                upstream_allowlist_unchanged=True,historical_stage_map=result['historical_stage_map'])
    write(out/'dependency_binding.json',answer)
    diff=[]
    for n in sorted(set(old)|set(new)):
        if old.get(n)!=new.get(n):
            diff.extend(difflib.unified_diff(old.get(n,b'').decode('utf-8-sig').splitlines(True),new.get(n,b'').decode('utf-8-sig').splitlines(True),fromfile='K9/'+n,tofile='K10/'+n))
    text(out/'K9_to_K10.diff',''.join(diff))
    # The transition route is new: actually rerun every old fixed-checker case.
    rerun=header_cases.run(checker,s,v);rerun['execution']='REEXECUTED_ROUND10_UNCHANGED_ROUND9_CHECKER'
    write(out/'binding_counterexamples_rerun.json',rerun)
    return answer,rerun
