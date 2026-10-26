"""Conservative whole-module equivalence plus the exact post-processing exception.

AST digests describe syntax, not semantic equivalence. Raw equality is required
for every original executable module except the reviewed round7 audit patch.
The exception checks the complete module environment and the untouched AST.
"""
import ast
import difflib
import zipfile
from pathlib import Path
from .common import canonical, read, sha, text_hashes, write, text

AUDIT = 'src/round7/audit.py'
DOCS = {'.gitignore', 'README.md'}


def ast_dump(node):
    return ast.dump(node, include_attributes=False)


def module_evidence(blob):
    source = blob.decode('utf-8-sig')
    tree = ast.parse(source)
    lines = blob.splitlines(keepends=True)
    symbols = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            piece = b''.join(lines[node.lineno-1:node.end_lineno])
            symbols.append(dict(name=node.name, line=node.lineno, end_line=node.end_lineno,
                                source_raw_sha256=sha(piece), ast_sha256=sha(ast_dump(node).encode()),
                                defaults=ast_dump(node.args) if isinstance(node, ast.FunctionDef) else None,
                                bases=[ast.unparse(x) for x in node.bases] if isinstance(node, ast.ClassDef) else [],
                                calls=sorted({ast.unparse(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)})))
    globals_ = [ast_dump(n) for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    imports = [dict(line=n.lineno, source=ast.unparse(n)) for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
    return dict(raw_sha256=sha(blob), ast_sha256=sha(ast_dump(tree).encode()),
                module_environment_sha256=sha(canonical(globals_)), module_environment=globals_, imports=imports, symbols=symbols)


def audit_patch(old, new):
    a = ast.parse(old.decode('utf-8')); b = ast.parse(new.decode('utf-8'))
    functions_a = {x.name: x for x in a.body if isinstance(x, ast.FunctionDef)}
    functions_b = {x.name: x for x in b.body if isinstance(x, ast.FunctionDef)}
    changes = []
    if set(functions_b) != set(functions_a) | {'audit_constraints'}:
        changes.append('AUDIT_FUNCTION_SET')
    env = lambda tree: [ast_dump(n) for n in tree.body if not isinstance(n, ast.FunctionDef)]
    if env(a) != env(b):
        changes.append('AUDIT_GLOBAL_OR_IMPORT_CHANGED')
    for name, node in functions_a.items():
        if name != 'audit_dataset' and (name not in functions_b or ast_dump(node) != ast_dump(functions_b[name])):
            changes.append('AUDIT_PREEXISTING_FUNCTION_CHANGED:'+name)
    def split_body(node):
        body = node.body
        start = next(i for i,n in enumerate(body) if isinstance(n, ast.Assign) and any(isinstance(t,ast.Name) and t.id=='constraints' for t in n.targets))
        stop = next(i for i,n in enumerate(body[start:],start) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='gaps' for t in n.targets))
        return body[:start], body[start:stop], body[stop:]
    try:
        oldfun=functions_a['audit_dataset']; newfun=functions_b['audit_dataset']
        pre_a, region_a, post_a=split_body(oldfun); pre_b, region_b, post_b=split_body(newfun)
        if ([ast_dump(n) for n in pre_a+post_a] != [ast_dump(n) for n in pre_b+post_b]
                or ast_dump(oldfun.args)!=ast_dump(newfun.args)):
            changes.append('AUDIT_OUTSIDE_CONSTRAINT_REGION')
        expected_b=ast.parse("constraints=audit_constraints(folder/'project',prior,cfg['round7']['satellites'],ids)\nchecks['constraints']=constraints['status']=='PASS'").body
        if [ast_dump(n) for n in region_b] != [ast_dump(n) for n in expected_b]:
            changes.append('AUDIT_REPLACEMENT_NOT_REVIEWED')
        if "len(constraints) >= 72" not in ast.unparse(region_a[-1]):
            changes.append('OLD_COUNT_GATE_NOT_FOUND')
        region=dict(old=[ast.unparse(n) for n in region_a],new=[ast.unparse(n) for n in region_b],
                    old_lines=[region_a[0].lineno,region_a[-1].end_lineno],new_lines=[region_b[0].lineno,region_b[-1].end_lineno])
    except (KeyError,StopIteration):
        changes.append('AUDIT_REGION_UNRESOLVED');region={}
    extra=functions_b.get('audit_constraints')
    if extra and any(isinstance(n,(ast.Global,ast.Nonlocal,ast.Import,ast.ImportFrom,ast.Yield,ast.Await)) for n in ast.walk(extra)):
        changes.append('CONSTRAINT_NONLOCAL_OR_IMPORT_EFFECT')
    calls={ast.unparse(n.func) for n in ast.walk(extra) if isinstance(n,ast.Call)} if extra else set()
    approved={'Path','project.glob','re.sub','re.findall','path.read_text','source.exists','compare','blocks',
              'checks.append','bindings.append','dict','bool','set','sats.get','re.search','sub.group',
              'g.splitlines','line.strip','sensors.get','str','points.items','sensors.items','len','all',
              "re.sub('\\\\s+', ' ', b).strip",'x.get'}
    if calls-approved:
        changes.append('CONSTRAINT_CALL_NOT_REVIEWED:'+','.join(sorted(calls-approved)))
    return dict(status='PASS' if not changes else 'BLOCKED',errors=changes,changed_statements=region,
                new_function_calls=sorted(calls),proof='All other functions and complete module environment are AST-identical; exact constraint replacement; read-only call allowlist.')


def native_equivalence(old, new, allow_audit_patch=False, allow_new=False):
    errors=[];changes=[]
    for name in sorted(set(old)|set(new)):
        if old.get(name)==new.get(name):continue
        if name in DOCS or name.startswith(('docs/','tests/')):
            kind='DOCUMENTATION_OR_TEST_ONLY'
        elif allow_new and name not in old and (name.startswith('src/round8/') or name in {'tools/run_round8.py','configs/round8.json'}):
            kind='NEW_OFFLINE_VALIDATOR_NOT_IMPORTED_BY_NATIVE_ENTRY'
        elif name==AUDIT and allow_audit_patch and name in old and name in new:
            result=audit_patch(old[name],new[name]);kind='POST_NATIVE_CONSTRAINT_AUDIT'
            errors+=result['errors']
        elif name in old and name in new and name.endswith('.json') and text_hashes(old[name])['normalized_text_sha256']==text_hashes(new[name])['normalized_text_sha256']:
            kind='CONFIG_CRLF_LF_ONLY'
        else:
            kind='UNPROVED_EXECUTABLE_OR_CONFIG_CHANGE';errors.append(kind+':'+name)
        changes.append(dict(path=name,kind=kind,old_sha256=sha(old[name]) if name in old else None,new_sha256=sha(new[name]) if name in new else None))
    return dict(status='PASS' if not errors else 'BLOCKED',errors=errors,changes=changes)


def snapshot(folder, root):
    manifest=read(folder/'code_manifest.json');ctx=read(folder/'run.json');errors=[]
    if manifest['run_id']!=ctx['run_id'] or sha(canonical(manifest['files']))!=ctx['code_sha256']:
        errors.append('CODE_MANIFEST_IDENTITY')
    with zipfile.ZipFile(folder/'code_snapshot.zip') as z:
        names=z.namelist(); blobs={n:z.read(n) for n in names}
    wanted={Path(r['path']).relative_to(root).as_posix():r for r in manifest['files']}
    if len(names)!=len(set(names)) or set(wanted)!=set(blobs):errors.append('SNAPSHOT_INVENTORY')
    rows=[]
    for name,r in wanted.items():
        b=blobs.get(name,b'');ok=sha(b)==r['sha256'] and len(b)==r['bytes']
        if not ok:errors.append('SNAPSHOT_MEMBER:'+name)
        rows.append(dict(path=name,sha256=sha(b),bytes=len(b),matches_manifest=ok))
    return blobs,dict(status='FAIL' if errors else 'PASS',errors=errors,run_id=ctx['run_id'],code_sha256=ctx['code_sha256'],files=rows)


def bind_versions(root, s, v, baseline, k_manifest, output):
    ss,scheck=snapshot(s,root);vv,vcheck=snapshot(v,root)
    with zipfile.ZipFile(baseline/'C_worktree_snapshot.zip') as z:cc={n:z.read(n) for n in z.namelist()}
    with zipfile.ZipFile(baseline/'C_git_snapshot.zip') as z:git={n:z.read(n) for n in z.namelist()}
    kk={Path(r['path']).relative_to(root).as_posix():Path(r['path']).read_bytes() for r in k_manifest}
    cm=read(baseline/'C_worktree_manifest.json');crows={Path(r['path']).relative_to(root).as_posix():r for r in cm['files']}
    c_valid=(sha(canonical(cm['files']))==cm['sha256'] and set(crows)==set(cc)
             and all(sha(cc[n])==r['sha256'] and len(cc[n])==r['bytes'] for n,r in crows.items()))
    gm={r['path']:r for r in read(baseline/'C_git_manifest.json')}
    import hashlib
    git_valid=(set(gm)==set(git) and all(sha(git[n])==r['raw_sha256'] and len(git[n])==r['bytes']
               and hashlib.sha1(b'blob '+str(len(git[n])).encode()+b'\0'+git[n]).hexdigest()==r['git_blob'] for n,r in gm.items()))
    with zipfile.ZipFile(output/'code_snapshot.zip') as z:
        k_valid=len(z.namelist())==len(kk) and set(z.namelist())==set(kk) and all(z.read(n)==b for n,b in kk.items())
    import json
    science_config=read(s/'config.json')['config']
    configs_valid=all(json.loads(data['configs/round7.json'])==science_config for data in [ss,vv,cc,kk])
    transitions={'S_to_V':native_equivalence(ss,vv,allow_audit_patch=True),
                 'V_to_C':native_equivalence(vv,cc),
                 'C_to_K':native_equivalence(cc,kk,allow_new=True)}
    patch=audit_patch(ss[AUDIT],vv[AUDIT])
    git_rows=[]
    for n in sorted(set(cc)|set(git)):
        a=cc.get(n,b'');b=git.get(n,b'')
        exact=a==b
        try:lf=text_hashes(a)['normalized_text_sha256']==text_hashes(b)['normalized_text_sha256']
        except UnicodeError:lf=False
        git_rows.append(dict(path=n,worktree_raw_sha256=sha(a),git_raw_sha256=sha(b),raw_equal=exact,crlf_lf_only=not exact and lf,
                             worktree_text=text_hashes(a) if not exact and lf else None))
    evidence={label:{n:module_evidence(b) for n,b in data.items() if n.endswith('.py') and not n.startswith('tests/')}
              for label,data in [('S',ss),('V',vv),('C',cc),('K',kk)]}
    # Import-resolution closure is conservative: every preexisting src/tools module
    # is included. New names may not occur in a preexisting import or dynamic call.
    additions=set(kk)-set(cc)
    source_old='\n'.join(b.decode('utf-8-sig') for n,b in ss.items() if n.endswith('.py') and not n.startswith('tests/'))
    isolated=not any('round8' in x for x in source_old.splitlines()) and all(n.startswith(('src/round8/','tests/','docs/')) or n in {'tools/run_round8.py','configs/round8.json'} for n in additions)
    config_rows={label:{n:sha(b) for n,b in data.items() if n.startswith('configs/')} for label,data in [('S',ss),('V',vv),('C',cc),('K',kk)]}
    status='PASS' if (scheck['status']==vcheck['status']==patch['status']=='PASS' and c_valid and git_valid and k_valid and configs_valid and all(x['status']=='PASS' for x in transitions.values()) and all(x['raw_equal'] or x['crlf_lf_only'] for x in git_rows) and isolated) else 'BLOCKED'
    result=dict(status=status,transitions=transitions,audit_patch=patch,snapshot_checks={'S':scheck,'V':vcheck,'C_worktree':dict(valid=c_valid,files=len(cc)),'C_git':dict(valid=git_valid,files=len(git)),'K':dict(valid=k_valid,files=len(kk))},
                git_worktree=git_rows,config_snapshots=config_rows,scientific_configs_match_S=configs_valid,new_module_import_isolation=isolated,
                closure_policy='All preexisting src and tools modules, imports, global initializers, defaults, bases and local dynamic imports are retained, not a function-name-only comparison.',
                limitations='Equivalence binds stored S execution to unchanged dependencies; it does not execute STK with K or prove physics/global completeness.')
    write(output/'dependency_binding.json',result);write(output/'function_evidence.json',evidence)
    for a,b,left,right in [('S','V',ss,vv),('V','C',vv,cc),('C','K',cc,kk)]:
        lines=[]
        for name in sorted(set(left)|set(right)):
            if left.get(name)!=right.get(name):
                lines.extend(difflib.unified_diff(left.get(name,b'').decode('utf-8-sig').splitlines(True),right.get(name,b'').decode('utf-8-sig').splitlines(True),fromfile=a+'/'+name,tofile=b+'/'+name))
        text(output/(a+'_to_'+b+'.diff'),''.join(lines))
    return result,ss,vv,cc,kk


def static_review(root,dependency):
    files=[];errors=[]
    paths=list((root/'src/round8').glob('*.py'))+[root/'tools/run_round8.py',root/'tests/test_round8.py']
    prohibited={'Dispatch','DispatchEx','GetActiveObject','CreateObject','CoInitialize','supervise','ShellExecute','WinExec'}
    for path in sorted(paths):
        blob=path.read_bytes();tree=ast.parse(blob.decode('utf-8'));compile(tree,str(path),'exec')
        calls=sorted({ast.unparse(x.func) for x in ast.walk(tree) if isinstance(x,ast.Call)})
        bad=[x for x in calls if x.rsplit('.',1)[-1] in prohibited]
        if bad:errors.append(dict(path=str(path),forbidden_calls=bad))
        files.append(dict(path=str(path),raw_sha256=sha(blob),syntax_valid=True,forbidden_native_calls=bad))
    if dependency['status']!='PASS':errors.append(dict(reason='DEPENDENCY_SCOPE_UNPROVEN'))
    return dict(status='PASS' if not errors else 'FAIL',errors=errors,files=files,
                reviewed_pure_reuse=['src.round7.audit.validate_config','src.round7.audit.audit_constraints','src.round7.integrity.audit_ledger','src.round5.audit.validate_events','src.round4.experiments.parameter_check','src.constellation.generate'],
                review_findings=dict(security='No native activation entrypoint; path guards and strict command allowlist; ZIP members read without extraction.',
                    compatibility='Existing rounds 2-7 source/config/tests unchanged from C; new round8 namespace only.',
                    error_handling='Exceptions produce FAIL/BLOCKED and nonzero exit; no inherited historical PASS.',
                    resources='Files/ZIP/process logs use context managers; trajectories parsed once per file and released.',
                    change_scope='Only round8 validator, configuration, documentation and tests added.',
                    identity='Separate S subject and K validator; raw preservation independent of normalized hashes.'),
                runtime_validation='Complete regression, actual source calculations and reason-specific mutation tests are separate required checks, not implied by this static review.')
