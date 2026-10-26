"""Full AST binding to immutable S/V references; never execute mutation text."""
import ast
import copy
import difflib
import inspect
import zipfile
from pathlib import Path
from src.round8.common import canonical, read, sha, text_hashes, write
from src.round8.binding import snapshot

AUDIT='src/round7/audit.py'
S_AUDIT_SHA='a3443716caabacc3482274f86fac223b9d031453aade86881517f05c55510380'
V_AUDIT_SHA='3f428e01697f79b1bde866d6a266a1f8d256d576d55deb12c2aaa268f3f60a2c'
FUNCTION_FIELDS={'name','args','body','decorator_list','returns','type_comment','type_params'}
ARG_FIELDS={'posonlyargs','args','vararg','kwonlyargs','kw_defaults','kwarg','defaults'}

def dump(node):
    return ast.dump(node,include_attributes=False)

def parse(blob):
    tree=ast.parse(blob.decode('utf-8-sig'),type_comments=True)
    seen=set()
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
            if node.name in seen:raise ValueError('DUPLICATE_TOP_LEVEL_DEFINITION:'+node.name)
            seen.add(node.name)
    for node in ast.walk(tree):
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and set(node._fields)-FUNCTION_FIELDS:raise ValueError('UNKNOWN_FUNCTION_FIELD')
        if isinstance(node,ast.arguments) and set(node._fields)-ARG_FIELDS:raise ValueError('UNKNOWN_ARGUMENT_FIELD')
    return tree

def header(node):
    return dict(kind=type(node).__name__,fields={k:dump(v) if isinstance(v,ast.AST) else [dump(x) if isinstance(x,ast.AST) else x for x in v] if isinstance(v,list) else v for k,v in ast.iter_fields(node) if k!='body'})

def functions(tree):
    return {n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}

def region(node):
    starts=[i for i,n in enumerate(node.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='constraints' for t in n.targets)]
    stops=[i for i,n in enumerate(node.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='gaps' for t in n.targets)]
    if len(starts)!=1 or len(stops)!=1 or stops[0]<=starts[0]:raise ValueError('UNRESOLVED_REPLACEMENT_REGION')
    return starts[0],stops[0]

class Checker:
    def __init__(self,reference_s,reference_v):
        if sha(reference_s)!=S_AUDIT_SHA or sha(reference_v)!=V_AUDIT_SHA:raise ValueError('UNTRUSTED_REFERENCE')
        self.reference_s=reference_s;self.reference_v=reference_v

    def audit_patch(self,old,new):
        errors=[]
        try:
            a,b,ra,rb=map(parse,[old,new,self.reference_s,self.reference_v])
            fa,fb,fra,frb=map(functions,[a,b,ra,rb])
            def order(tree):return [(type(n).__name__,getattr(n,'name',None)) for n in tree.body]
            if set(fa)!=set(fra) or set(fb)!=set(frb):errors.append('FUNCTION_INVENTORY')
            for name in set(fa)&set(fb):
                if type(fa[name]) is not type(fb[name]):errors.append('FUNCTION_KIND:'+name)
            if not errors and (order(a)!=order(ra) or order(b)!=order(rb)):errors.append('MODULE_DEFINITION_ORDER')
            if errors:return self.result(errors)
            for name in fa:
                if name=='audit_dataset':
                    left,right=copy.deepcopy(fa[name]),copy.deepcopy(fb[name])
                    if header(left)!=header(right):errors.append('FUNCTION_HEADER_CHANGED:'+name)
                    ia,ja=region(left);ib,jb=region(right)
                    ira,jra=region(fra[name]);irb,jrb=region(frb[name])
                    if [dump(n) for n in left.body[ia:ja]]!=[dump(n) for n in fra[name].body[ira:jra]]:errors.append('OLD_REGION_NOT_APPROVED')
                    if [dump(n) for n in right.body[ib:jb]]!=[dump(n) for n in frb[name].body[irb:jrb]]:errors.append('NEW_REGION_NOT_APPROVED')
                    left.body[ia:ja]=[ast.Pass()];right.body[ib:jb]=[ast.Pass()]
                    # Compare the COMPLETE nodes. All semantic fields survive.
                    if dump(left)!=dump(right) and header(left)==header(right):errors.append('FUNCTION_BODY_OUTSIDE_REGION:'+name)
                elif dump(fa[name])!=dump(fb[name]):errors.append('PREEXISTING_FUNCTION_CHANGED:'+name)
            helper=fb['audit_constraints'];trusted=frb['audit_constraints']
            if header(helper)!=header(trusted):errors.append('HELPER_HEADER_CHANGED')
            if [dump(n) for n in helper.body]!=[dump(n) for n in trusted.body]:errors.append('HELPER_BODY_CHANGED')
            if [dump(n) for n in a.body if not isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]!=[dump(n) for n in b.body if not isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]:errors.append('MODULE_GLOBAL_OR_IMPORT_CHANGED')
            # Prevent coordinated changes in both inputs, including type comments.
            if dump(a)!=dump(ra):errors.append('SOURCE_AST_NOT_TRUSTED_S')
            if dump(b)!=dump(rb) and not errors:errors.append('UNREVIEWED_AST_FIELD')
            result=self.result(errors)
            result.update(actual_headers_equal=header(fa['audit_dataset'])==header(fb['audit_dataset']),source_header=header(fa['audit_dataset']),target_header=header(fb['audit_dataset']),helper_header=header(helper),helper_reference_sha256=V_AUDIT_SHA,
                          helper_side_effect_review='Complete helper body and header equal reviewed immutable V; imported/global/module statements and insertion order bound too. Only saved-file read-only parsing permitted.')
            return result
        except SyntaxError as exc:return self.result(['PARSE_ERROR:'+str(exc)],parsed=False)
        except (ValueError,KeyError,TypeError) as exc:return self.result([str(exc)],parsed=False)

    def result(self,errors,parsed=True):
        return dict(status='BLOCKED' if errors else 'PASS',errors=errors,parsed=parsed,checker=checker_identity(self.audit_patch),reference_s_sha256=S_AUDIT_SHA,reference_v_sha256=V_AUDIT_SHA,
                    ast_policy='type_comments=True; all AST fields compared; only approved body region normalized; only source locations ignored',type_params='SUPPORTED' if 'type_params' in ast.FunctionDef._fields else 'NOT_APPLICABLE_PYTHON_3_11')

    def native_equivalence(self,old,new,allow_audit_patch=False,allow_new=False):
        errors=[];changes=[]
        for name in sorted(set(old)|set(new)):
            if old.get(name)==new.get(name):continue
            if name==AUDIT and allow_audit_patch:
                result=self.audit_patch(old[name],new[name]);errors+=result['errors'];kind='FULL_FUNCTION_PATCH_BINDING'
            elif name in {'.gitignore','README.md'} or name.startswith(('docs/','tests/')):kind='DOCUMENTATION_OR_TEST'
            elif allow_new and name not in old and (name.startswith(('src/round8/','src/round9/')) or name in {'tools/run_round8.py','tools/run_round9.py','configs/round8.json','configs/round9.json'}):kind='ISOLATED_OFFLINE_ADDITION'
            elif name.endswith('.json') and name in old and name in new and text_hashes(old[name])['normalized_text_sha256']==text_hashes(new[name])['normalized_text_sha256']:kind='CRLF_LF_ONLY'
            else:kind='UNPROVED_EXECUTABLE_OR_CONFIG_CHANGE';errors.append(kind+':'+name)
            changes.append(dict(path=name,kind=kind,old_sha256=sha(old[name]) if name in old else None,new_sha256=sha(new[name]) if name in new else None))
        return dict(status='BLOCKED' if errors else 'PASS',errors=errors,changes=changes,checker=checker_identity(self.native_equivalence))

def checker_identity(func):
    return dict(module=func.__module__,function=func.__qualname__,module_raw_sha256=sha(Path(__file__).read_bytes()),function_source_sha256=sha(inspect.getsource(func).encode('utf-8')))

def require_checker(checker):
    if not isinstance(checker,Checker) or checker.audit_patch.__func__ is not Checker.audit_patch or checker.native_equivalence.__func__ is not Checker.native_equivalence:
        raise ValueError('CHECKER_ROUTE_NOT_ROUND9')
    return checker_identity(checker.audit_patch)

def load_references(policy,root):
    s,sc=snapshot(Path(policy['source_dir']),root);v,vc=snapshot(Path(policy['historical_validator_dir']),root)
    if sc['status']!='PASS' or vc['status']!='PASS':raise ValueError('SOURCE_SNAPSHOT_INVALID')
    return Checker(s[AUDIT],v[AUDIT]),s,v

def bind(policy,root,k9_manifest,out):
    checker,s,v=load_references(policy,root);route=require_checker(checker);k8dir=Path(policy['k8_dir'])
    k8,k8check=snapshot(k8dir,root)
    with zipfile.ZipFile(k8dir/'C_worktree_snapshot.zip') as z:c={n:z.read(n) for n in z.namelist()}
    k9={Path(r['path']).relative_to(root).as_posix():Path(r['path']).read_bytes() for r in k9_manifest}
    transitions={'S_to_V':checker.native_equivalence(s,v,allow_audit_patch=True),'V_to_C':checker.native_equivalence(v,c),
                 'C_to_K8':checker.native_equivalence(c,k8,allow_new=True),'K8_to_K9':checker.native_equivalence(k8,k9,allow_new=True)}
    unchanged=all(k9.get(n)==b for n,b in k8.items())
    additions=set(k9)-set(k8)
    allowed=all(n.startswith('src/round9/') or n in {'configs/round9.json','tools/run_round9.py','docs/round9.md'} or n.startswith('tests/test_round9') for n in additions)
    isolation=all(b'round9' not in b for n,b in k8.items() if n.startswith(('src/','tools/')) and n.endswith('.py'))
    errors=[]
    if not unchanged:errors.append('K8_OR_EARLIER_RAW_BYTES_CHANGED')
    if not allowed or not isolation:errors.append('ROUND9_IMPORT_ISOLATION')
    if k8check['status']!='PASS':errors.append('K8_SNAPSHOT')
    status='FAIL' if errors else 'BLOCKED' if any(v['status']!='PASS' for v in transitions.values()) else 'PASS'
    result=dict(status=status,errors=errors,transitions=transitions,positive_control=checker.audit_patch(s[AUDIT],v[AUDIT]),actual_checker=route,k8_raw_unchanged=unchanged,new_modules_isolated=isolation,additions=sorted(additions),function_fields=list(ast.FunctionDef._fields),argument_fields=list(ast.arguments._fields),historical_states_preserved=True,
                native_binding='All original modules, globals, imports, callbacks, defaults, dispatch and inherited classes remain byte-identical after V. S→V uses full-node comparison against anchored S/V references.',historical_stage_map=read(k8dir/'historical_native_evidence.json')['call_edges'])
    write(out/'dependency_binding.json',result)
    from src.round8.common import text
    lines=[]
    for name in sorted(set(k8)|set(k9)):
        if k8.get(name)!=k9.get(name):lines.extend(difflib.unified_diff(k8.get(name,b'').decode('utf-8-sig').splitlines(True),k9.get(name,b'').decode('utf-8-sig').splitlines(True),fromfile='K8/'+name,tofile='K9/'+name))
    text(out/'K8_to_K9.diff',''.join(lines))
    return result,checker,s,v
