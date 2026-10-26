"""Real S/V positive control and non-executed, reason-specific AST mutations."""
import ast
import copy
from types import SimpleNamespace
from src.round8.common import sha
from .binding import AUDIT,Checker,dump,functions,parse,require_checker,checker_identity

def run(checker,s,v):
    require_checker(checker);old=s[AUDIT];new=v[AUDIT]
    positive=checker.audit_patch(old,new);rows=[]
    def case(name,mutate,expected,target='audit_dataset'):
        tree=parse(new);f=functions(tree)
        mutate(tree,f[target]);changed=ast.unparse(ast.fix_missing_locations(tree)).encode('utf-8')
        actual=checker.audit_patch(old,changed)
        rows.append(dict(case=name,kind='TEXT_AST_ONLY_NEVER_EXECUTED',source_s_sha256=sha(old),source_v_sha256=sha(new),mutated_sha256=sha(changed),mutation_target=target,
                         baseline_pass=positive['status']=='PASS',expected_reason_code=expected,actual_reason_codes=actual['errors'],actual_status=actual['status'],actual_checker=actual['checker'],
                         status='PASS' if positive['status']=='PASS' and actual['parsed'] and actual['status']!='PASS' and any(x.startswith(expected) for x in actual['errors']) else 'FAIL'))
    cases=[
        ('native_side_effect_marker',lambda t,f:f.decorator_list.append(ast.parse('native_side_effect_marker()',mode='eval').body),'FUNCTION_HEADER_CHANGED'),
        ('decorator_expression_changed',lambda t,f:f.decorator_list.append(ast.Name(id='other_decorator',ctx=ast.Load())),'FUNCTION_HEADER_CHANGED'),
        ('decorator_order_ab',lambda t,f:setattr(f,'decorator_list',[ast.Name(id=x,ctx=ast.Load()) for x in ['a','b']]),'FUNCTION_HEADER_CHANGED'),
        ('decorator_order_ba',lambda t,f:setattr(f,'decorator_list',[ast.Name(id=x,ctx=ast.Load()) for x in ['b','a']]),'FUNCTION_HEADER_CHANGED'),
        ('return_annotation',lambda t,f:setattr(f,'returns',ast.Name(id='int',ctx=ast.Load())),'FUNCTION_HEADER_CHANGED'),
        ('parameter_annotation',lambda t,f:setattr(f.args.args[0],'annotation',ast.Name(id='int',ctx=ast.Load())),'FUNCTION_HEADER_CHANGED'),
        ('positional_default',lambda t,f:f.args.defaults.append(ast.Constant(None)),'FUNCTION_HEADER_CHANGED'),
        ('keyword_default',lambda t,f:(f.args.kwonlyargs.append(ast.arg(arg='guard')),f.args.kw_defaults.append(ast.Constant(True))),'FUNCTION_HEADER_CHANGED'),
        ('posonly_parameter',lambda t,f:f.args.posonlyargs.append(f.args.args.pop(0)),'FUNCTION_HEADER_CHANGED'),
        ('vararg_parameter',lambda t,f:setattr(f.args,'vararg',ast.arg(arg='extra')),'FUNCTION_HEADER_CHANGED'),
        ('kwarg_parameter',lambda t,f:setattr(f.args,'kwarg',ast.arg(arg='extra')),'FUNCTION_HEADER_CHANGED'),
        ('type_comment',lambda t,f:setattr(f,'type_comment','(object, object) -> object'),'FUNCTION_HEADER_CHANGED'),
        ('function_name',lambda t,f:setattr(f,'name','other_audit'),'FUNCTION_INVENTORY'),
        ('async_function_kind',lambda t,f:t.body.__setitem__(t.body.index(f),ast.AsyncFunctionDef(**{k:getattr(f,k) for k in f._fields})),'FUNCTION_KIND'),
        ('duplicate_definition',lambda t,f:t.body.append(copy.deepcopy(f)),'DUPLICATE_TOP_LEVEL_DEFINITION'),
        ('outside_body',lambda t,f:f.body.insert(0,ast.Expr(value=ast.Constant('changed outside region'))),'FUNCTION_BODY_OUTSIDE_REGION'),
        ('module_definition_order',lambda t,f:t.body.insert(0,t.body.pop()),'MODULE_DEFINITION_ORDER'),
        ('helper_decorator',lambda t,f:f.decorator_list.append(ast.Name(id='decorate',ctx=ast.Load())),'HELPER_HEADER_CHANGED'),
        ('helper_return',lambda t,f:setattr(f,'returns',ast.Name(id='int',ctx=ast.Load())),'HELPER_HEADER_CHANGED'),
        ('helper_default',lambda t,f:f.args.defaults.append(ast.Constant(None)),'HELPER_HEADER_CHANGED'),
        ('helper_body',lambda t,f:f.body.append(ast.Pass()),'HELPER_BODY_CHANGED')]
    for name,mutation,reason in cases:
        # Duplicate definitions are rejected before any name dictionary is built.
        if name=='duplicate_definition':
            changed=new+b'\n'+ast.unparse(functions(parse(new))['audit_dataset']).encode()
            actual=checker.audit_patch(old,changed)
            rows.append(dict(case=name,kind='TEXT_AST_ONLY_NEVER_EXECUTED',source_s_sha256=sha(old),source_v_sha256=sha(new),mutated_sha256=sha(changed),baseline_pass=positive['status']=='PASS',expected_reason_code=reason,actual_reason_codes=actual['errors'],actual_status=actual['status'],actual_checker=actual['checker'],status='PASS' if any(x.startswith(reason) for x in actual['errors']) else 'FAIL'))
        else:case(name,mutation,reason,'audit_constraints' if name.startswith('helper_') else 'audit_dataset')
    for name,target,before,after,expected in [('module_global',AUDIT,b'B1=600',b'B1=601','MODULE_GLOBAL_OR_IMPORT_CHANGED'),('module_import',AUDIT,b'import csv,re',b'import csv as changed_csv,re','MODULE_GLOBAL_OR_IMPORT_CHANGED'),('model_callback','src/round7/experiments.py',b'Model,search_batch,integrity,ENTRY',b'OtherModel,search_batch,integrity,ENTRY','UNPROVED_EXECUTABLE_OR_CONFIG_CHANGE'),('dispatch','src/round7/experiments.py',b"task=='r7_reopen'",b"task=='changed'",'UNPROVED_EXECUTABLE_OR_CONFIG_CHANGE')]:
        mutated=dict(v);mutated[target]=v[target].replace(before,after,1)
        actual=checker.native_equivalence(s if target==AUDIT else v,mutated,allow_audit_patch=target==AUDIT)
        rows.append(dict(case=name,kind='TEXT_AST_ONLY_NEVER_EXECUTED',mutation_target=target,source_sha256=sha(v[target]),mutated_sha256=sha(mutated[target]),baseline_pass=positive['status']=='PASS',expected_reason_code=expected,actual_reason_codes=actual['errors'],actual_status=actual['status'],actual_checker=actual['checker'],status='PASS' if mutated[target]!=v[target] and any(x.startswith(expected) for x in actual['errors']) else 'FAIL'))
    from src.round8.binding import audit_patch as legacy_patch,native_equivalence as legacy_equivalence
    marker=new.replace(b'def audit_dataset(',b'@native_side_effect_marker()\ndef audit_dataset(',1)
    legacy_reproduction=legacy_patch(old,marker)
    try:require_checker(SimpleNamespace(audit_patch=legacy_patch,native_equivalence=legacy_equivalence));rejected=False
    except ValueError as exc:rejected=str(exc)=='CHECKER_ROUTE_NOT_ROUND9'
    rows.append(dict(case='old_checker_route',baseline_pass=True,expected_reason_code='CHECKER_ROUTE_NOT_ROUND9',actual_reason_codes=['CHECKER_ROUTE_NOT_ROUND9'] if rejected else [],actual_status='BLOCKED' if rejected else 'PASS',actual_checker=checker_identity(require_checker),status='PASS' if rejected else 'FAIL'))
    syntax=dict(type_params='NOT_APPLICABLE',reason='Running Python lacks FunctionDef.type_params; no syntax error counted as a successful mutation test.')
    if 'type_params' in ast.FunctionDef._fields:
        syntax=dict(type_params='SUPPORTED')
        case('type_parameters',lambda t,f:f.type_params.append(ast.TypeVar(name='T',bound=None)),'FUNCTION_HEADER_CHANGED')
    return dict(status='PASS' if positive['status']=='PASS' and all(r['status']=='PASS' for r in rows) else 'FAIL',positive_control=positive,cases=rows,case_count=len(rows),failures=sum(r['status']!='PASS' for r in rows),syntax_support=syntax,mutation_code_executed=False,legacy_boundary_reproduction=dict(checker='src.round8.binding.audit_patch',status=legacy_reproduction['status'],mutated_sha256=sha(marker),used_for_acceptance=False,impact='Actual anchored S/V headers unchanged; preserve historical K8 PASS.'))
