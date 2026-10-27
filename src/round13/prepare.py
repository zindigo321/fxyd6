"""Bind immutable inputs and materialize only the evidence used by this round."""
import ast
import hashlib
from pathlib import Path
import shutil
import subprocess
import zipfile
from .archive import Archive
from .common import read, write, require, record, sha
from .control import Lifecycle

ROOT = Path(__file__).resolve().parents[2]


def prepare(work):
    life = Lifecycle(work / 'lifecycle.json')
    cfg = read(ROOT / 'configs/round13.json')
    for args in [['rev-parse','HEAD'],['status','--porcelain=v1','-uall'],['diff','--no-ext-diff'],['diff','--cached','--no-ext-diff']]:
        name='git_'+args[0]+('_cached' if '--cached' in args else '')+'.txt'
        if not (work/name).exists():
            p=subprocess.run(['git',*args],cwd=ROOT,capture_output=True,timeout=min(30,life.remaining()))
            (work/name).write_bytes(p.stdout+p.stderr)
    prior = Path(cfg['prior']) / 'executed_closure'
    old = read(prior / 'code_manifest.json')
    identity = hashlib.sha256(__import__('json').dumps(old['files'], sort_keys=True, ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    require(identity == cfg['old_code_identity'] and len(old['files']) == 149, 'K12_CODE_MANIFEST_IDENTITY')
    for row in old['files']:
        require(record(row['path'], life.check) == row, 'OLD_CODE_BYTES_CHANGED')
        p = Path(row['path'])
        if p.suffix == '.py':
            tree = ast.parse(p.read_text(encoding='utf-8-sig'))
            require(not any(isinstance(n, (ast.Import, ast.ImportFrom)) and 'round13' in ast.unparse(n) for n in ast.walk(tree)), 'OLD_CODE_IMPORTS_ROUND13')
    write(work / 'old_code_before.json', old)
    with zipfile.ZipFile(work / 'old_code_snapshot.zip', 'w', zipfile.ZIP_DEFLATED) as z:
        for row in old['files']:
            z.write(row['path'], Path(row['path']).relative_to(ROOT).as_posix())
    audit = Path(cfg['audit'])
    reuse = {}
    for name in ['comparison_and_plan.md', 'independent_package_integrity.json', 'methods_and_protocol_audit.json']:
        reuse[name] = record(audit / name, life.check)
        shutil.copyfile(audit / name, work / ('reused_' + name))
    integrity = read(audit / 'independent_package_integrity.json')
    require(integrity['package']['sha256'] == cfg['archive_sha256'] and integrity['manifest']['manifest_sha256'] == cfg['manifest_sha256'], 'AUDIT_INPUT_BINDING')
    require(not integrity['manifest']['mismatches'] and integrity['manifest']['checked'] == 13315, 'PRIOR_INTEGRITY_FAILURE')
    write(work / 'reused_evidence.json', dict(status='REUSED', scope='Full-package 13315 member SHA/CRC audit; current archive and all used members freshly verified', sources=reuse))
    arc = Archive(cfg, work / 'vendor', life.check)
    try:
        names = arc.manifest['files']
        required = [n for n in names if n.startswith(('competition_v1/config/', 'competition_v1/src/famou/', 'stable_app/src/famou/'))]
        required += ['competition_v1/research/canonical_global_coordinates.npy', 'competition_v1/research/historical_dataset/dataset_index.json', 'competition_v1/research/historical_dataset/dataset_arrays.npz', 'competition_v1/research/historical_dataset/historical_protocol_scope.json', 'competition_v1/runs/component_catalog_v1/catalog.json', 'competition_v1/runs/component_catalog_v1/first_hits.npy']
        required += [n for n in names if n.startswith('stable_app/frontend/dist/assets/N') and n.endswith(('_metadata.json', '_orbits.csv'))]
        required += [n for n in names if n.endswith('.docx') or ('任务' in n and n.endswith(('.md', '.txt'))) or n == 'competition_v1/research/amendment_01.json']
        for c in cfg['cases'].values():
            if 'path' not in c:
                continue
            base = c['path']
            required += [n for n in names if n.startswith(base + '/') and ('/executed_source/' in n or n.endswith(('.json', '.py', '.sn', '.at', '.sc', '.sa')) or n.endswith(('/global_grid.csv', '/global_first_hits.csv', '/access_raw.csv', '/orbits.csv', '/EOP-v1.1.txt')))]
        for n in dict.fromkeys(required):
            arc.path(n)
        cat = arc.json('competition_v1/runs/component_catalog_v1/catalog.json')
        selected = set()
        for c in cfg['cases'].values():
            if 'path' in c:
                selected.update(arc.json(c['path'] + '/promotion.json')['choice']['indices'])
        for index in sorted(selected):
            asset = cat['assets'][index]
            for kind, data in [('global', 'hits.npz'), ('regional', 'intervals.json')]:
                base = 'competition_v1/runs/access_library/' + kind + '/' + asset[kind + '_key']
                arc.path(base + '/entry.json'); arc.path(base + '/' + data)
        write(work / 'input_binding.json', dict(status='PASS', archive=record(cfg['archive'], life.check), manifest_sha256=cfg['manifest_sha256'], members=cfg['archive_members'], selected_assets=len(selected), vendor=arc.preserve(), old_code_files=149, reused_full_package_audit=True, lifecycle_elapsed_upper_bound_s=life.elapsed()))
        write(work / 'prepared_members.json', sorted(arc.used))
    finally:
        arc.close()
    life.phase('implementation_replay')
    print('INPUT_BOUND', len(required), 'selected assets', len(selected), 'elapsed upper bound', life.elapsed())


if __name__ == '__main__':
    import sys
    prepare(Path(sys.argv[1]))
