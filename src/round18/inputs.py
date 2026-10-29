"""R18 read-only full-catalog adapter and byte-bound R17 reuse evidence."""
import hashlib
import json
from pathlib import Path
import zipfile

from src.round13.archive import safe_name
from src.round13.common import read, require, record, sha, fingerprint
from src.round16 import inputs as prior_inputs
from .science import neighborhood_summary

ROOT = Path(__file__).resolve().parents[2]
R17_SEALED = '68c0a436c84102344a2e3afb144ca12b88f370b35d3c9f5a6893673568c39902'
R17_TRANSPORT = '76d914b4e92fa9ac2b722bc73d3a6a1adcdebe0c57beaddc85ff1392410b8163'
R17_DELIVERY = 'd95ed8d31fe285de7480f5b6ce7aa7c04876ae447595d5da249d1d987b03b13f'
R17_ZIP = 'caef7a821832e72bbadfd555261c6dc2058efee6c158d9a0e63c5e9ec23d12c8'


def prior_binding(cfg, check=lambda: None):
    base = Path(cfg['r17_delivery']).resolve()
    layers = [('sealed', 'artifact_manifest.json', 'receipt.json', R17_SEALED),
              ('', 'transport_manifest.json', 'transfer_receipt.json', R17_TRANSPORT),
              ('', 'delivery_manifest.json', 'delivery_receipt.json', R17_DELIVERY)]
    verified = {}
    for sub, manifest_name, receipt_name, digest in layers:
        check()
        folder = base/sub
        require(sha(folder/manifest_name, check) == digest, 'R18_R17_MANIFEST_ANCHOR:'+manifest_name)
        manifest, receipt = read(folder/manifest_name), read(folder/receipt_name)
        require(receipt['manifest_sha256'] == digest, 'R18_R17_RECEIPT_BINDING')
        expected, folded = set(), set()
        for row in manifest['files']:
            check()
            name = safe_name(row['path']); path = folder/name
            require(name.casefold() not in folded and path.resolve().is_relative_to(folder)
                    and not path.is_symlink() and all(not p.is_symlink() for p in path.parents if p.is_relative_to(folder)),
                    'R18_R17_MANIFEST_SCOPE')
            folded.add(name.casefold()); expected.add(name)
            require(path.stat().st_size == row['bytes'] and sha(path, check) == row['sha256'],
                    'R18_R17_MANIFEST_BYTES:'+name)
        actual = {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}
        extras = {manifest_name, receipt_name}
        if manifest_name == 'transport_manifest.json':
            extras |= {'completion/export_command_result.json','completion/stdout.log','completion/stderr.log',
                       'completion/export_shell_result.json','completion/cumulative_timing.json',
                       'delivery_manifest.json','delivery_receipt.json'}
        require(actual == expected|extras, 'R18_R17_EXACT_SET:'+manifest_name)
        verified[manifest_name] = dict(files=len(expected), sha256=digest, exact_set_verified=True)
    sealed = base/'sealed'
    require(sha(sealed/'frozen/consumer_code.zip', check) == R17_ZIP, 'R18_R17_SOURCE_ZIP')
    old = read(sealed/'frozen/consumer_code.json')
    require(len(old) == len({r['relative_path'] for r in old}) == 245, 'R18_OLD245_COUNT')
    for row in old:
        name = safe_name(row['relative_path']); path = ROOT/name
        require(path.resolve().is_relative_to(ROOT) and not path.is_symlink(), 'R18_OLD_SOURCE_SCOPE')
        require(path.stat().st_size == row['bytes'] and sha(path, check) == row['sha256'], 'R18_OLD_SOURCE_BYTES:'+name)
    used = {}
    for name in ['report.md','final_status.json','frozen/contract.json','frozen/consumer_code.json',
                 'consumer_version_binding.json','science/baseline.json','science/anchor_selection.json',
                 'science/five_anchor_checker.json','science/candidates.jsonl','science/necessary_gate_context.json',
                 'science/enumeration_completion.json']:
        path = sealed/name
        # Decode all human/machine evidence as UTF-8; contents never become executable instructions.
        path.read_text(encoding='utf8')
        used[name] = record(path, check)
    for name in ['transport/scientific_supplement.md','completion/export_command_result.json',
                 'completion/export_shell_result.json','completion/cumulative_timing.json']:
        (base/name).read_text(encoding='utf8'); used[name] = record(base/name, check)
    for row in read(base/'transport_manifest.json')['files']:
        source = Path(read(base/'transfer_receipt.json')['source_work'])/row['source_path']
        require(source.stat().st_size == row['bytes'] and sha(source, check) == row['sha256'],
                'R18_R17_ORIGINAL_WORK_BYTES')
    final = read(sealed/'final_status.json')
    require(final['status'] == 'PASS' and final['exit_code'] == 0, 'R18_R17_STATUS')
    command = read(base/'completion/export_command_result.json')
    shell = read(base/'completion/export_shell_result.json')
    require(command['export_process_exit_code'] == 0 and command['export_shell_exit_code'] is None,
            'R18_R17_EXPORT_EXIT')
    require(shell['export_launcher_python_exit_code'] == shell['export_shell_exit_code'] == 0,
            'R18_R17_OUTER_EXIT')
    audit = Path(cfg['r17_audit']); audit_evidence = {}
    for name in ['round17_audit_and_plan.md','evidence/science_audit.json',
                 'evidence/strategy_summary.json','evidence/diagnostic.json']:
        path = audit/name; path.read_text(encoding='utf-8-sig'); audit_evidence[name] = record(path, check)
    return dict(status='PASS', reuse_status='REUSED', layers=verified,
        sealed_manifest_sha256=R17_SEALED, transport_manifest_sha256=R17_TRANSPORT,
        delivery_manifest_sha256=R17_DELIVERY, source_zip_sha256=R17_ZIP,
        old245_current_bytes_verified=True, old245_count=245, used_evidence=used,
        audit_evidence=audit_evidence, audit_is_new_candidate_evaluation=False,
        completion=read(sealed/'science/enumeration_completion.json'), new_R18_candidates_evaluated=0)


def metadata_from(catalog, promotion, check=lambda: None):
    result = prior_inputs.metadata_from(catalog, promotion, check)
    states = {int(i): s for i,s in result['states'].items()}
    result['space_summary'] = neighborhood_summary(result['baseline_indices'], result['donor_indices'], states, check)
    result.update(scope='Remaining four R16 anchor second repairs excluding all 705 combinations',
                  fixed_remove=1284, anchor_donors=[28,218,1801,2021], excluded_donor=705)
    return result


def r16_anchor_records(cfg, check=lambda: None):
    result = []
    with (Path(cfg['r16_delivery'])/'sealed/science/candidates.jsonl').open(encoding='utf8') as stream:
        for n,line in enumerate(stream):
            if n%128 == 0: check()
            item = json.loads(line)
            if item['feasibility']['rejection_reasons'] == ['T90_s_WORSE_THAN_BASELINE'] and item['improvement']['substantive_improvement']:
                result.append(item)
    require(len(result) == 5 and {r['add'] for r in result} == {28,218,705,1801,2021}, 'R18_R16_ANCHOR_SET')
    return result


def metadata(cfg, work=None, check=lambda: None):
    prior = prior_binding(cfg, check)
    with zipfile.ZipFile(cfg['archive']) as z:
        prior_inputs.archived.safe_inventory(z.infolist())
        require(len(z.infolist()) == cfg['archive_members'], 'R18_ARCHIVE_MEMBERS')
        prefix = cfg['archive_root']+'/'
        cat, pro = z.read(prefix+prior_inputs.CATALOG), z.read(prefix+prior_inputs.PROMOTION)
        require(hashlib.sha256(cat).hexdigest() == cfg['catalog_sha256'], 'R18_CATALOG_ANCHOR')
        require(hashlib.sha256(pro).hexdigest() == cfg['promotion_sha256'], 'R18_PROMOTION_ANCHOR')
    result = metadata_from(json.loads(cat), json.loads(pro), check)
    anchors = r16_anchor_records(cfg, check)
    result['anchor_identities'] = {str(r['add']):r['identity'] for r in anchors if r['add'] != 705}
    result['r17_prior_binding'] = prior
    baseline = read(Path(cfg['r17_delivery'])/'sealed/science/baseline.json')
    result['original_reference_thresholds'] = dict(tau100=baseline['effective_grid']['T100_s']+1e-6,
        tau90=baseline['effective_grid']['T90_s']+1e-6,k90=(9*baseline['effective_grid']['points']+9)//10,
        reference_identity=baseline['identity'])
    result['diagnostic_role'] = 'Input identities and enumeration only; no new R18 numerical evaluation'
    return result


def load(cfg, work, check=lambda: None):
    # The formal immutable metadata has already bound R17; verify all original catalog bytes afresh here.
    lib = prior_inputs.load(cfg, work, check)
    try:
        lib.r16_anchor_records = r16_anchor_records(cfg, check)
        lib.r17_baseline = read(Path(cfg['r17_delivery'])/'sealed/science/baseline.json')
        lib.metadata['space_summary'] = neighborhood_summary(lib.baseline_indices, lib.donor_indices, lib.states, check)
        lib.metadata['scope'] = '231066 remaining four-anchor repairs; no 705; no bridge filter'
        lib.evidence['round18_adapter'] = 'Fresh all2171 NPZ/matrix/context/own-altitude checks via unchanged R16 primitives'
        lib.evidence['r17_prior_binding'] = read(Path(work)/'frozen/contract.json')['metadata']['r17_prior_binding']
        return lib
    except BaseException:
        lib.close(); raise


pool_diagnostic = prior_inputs.pool_diagnostic
