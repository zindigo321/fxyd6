"""Raw-byte evidence and separated subject/validator identities."""
import hashlib
import json
from pathlib import Path

KEYS = ('run_id', 'config_sha256', 'input_sha256', 'code_sha256')
NORMALIZATION = 'strict UTF-8 decode; replace CRLF with LF; UTF-8 encode; preserve BOM, lone CR, whitespace and terminal newline'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode('utf-8')


def read(path):
    return json.loads(Path(path).read_bytes())


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False).encode('utf-8')
    path.write_bytes(blob)
    if path.read_bytes() != blob:
        raise ValueError('OUTPUT_READBACK')


def text(path, value):
    blob = value.encode('utf-8')
    Path(path).write_bytes(blob)
    if Path(path).read_bytes().decode('utf-8') != value:
        raise ValueError('TEXT_READBACK')


def file_record(path):
    path = Path(path)
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            digest.update(chunk)
            size += len(chunk)
    return dict(path=str(path.resolve()), sha256=digest.hexdigest(), bytes=size)


def text_hashes(blob, algorithm=NORMALIZATION):
    if algorithm != NORMALIZATION:
        raise ValueError('HASH_ALGORITHM_LABEL')
    value = blob.decode('utf-8', errors='strict')
    return dict(raw_file_sha256=sha(blob), raw_bytes=len(blob), encoding='UTF-8',
                bom=blob.startswith(b'\xef\xbb\xbf'), crlf=blob.count(b'\r\n'),
                lone_lf=blob.count(b'\n')-blob.count(b'\r\n'),
                lone_cr=blob.count(b'\r')-blob.count(b'\r\n'),
                normalized_text_sha256=sha(value.replace('\r\n', '\n').encode('utf-8')),
                normalization_algorithm=algorithm)


def preserve(expected, actual):
    return expected['sha256'] == actual['sha256'] and expected['bytes'] == actual['bytes']


def identities(subject, validator):
    if any(k not in subject for k in KEYS) or any(k not in validator for k in KEYS):
        raise ValueError('IDENTITY_FIELDS')
    if subject['run_id'] == validator['run_id'] or subject['code_sha256'] == validator['code_sha256']:
        raise ValueError('SUBJECT_VALIDATOR_MIXED')
    return dict(subject={k: subject[k] for k in KEYS}, validator={k: validator[k] for k in KEYS})


def owned(records, subject):
    return all(all(r.get(k) == subject[k] for k in KEYS) for r in records)


def separate_paths(source, historical_validator, output, work):
    inputs = [Path(source).resolve(), Path(historical_validator).resolve()]
    targets = [Path(output).resolve(), Path(work).resolve()]
    if any(a.is_relative_to(b) or b.is_relative_to(a) for a in targets for b in inputs):
        raise ValueError('OUTPUT_SOURCE_OVERLAP')
    if targets[0] == targets[1] or targets[0].is_relative_to(targets[1]) or targets[1].is_relative_to(targets[0]):
        raise ValueError('OUTPUT_WORK_OVERLAP')


def outcome(checks):
    if any(v['status'] == 'FAIL' for v in checks.values()):
        return 'FAIL'
    if any(v['status'] != 'PASS' for v in checks.values()):
        return 'BLOCKED'
    return 'PASS'


def apply_final_checks(summary, checks):
    """Delivery gates participate in the same status and exit decision."""
    summary['checks'].update(checks)
    summary['offline_acceptance'] = outcome(summary['checks'])
    summary['exit_code'] = 0 if summary['offline_acceptance'] == 'PASS' else 1
    return summary


def no_fresh_native(summary):
    return (summary.get('fresh_native_validation_performed') is False
            and summary.get('round8_native_activation_count') == 0
            and summary.get('native_evidence_origin_run_id') == summary.get('subject_run_id')
            and summary.get('validator_run_id') != summary.get('subject_run_id'))
