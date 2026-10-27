"""Byte identities and strict JSON; no producer modules are imported."""
import hashlib
import json
from pathlib import Path


class EvidenceError(ValueError):
    pass


class Unavailable(FileNotFoundError):
    pass


def require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf8')


def sha(path, check=lambda: None):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while block := stream.read(1024 * 1024):
            check()
            h.update(block)
    return h.hexdigest()


def record(path, check=lambda: None):
    p = Path(path)
    return dict(path=str(p), bytes=p.stat().st_size, sha256=sha(p, check))


def fingerprint(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
