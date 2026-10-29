"""One-way transport export with exact byte readback, outside the sealed tree."""
import argparse
import datetime
from pathlib import Path
import shutil
import time

from src.round13.common import read, write, require, sha
from .binding import ROOT, verify_sources
from .control import Lifecycle


def file_set(root):
    return {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}


def export(work, destination=None):
    from .seal import independent_readback
    work = Path(work).resolve()
    require(work.is_relative_to(ROOT/'work/round16'), 'ROUND16_EXPORT_WORK_SCOPE')
    life = Lifecycle(work/'lifecycle.json')
    check = lambda: life.check(False)
    check()
    require((work/'latest_delivery.json').exists(), 'ROUND16_EXPORT_NO_SEAL')
    source = Path(read(work/'latest_delivery.json')['path']).resolve()
    require(source.parent == work and (source.name == 'sealed' or source.name.startswith(('sealed_', 'sealed_prefix_')))
            and not source.is_symlink(), 'ROUND16_EXPORT_SEAL_SCOPE')
    audit = independent_readback(source, check)
    if (source/'frozen/consumer_code.json').exists():
        verify_sources(read(source/'frozen/consumer_code.json'), check)
    else:
        require(audit['status'] != 'PASS', 'ROUND16_EXPORT_PASS_SOURCE_MISSING')
    require((work/'transport/shell_default.json').is_file(), 'ROUND16_EXPORT_SHELL_RECORD_MISSING')
    shell = read(work/'transport/shell_default.json')
    require(shell['python_exit_code'] == shell['shell_exit_code'] == audit['exit_code'], 'ROUND16_EXPORT_SHELL_EXIT')
    destination = Path(destination or read(ROOT/'configs/round16.json')['preferred_output'])/work.name
    destination = destination.resolve()
    require(destination != work and not destination.exists(), 'ROUND16_EXPORT_DESTINATION_EXISTS')
    start = time.perf_counter()
    # Only the immutable sealed tree and finalized transport records form delivery.
    paths = sorted([p for folder in [source, work/'transport'] for p in folder.rglob('*') if p.is_file()])
    rows = []
    for path in paths:
        check()
        require(not path.is_symlink() and path.resolve().is_relative_to(work), 'ROUND16_EXPORT_SOURCE_LINK')
        relative = ('sealed/'+path.relative_to(source).as_posix() if path.is_relative_to(source)
                    else path.relative_to(work).as_posix())
        rows.append(dict(path=relative, source_path=path.relative_to(work).as_posix(),
                         bytes=path.stat().st_size, sha256=sha(path, check)))
    manifest = dict(profile='ROUND16_TRANSPORT_V1', source_work=str(work), files=rows)
    write(work/'transport_manifest.json', manifest)
    destination.mkdir(parents=True)
    for row in rows:
        check()
        target = destination/row['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(work/row['source_path'], target)
    shutil.copyfile(work/'transport_manifest.json', destination/'transport_manifest.json')
    require(file_set(destination) == {r['path'] for r in rows}|{'transport_manifest.json'}, 'ROUND16_EXPORT_EXACT_SET')
    for row in rows:
        check()
        original, copied = work/row['source_path'], destination/row['path']
        require(original.stat().st_size == copied.stat().st_size == row['bytes'] and
                sha(original, check) == sha(copied, check) == row['sha256'], 'ROUND16_EXPORT_BYTE_READBACK')
    require(sha(work/'transport_manifest.json', check) == sha(destination/'transport_manifest.json', check),
            'ROUND16_EXPORT_MANIFEST_READBACK')
    receipt = dict(status='PASS', research_status=audit['status'], research_exit_code=audit['exit_code'],
        profile='ROUND16_TRANSPORT_V1', source_work=str(work),
        destination=str(destination), manifest_sha256=sha(work/'transport_manifest.json', check),
        sealed_manifest_sha256=audit['manifest_sha256'], copied_files=len(rows),
        copied_bytes=sum(r['bytes'] for r in rows), exact_set_and_byte_readback=True,
        sealed_content_modified=False, export_wall_s=time.perf_counter()-start,
        lifecycle_elapsed_upper_bound_s=life.elapsed(),
        completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        native_activation_count=0, git_write_operations=0)
    write(work/'transfer_receipt.json', receipt)
    write(destination/'transfer_receipt.json', receipt)
    require(read(destination/'transfer_receipt.json') == receipt and
            sha(work/'transfer_receipt.json', check) == sha(destination/'transfer_receipt.json', check),
            'ROUND16_EXPORT_RECEIPT_READBACK')
    require(file_set(destination) == {r['path'] for r in rows}|{'transport_manifest.json','transfer_receipt.json'},
            'ROUND16_EXPORT_FINAL_SET')
    check()
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--work', required=True)
    parser.add_argument('--destination')
    args = parser.parse_args()
    print(__import__('json').dumps(export(args.work, args.destination), ensure_ascii=False))
