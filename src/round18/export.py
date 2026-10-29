"""Supervised export child plus outer completion records without hash cycles."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from src.round13.common import read, write, require, sha
from src.round13.archive import safe_name
from .binding import ROOT, verify_sources
from .control import Lifecycle


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def file_set(folder):
    return {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}


def install_export_guard(work, destination, allow_export_child=False):
    """Restrict each export process to its two authorized output trees."""
    work, destination = Path(work).resolve(), Path(destination).resolve()
    expected = [sys.executable, '-X', 'utf8', '-B', '-m', 'src.round18.export',
        '--work', str(work), '--destination', str(destination)]
    if allow_export_child and os.name == 'nt':
        import ctypes
        split = ctypes.windll.shell32.CommandLineToArgvW
        split.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
        split.restype = ctypes.POINTER(ctypes.c_wchar_p)
        free = ctypes.windll.kernel32.LocalFree
        free.argtypes = [ctypes.c_void_p]

    def command_args(value):
        if isinstance(value, (list, tuple)):
            return list(value)
        if not allow_export_child or os.name != 'nt' or not isinstance(value, str):
            return []
        count = ctypes.c_int()
        pointer = split(value, ctypes.byref(count))
        if not pointer:
            return []
        try:
            return [pointer[i] for i in range(count.value)]
        finally:
            free(pointer)

    def inside(value):
        if isinstance(value, int) or value is None or os.fsdecode(value).lower() == 'nul':
            return True
        path = Path(os.fsdecode(value)).resolve()
        return path.is_relative_to(work) or path.is_relative_to(destination)

    def audit(event, args):
        reason = None
        if event == 'import' and args[0].split('.')[0] in {'pythoncom', 'win32com', 'comtypes', 'win32event', 'winreg'}:
            reason = 'NATIVE_IMPORT'
        elif event == 'subprocess.Popen':
            if not allow_export_child or command_args(args[1]) != expected:
                reason = 'UNAPPROVED_SUBPROCESS'
        elif event in {'os.system', 'os.startfile', 'os.startfile/2', 'os.posix_spawn', 'os.spawn', 'socket.connect', 'socket.bind'}:
            reason = 'EXTERNAL_ACTIVATION'
        elif event == 'exec' and not args[0].co_filename.startswith('<'):
            path = Path(args[0].co_filename).resolve()
            if path.is_relative_to(ROOT/'work') and any(p.lower() in {'vendor', 'materialized'} for p in path.parts):
                reason = 'VENDOR_EXECUTION'
        elif event == 'open':
            path, mode, flags = args
            writing = (isinstance(mode, str) and any(c in mode for c in 'wax+')) or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
            if writing and not inside(path):
                reason = 'WRITE_OUTSIDE_EXPORT'
        elif event == 'os.mkdir':
            path = Path(os.fsdecode(args[0])).resolve()
            if not inside(path) and path not in destination.parents:
                reason = 'MUTATION_OUTSIDE_EXPORT'
        elif event in {'os.remove', 'os.rmdir', 'os.chmod', 'os.utime'}:
            if not inside(args[0]):
                reason = 'MUTATION_OUTSIDE_EXPORT'
        elif event in {'os.rename', 'os.replace', 'os.link', 'os.symlink'}:
            if not all(inside(path) for path in args[:2]):
                reason = 'MUTATION_OUTSIDE_EXPORT'
        if reason:
            raise PermissionError('ROUND18_EXPORT_GUARD_'+reason)

    sys.addaudithook(audit)
    return dict(installed=True, profile='ROUND18_EXPORT_OFFLINE_GUARD_V1',
        write_roots=[str(work), str(destination)], native_activation_budget=0,
        native_imports_denied=True, network_denied=True, vendor_execution_denied=True,
        allowed_child_argv=expected if allow_export_child else None)


def verify_transport(destination, check=lambda: None, completed=False):
    destination = Path(destination).resolve()
    manifest, receipt = read(destination/'transport_manifest.json'), read(destination/'transfer_receipt.json')
    require(receipt['manifest_sha256'] == sha(destination/'transport_manifest.json', check), 'TRANSPORT_RECEIPT_BINDING')
    names = set()
    for row in manifest['files']:
        check()
        name = safe_name(row['path'])
        path = destination/name
        require(name.casefold() not in names and path.resolve().is_relative_to(destination) and not path.is_symlink(), 'TRANSPORT_MEMBER_SCOPE')
        require(all(not p.is_symlink() for p in path.parents if p.is_relative_to(destination)), 'TRANSPORT_PARENT_LINK')
        names.add(name.casefold())
        require(path.stat().st_size == row['bytes'] and sha(path, check) == row['sha256'], 'TRANSPORT_ORIGINAL_MEMBER_BYTES')
    expected = {r['path'] for r in manifest['files']} | {'transport_manifest.json', 'transfer_receipt.json'}
    if completed:
        expected |= {'completion/export_command_result.json', 'completion/stdout.log', 'completion/stderr.log',
            'completion/export_shell_result.json', 'completion/cumulative_timing.json',
            'delivery_manifest.json', 'delivery_receipt.json'}
    require(file_set(destination) == expected, 'TRANSPORT_ORIGINAL_EXACT_SET')
    if 'source_work' in manifest:
        verify_work_mapping(destination, manifest, receipt, check)
    return dict(status='PASS', files=len(manifest['files']))


def verify_work_mapping(destination, manifest, receipt, check=lambda: None):
    """Read original work bytes independently of the exported copy's hashes."""
    work = Path(manifest['source_work']).resolve()
    require(work.is_relative_to(ROOT/'work/round18') and not work.is_symlink(), 'TRANSPORT_WORK_SCOPE')
    require(receipt.get('source_work') == str(work), 'TRANSPORT_RECEIPT_WORK_BINDING')
    require(receipt.get('destination') == str(destination), 'TRANSPORT_RECEIPT_DESTINATION_BINDING')
    source_names = set()
    for row in manifest['files']:
        check()
        name = safe_name(row['source_path'])
        source = work/name
        require(name.casefold() not in source_names and source.resolve().is_relative_to(work)
            and not source.is_symlink(), 'TRANSPORT_SOURCE_SCOPE')
        require(all(not p.is_symlink() for p in source.parents if p.is_relative_to(work)),
            'TRANSPORT_SOURCE_PARENT_LINK')
        source_names.add(name.casefold())
        require(source.stat().st_size == row['bytes'] and sha(source, check) == row['sha256'],
            'TRANSPORT_SOURCE_WORK_BYTES')


def export(work, destination):
    from .seal import independent_readback
    work, destination = Path(work).resolve(), Path(destination).resolve()
    require(work.is_relative_to(ROOT/'work/round18'), 'EXPORT_WORK_SCOPE')
    guard = install_export_guard(work, destination)
    life = Lifecycle(work/'lifecycle.json')
    check = lambda: life.check(False)
    check()
    source = Path(read(work/'latest_delivery.json')['path']).resolve()
    require(source.parent == work and not source.is_symlink(), 'EXPORT_SEAL_SCOPE')
    audit = independent_readback(source, check)
    if (source/'frozen/consumer_code.json').exists():
        verify_sources(read(source/'frozen/consumer_code.json'), check)
    shell = read(work/'transport/shell_default.json')
    require(shell['python_exit_code'] == shell['shell_exit_code'] == audit['exit_code'], 'EXPORT_RESEARCH_SHELL_EXIT')
    require(destination.name == work.name and not destination.exists() and destination != work, 'EXPORT_DESTINATION_SCOPE')
    start = time.perf_counter()
    rows = []
    for folder in [source, work/'transport']:
        for path in sorted(folder.rglob('*')):
            if not path.is_file():
                continue
            check()
            require(not path.is_symlink() and path.resolve().is_relative_to(work), 'EXPORT_SOURCE_LINK')
            relative = 'sealed/'+path.relative_to(source).as_posix() if folder == source else path.relative_to(work).as_posix()
            rows.append(dict(path=relative, source_path=path.relative_to(work).as_posix(),
                bytes=path.stat().st_size, sha256=sha(path, check)))
    require(len({r['path'].casefold() for r in rows}) == len(rows), 'EXPORT_CASE_COLLISION')
    manifest = dict(profile='ROUND18_TRANSPORT_V1', source_work=str(work), files=rows)
    write(work/'transport_manifest.json', manifest)
    destination.mkdir(parents=True)
    for row in rows:
        check()
        target = destination/row['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(work/row['source_path'], target)
    shutil.copyfile(work/'transport_manifest.json', destination/'transport_manifest.json')
    require(file_set(destination) == {r['path'] for r in rows}|{'transport_manifest.json'}, 'EXPORT_EXACT_SET')
    for row in rows:
        copied = destination/row['path']
        require(copied.stat().st_size == row['bytes'] and sha(copied, check) == row['sha256'], 'EXPORT_BYTE_READBACK')
    require(sha(destination/'transport_manifest.json', check) == sha(work/'transport_manifest.json', check), 'EXPORT_MANIFEST_READBACK')
    receipt = dict(status='PASS', profile='ROUND18_TRANSPORT_V1', research_status=audit['status'],
        research_exit_code=audit['exit_code'], destination=str(destination), source_work=str(work),
        manifest_sha256=sha(destination/'transport_manifest.json', check), sealed_manifest_sha256=audit['manifest_sha256'],
        copied_files=len(rows), copied_bytes=sum(r['bytes'] for r in rows), exact_set_and_byte_readback=True,
        receipt_self_hashed=False, sealed_content_modified=False, export_wall_s=time.perf_counter()-start,
        lifecycle_elapsed_upper_bound_s=life.elapsed(), completed_utc=utc_now(), native_activation_count=0, git_write_operations=0,
        offline_guard=guard)
    write(work/'transfer_receipt.json', receipt)
    write(destination/'transfer_receipt.json', receipt)
    require(read(destination/'transfer_receipt.json') == receipt, 'EXPORT_RECEIPT_READBACK')
    verify_transport(destination, check)
    check()
    return receipt


def verify_delivery(destination, check=lambda: None):
    from .seal import independent_readback
    destination = Path(destination).resolve()
    verify_transport(destination, check, completed=True)
    manifest, receipt = read(destination/'delivery_manifest.json'), read(destination/'delivery_receipt.json')
    require(receipt['manifest_sha256'] == sha(destination/'delivery_manifest.json', check), 'DELIVERY_RECEIPT_BINDING')
    expected = {r['path'] for r in manifest['files']} | {'delivery_manifest.json', 'delivery_receipt.json'}
    require(file_set(destination) == expected, 'DELIVERY_EXACT_SET')
    for row in manifest['files']:
        check()
        name = safe_name(row['path'])
        path = destination/name
        require(path.resolve().is_relative_to(destination) and not path.is_symlink() and
            path.stat().st_size == row['bytes'] and sha(path, check) == row['sha256'], 'DELIVERY_BYTES')
    names = [safe_name(row['path']).casefold() for row in manifest['files']]
    require(len(names) == len(set(names)), 'DELIVERY_DUPLICATE_PATH')
    command = read(destination/'completion/export_command_result.json')
    transport = read(destination/'transfer_receipt.json')
    require(command['export_process_exit_code'] == 0 and not command['timeout'] and
        command['receipt_sha256'] == sha(destination/'transfer_receipt.json', check) and
        command['transport_manifest_sha256'] == sha(destination/'transport_manifest.json', check) == transport['manifest_sha256'],
        'DELIVERY_EXPORT_COMMAND_BINDING')
    shell = read(destination/'completion/export_shell_result.json')
    require(shell['export_launcher_python_exit_code'] == shell['export_shell_exit_code'] == 0, 'DELIVERY_EXPORT_SHELL_EXIT')
    require(command['export_shell_exit_code'] is None and command['shell_used'] is False,
        'DELIVERY_DIRECT_CHILD_SHELL_SEMANTICS')
    verify_exit_records(destination, command, shell, check)
    audit = independent_readback(destination/'sealed', check)
    require(audit['manifest_sha256'] == transport['sealed_manifest_sha256'], 'DELIVERY_SEAL_BINDING')
    return dict(status='PASS', files=len(manifest['files']), destination=str(destination),
        delivery_manifest_sha256=receipt['manifest_sha256'], research_status=audit['status'], research_exit_code=audit['exit_code'],
        export_process_exit_code=0, export_launcher_python_exit_code=0, export_shell_exit_code=0)


def verify_exit_records(destination, command, shell, check=lambda: None):
    destination = Path(destination).resolve()
    work = Path(read(destination/'transport_manifest.json')['source_work']).resolve()
    expected = [sys.executable, '-X', 'utf8', '-B', '-m', 'src.round18.export',
        '--work', str(work), '--destination', str(destination)]
    require(command['argv'] == expected and Path(command['cwd']).resolve() == ROOT,
        'DELIVERY_EXPORT_ARGV_BINDING')
    require(command['destination'] == str(destination), 'DELIVERY_EXPORT_DESTINATION_BINDING')
    for stream in ['stdout', 'stderr']:
        path = destination/'completion'/(stream+'.log')
        require(path.stat().st_size == command[stream]['bytes'] and
            sha(path, check) == command[stream]['sha256'], 'DELIVERY_EXPORT_LOG_BINDING')
    require(shell.get('observed_after_process_exit') is True and
        shell.get('export_process_exit_code') == command['export_process_exit_code'],
        'DELIVERY_LAUNCHER_OBSERVATION_BINDING')
    actual = shell.get('actual_argv', [])
    require(len(actual) >= 8 and Path(actual[0]).resolve() == Path(sys.executable).resolve() and
        actual[1:4] == ['-X', 'utf8', '-B'] and
        actual[4].replace('\\', '/') == 'tools/export_round18.py' and
        actual[5:] == ['--work', str(work), '--destination', str(destination)] and
        Path(shell['cwd']).resolve() == ROOT, 'DELIVERY_LAUNCHER_ARGV_BINDING')


def finalize(work, destination, shell_record):
    work, destination = Path(work).resolve(), Path(destination).resolve()
    guard = install_export_guard(work, destination)
    life = Lifecycle(work/'lifecycle.json')
    check = lambda: life.check(False)
    check()
    command = read(work/'export_process/export_command_result.json')
    require(command['export_process_exit_code'] == 0 and command['destination'] == str(destination), 'FINALIZE_EXPORT_NOT_PASS')
    shell = read(shell_record)
    require(shell['export_launcher_python_exit_code'] == shell['export_shell_exit_code'] == 0, 'FINALIZE_SHELL_NOT_PASS')
    verify_transport(destination, check)
    completion = destination/'completion'
    completion.mkdir(exist_ok=False)
    for name in ['export_command_result.json', 'stdout.log', 'stderr.log']:
        shutil.copyfile(work/'export_process'/name, completion/name)
    shutil.copyfile(shell_record, completion/'export_shell_result.json')
    # Every preceding object is complete before this final outer manifest is made.
    clock = read(work/'lifecycle.json')
    write(completion/'cumulative_timing.json', dict(lifecycle_elapsed_s=life.elapsed(),
        first_preparation_utc=datetime.datetime.fromtimestamp(life.effective_start_epoch, datetime.timezone.utc).isoformat(),
        effective_start_epoch=life.effective_start_epoch if hasattr(life, 'effective_start_epoch') else clock.get('effective_start_epoch'),
        record_epoch=clock.get('record_epoch'), record_utc=clock.get('record_utc'),
        preparation_offset_seconds=clock.get('preparation_offset_seconds', 0),
        completed_utc=utc_now(),
        overlapping_worker_walls_added=False, export_process_exit_code=command['export_process_exit_code']))
    rows = [dict(path=p.relative_to(destination).as_posix(), bytes=p.stat().st_size, sha256=sha(p, check))
            for p in sorted(destination.rglob('*')) if p.is_file()]
    write(destination/'delivery_manifest.json', dict(profile='ROUND18_DELIVERY_COMPLETION_V1', files=rows))
    write(destination/'delivery_receipt.json', dict(status='PASS', profile='ROUND18_DELIVERY_COMPLETION_V1',
        manifest_sha256=sha(destination/'delivery_manifest.json', check), receipt_self_hashed=False,
        completed_utc=utc_now(), lifecycle_elapsed_s=life.elapsed(), offline_guard=guard))
    result = verify_delivery(destination, check)
    write(work/'export_process/final_delivery_readback.json', result)
    return result


def launch(work, destination):
    work, destination = Path(work).resolve(), Path(destination).resolve()
    guard = install_export_guard(work, destination, allow_export_child=True)
    life = Lifecycle(work/'lifecycle.json')
    life.check(False)
    folder = work/'export_process'
    folder.mkdir(exist_ok=False)
    argv = [sys.executable, '-X', 'utf8', '-B', '-m', 'src.round18.export', '--work', str(work), '--destination', str(destination)]
    started, start = utc_now(), time.perf_counter()
    timedout, code = False, None
    from .supervise import run
    with (folder/'stdout.log').open('wb') as stdout, (folder/'stderr.log').open('wb') as stderr:
        try:
            result = run(argv, cwd=ROOT, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
                stdout=stdout, stderr=stderr, timeout=max(.001, life.remaining()))
            code = result.returncode
        except subprocess.TimeoutExpired:
            timedout = True
    data = dict(argv=argv, cwd=str(ROOT), start_utc=started, end_utc=utc_now(),
        export_process_exit_code=code, export_shell_exit_code=None, shell_used=False,
        timeout=timedout, wall_s=time.perf_counter()-start, destination=str(destination),
        process_tree_supervision='Windows Job Object; direct Python child; no export-child Shell',
        stdout=dict(bytes=(folder/'stdout.log').stat().st_size, sha256=sha(folder/'stdout.log')),
        stderr=dict(bytes=(folder/'stderr.log').stat().st_size, sha256=sha(folder/'stderr.log')),
        transport_manifest_sha256=sha(destination/'transport_manifest.json') if (destination/'transport_manifest.json').exists() else None,
        receipt_sha256=sha(destination/'transfer_receipt.json') if (destination/'transfer_receipt.json').exists() else None)
    data['offline_guard'] = guard
    write(folder/'export_command_result.json', data)
    return data, 2 if timedout else code if code is not None else 1


def outer_cli():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--work', required=True)
    parser.add_argument('--destination')
    parser.add_argument('--finalize-shell-record')
    args = parser.parse_args()
    work = Path(args.work).resolve()
    destination = Path(args.destination or Path(read(ROOT/'configs/round18.json')['preferred_output'])/work.name).resolve()
    if args.finalize_shell_record:
        print(json.dumps(finalize(work, destination, args.finalize_shell_record), ensure_ascii=False), flush=True)
        return 0
    data, code = launch(work, destination)
    print(json.dumps(data, ensure_ascii=False), flush=True)
    return code


if __name__ == '__main__':
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--work', required=True)
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    print(json.dumps(export(args.work, args.destination), ensure_ascii=False), flush=True)
