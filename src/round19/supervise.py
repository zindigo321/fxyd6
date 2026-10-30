"""ROUND19 parent process supervision and real Python descendant probes."""
import ctypes
from ctypes import wintypes
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from src.round16.supervise import run
from src.round13.common import require, write, read

PROBE_CHILD_CODE = ("import pathlib,sys,time;from src.round19.guard import install;"
    "root=pathlib.Path(sys.argv[1]);install(root,root/'supervision'/'descendant_guard.jsonl',role='science');time.sleep(60)")
PROBE_CODE = ("import json,pathlib,subprocess,sys,time;"
    "from src.round19.guard import install,register_command;"
    "root=pathlib.Path(sys.argv[1]).parents[2];allowed=[];"
    "argv=[sys.executable,'-B','-c',"+repr(PROBE_CHILD_CODE)+",str(root)];"
    "register_command(allowed,argv,pathlib.Path.cwd(),root);"
    "install(root,pathlib.Path(sys.argv[1]).parent/'parent_guard.jsonl',role='coordinator',commands=allowed);"
    "child=subprocess.Popen(argv,cwd=pathlib.Path.cwd());"
    "pathlib.Path(sys.argv[1]).write_text(json.dumps(dict(parent_pid=__import__('os').getpid(),child_pid=child.pid)),encoding='utf8');"
    "time.sleep(.15 if sys.argv[2]=='normal_parent_return' else 60)")
PROBE_MODES = ('normal_parent_return', 'parent_timeout')


def _own_pid_terminated(pid):
    """Query only a PID emitted by our immediately preceding probe parent."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
    if not handle:
        code = ctypes.get_last_error()
        require(code == 87, 'SUPERVISOR_OWN_PID_QUERY_ERROR:'+str(code))
        return dict(pid=pid, terminated=True, process_no_longer_exists=True,
                    windows_process_exit_code=None)
    try:
        status = wintypes.DWORD()
        require(bool(kernel.GetExitCodeProcess(handle, ctypes.byref(status))),
                'SUPERVISOR_OWN_PID_EXIT_QUERY_FAILED')
        return dict(pid=pid, terminated=status.value != 259,
                    process_no_longer_exists=False, windows_process_exit_code=status.value)
    finally:
        kernel.CloseHandle(handle)


def verify_process_tree(out, life):
    """Exercise both successful-parent and timeout kill-on-close behavior."""
    out = Path(out); out.mkdir(parents=True, exist_ok=False)
    require(os.name == 'nt', 'SUPERVISOR_PROBE_REQUIRES_WINDOWS')
    results = []
    for mode in PROBE_MODES:
        life.check(True)
        folder = out/mode; folder.mkdir()
        pid_file = folder/'created_pid.json'
        argv = [sys.executable, '-X', 'utf8', '-B', '-c', PROBE_CODE, str(pid_file), mode]
        start_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        start = time.perf_counter(); timed_out = False; process_code = None
        timeout = min(life.timeout(), 2.0 if mode == 'parent_timeout' else 10.0)
        with (folder/'stdout.log').open('wb') as stdout, (folder/'stderr.log').open('wb') as stderr:
            try:
                proc = run(argv, cwd=folder, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
                    PYTHONPATH=str(Path(__file__).resolve().parents[2])),
                           stdout=stdout, stderr=stderr, timeout=timeout)
                process_code = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
        require(pid_file.exists(), 'SUPERVISOR_PROBE_NO_CREATED_PID')
        created = read(pid_file)
        # Job closure has already waited for the direct child. Query only our descendants.
        queries = [_own_pid_terminated(created['parent_pid']), _own_pid_terminated(created['child_pid'])]
        require(all(item['terminated'] for item in queries), 'SUPERVISOR_DESCENDANT_SURVIVED')
        require(timed_out == (mode == 'parent_timeout'), 'SUPERVISOR_TIMEOUT_BEHAVIOR')
        require(timed_out or process_code == 0, 'SUPERVISOR_NORMAL_PARENT_EXIT')
        result = dict(status='PASS', mode=mode, argv=argv, cwd=str(folder),
                      start_utc=start_utc, end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      actual_parent_process_exit_code=process_code, timeout=timed_out,
                      timeout_exception=timed_out, enforced_timeout_seconds=timeout,
                      own_created_pid_queries=queries, wall_seconds=time.perf_counter()-start,
                      queried_other_processes=False, native_activation_count=0)
        write(folder/'command_result.json', result); results.append(result)
    result = dict(status='PASS', cases=2, results=results, native_activation_count=0,
                  scope='Only own pure-Python parent and descendant PIDs queried')
    write(out/'process_tree_verification.json', result)
    return result
