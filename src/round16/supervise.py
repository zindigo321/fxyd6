"""Parent-only Windows process-tree supervision with an unrenewed timeout.

The child starts suspended, enters a kill-on-close Job Object, and only then
runs. Every descendant inherits the job; closing it terminates outstanding
descendants on timeout, failure, and successful direct-child exit alike.
This module is used by the coordinator, never by an offline-guarded worker.
"""
import ctypes
from ctypes import wintypes
import os
import subprocess
import time


CREATE_SUSPENDED = 0x00000004
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [('PerProcessUserTimeLimit', ctypes.c_int64),
                ('PerJobUserTimeLimit', ctypes.c_int64),
                ('LimitFlags', wintypes.DWORD),
                ('MinimumWorkingSetSize', ctypes.c_size_t),
                ('MaximumWorkingSetSize', ctypes.c_size_t),
                ('ActiveProcessLimit', wintypes.DWORD),
                ('Affinity', ctypes.c_size_t),
                ('PriorityClass', wintypes.DWORD),
                ('SchedulingClass', wintypes.DWORD)]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ['ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount']]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ('IoInfo', IO_COUNTERS),
                ('ProcessMemoryLimit', ctypes.c_size_t),
                ('JobMemoryLimit', ctypes.c_size_t),
                ('PeakProcessMemoryUsed', ctypes.c_size_t),
                ('PeakJobMemoryUsed', ctypes.c_size_t)]


def run(argv, *, cwd, env, stdout, stderr, timeout):
    """Like subprocess.run for redirected streams, terminating the whole tree.

    Assignment failure never resumes the child. Job, process, and Popen-owned
    primary-thread handles are closed on every path. Supplied stream handles
    belong to the caller and stay open. Setup consumes the same timeout budget.
    """
    if os.name != 'nt':
        raise RuntimeError('ROUND16_TREE_SUPERVISOR_REQUIRES_WINDOWS')
    if timeout <= 0:
        raise subprocess.TimeoutExpired(argv, timeout)
    started = time.monotonic()
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                              ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = ctypes.c_long
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    proc = None
    assigned = False
    job_closed = False

    def close_job():
        nonlocal job_closed
        if not job_closed:
            if not kernel.CloseHandle(job):
                raise ctypes.WinError(ctypes.get_last_error())
            job_closed = True

    try:
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                                              ctypes.byref(limits), ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                creationflags=CREATE_SUSPENDED)
        if not kernel.AssignProcessToJobObject(job, wintypes.HANDLE(int(proc._handle))):
            raise ctypes.WinError(ctypes.get_last_error())
        assigned = True
        remaining = timeout-(time.monotonic()-started)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, timeout)
        status = ntdll.NtResumeProcess(wintypes.HANDLE(int(proc._handle)))
        if status < 0:
            raise OSError('ROUND16_TREE_SUPERVISOR_NT_RESUME_FAILED: '+hex(status & 0xffffffff))
        try:
            code = proc.wait(timeout=max(.001, timeout-(time.monotonic()-started)))
        except subprocess.TimeoutExpired:
            close_job()
            proc.wait(timeout=5)
            raise subprocess.TimeoutExpired(argv, timeout)
        return subprocess.CompletedProcess(argv, code)
    finally:
        try:
            # An unassigned process is still suspended and cannot own children.
            if proc is not None and not assigned and proc.poll() is None:
                proc.kill()
            close_job()
        finally:
            if proc is not None:
                try:
                    if proc.poll() is None:
                        proc.wait(timeout=5)
                finally:
                    proc._handle.Close()
