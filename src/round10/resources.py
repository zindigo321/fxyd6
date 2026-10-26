"""Local process accounting, without application/COM activation."""
import ctypes
from ctypes import wintypes
import os
import time


def usage():
    class Counters(ctypes.Structure):
        _fields_=[('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD)]+[(name,ctypes.c_size_t) for name in
            ['PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage','QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage']]
    current=ctypes.windll.kernel32.GetCurrentProcess;current.restype=wintypes.HANDLE
    info=Counters();info.cb=ctypes.sizeof(info)
    get=ctypes.windll.psapi.GetProcessMemoryInfo;get.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
    ok=get(current(),ctypes.byref(info),info.cb)
    return dict(pid=os.getpid(),cpu_s=time.process_time(),peak_working_set_bytes=info.PeakWorkingSetSize if ok else None,
                working_set_bytes=info.WorkingSetSize if ok else None,memory_scope='This process only; Windows GetProcessMemoryInfo')
