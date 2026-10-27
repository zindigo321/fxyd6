"""Self-process memory only. Prebind these OS functions before the offline guard."""
import ctypes
from ctypes import wintypes


class SelfMemory:
    class Counters(ctypes.Structure):
        _fields_ = [('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD)] + [(n,ctypes.c_size_t) for n in ['PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage','QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage']]

    def __init__(self):
        current=ctypes.windll.kernel32.GetCurrentProcess;current.restype=wintypes.HANDLE
        self.handle=current()
        self.get=ctypes.windll.psapi.GetProcessMemoryInfo
        self.get.argtypes=[wintypes.HANDLE,ctypes.POINTER(self.Counters),wintypes.DWORD]

    def sample(self):
        counters=self.Counters();counters.cb=ctypes.sizeof(counters)
        ok=self.get(self.handle,ctypes.byref(counters),counters.cb)
        return dict(scope='this Python worker process lifetime; Windows self-process counters only',
                    peak_working_set_bytes=counters.PeakWorkingSetSize if ok else None)
