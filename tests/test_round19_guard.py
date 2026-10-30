"""ROUND19 per-role network closure and exact process/write boundaries."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.round19 import guard


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('ROUND19_TEST_ROOT'))
        self.work = Path(self.tmp.name).resolve()
        self.destination = self.work/'destination'

    def tearDown(self):
        self.tmp.cleanup()

    def capture(self, role='science', commands=None, destination=None):
        callbacks = []
        with patch.object(sys, 'addaudithook', side_effect=callbacks.append), \
             patch.object(sys, 'meta_path', list(sys.meta_path)):
            lock = guard.install(self.work,self.work/(role+'_guard.jsonl'),controlled=True,
                role=role,commands=commands,destination=destination)
        self.assertEqual(len(callbacks),1)
        return callbacks[0], lock

    def worker(self, job='science'):
        return [sys.executable,'-X','utf8','-B','-m','src.round19.worker',
            '--work',str(self.work),'--out',str(self.work/'attempts/one/output'),'--job',job]

    def test_every_role_rejects_every_socket_audit_event(self):
        events = ['socket.__new__','socket.connect','socket.bind','socket.sendto','socket.getaddrinfo',
                  'socket.gethostname','socket.gethostbyname','socket.gethostbyaddr','socket.getnameinfo','socket.unknown_future_event']
        for role in guard.ROLES:
            audit, _ = self.capture(role)
            for event in events:
                with self.subTest(role=role,event=event), self.assertRaisesRegex(PermissionError,'ROUND19_GUARD_NETWORK'):
                    audit(event,(None,('example.invalid',9)))

    def test_registered_argv_interpreter_cwd_work_and_destination_are_all_exact(self):
        commands = []
        argv = [sys.executable,'-X','utf8','-B','-m','src.round19.export',
            '--work',str(self.work),'--destination',str(self.destination)]
        guard.register_command(commands,argv,guard.ROOT,self.work,self.destination)
        self.assertTrue(guard.command_allowed(argv,guard.ROOT,commands,self.work,self.destination))
        for changed in [argv+['--extra'],['other_python.exe']+argv[1:],argv[:-1]+[str(self.destination/'other')]]:
            self.assertFalse(guard.command_allowed(changed,guard.ROOT,commands,self.work,self.destination))
        self.assertFalse(guard.command_allowed(argv,self.work,commands,self.work,self.destination))
        self.assertFalse(guard.command_allowed(argv,guard.ROOT,commands,self.work/'other',self.destination))
        self.assertFalse(guard.command_allowed(argv,guard.ROOT,commands,self.work,self.destination/'other'))
        audit, _ = self.capture('export_launcher',commands,self.destination)
        audit('subprocess.Popen',(sys.executable,argv,str(guard.ROOT),{}))
        audit('subprocess.Popen',(None,argv,str(guard.ROOT),{}))
        with self.assertRaisesRegex(PermissionError,'ROUND19_GUARD_UNAPPROVED_SUBPROCESS'):
            audit('subprocess.Popen',('other_python.exe',argv,str(guard.ROOT),{}))

    def test_coordinator_workers_and_supervisor_probes_have_exact_scope(self):
        from src.round19.supervise import PROBE_CODE, PROBE_MODES
        for job in guard.COORDINATOR_JOBS:
            self.assertTrue(guard.coordinator_command_allowed(self.worker(job),self.work,guard.ROOT))
        self.assertFalse(guard.coordinator_command_allowed(self.worker()+['extra'],self.work,guard.ROOT))
        self.assertFalse(guard.coordinator_command_allowed(self.worker('other'),self.work,guard.ROOT))
        self.assertFalse(guard.coordinator_command_allowed(self.worker(),self.work,self.work))
        wrong = self.worker(); wrong[9] = str(self.work.parent/'unrelated/attempts/one/output')
        self.assertFalse(guard.coordinator_command_allowed(wrong,self.work,guard.ROOT))
        for mode in PROBE_MODES:
            folder = self.work/'supervision'/mode
            argv = [sys.executable,'-X','utf8','-B','-c',PROBE_CODE,str(folder/'created_pid.json'),mode]
            self.assertTrue(guard.coordinator_command_allowed(argv,self.work,folder))
            argv[5] += ';print(1)'
            self.assertFalse(guard.coordinator_command_allowed(argv,self.work,folder))

    def test_export_child_and_finalizer_cannot_create_any_child(self):
        argv = self.worker('tests')
        commands = []
        guard.register_command(commands,argv,guard.ROOT,self.work)
        for role in ['export_child','finalizer']:
            with self.assertRaisesRegex(ValueError,'ROUND19_TERMINAL_ROLE_HAS_CHILDREN'):
                self.capture(role,commands)
            empty = []
            audit, _ = self.capture(role,empty)
            guard.register_command(empty,argv,guard.ROOT,self.work)
            with self.assertRaisesRegex(PermissionError,'ROUND19_GUARD_UNAPPROVED_SUBPROCESS'):
                audit('subprocess.Popen',(sys.executable,argv,str(guard.ROOT),{}))

    def test_native_vendor_and_outside_mutations_denied_but_export_write_allowed(self):
        audit, lock = self.capture('export_child',destination=self.destination)
        audit('open',(str(self.destination/'legal.json'),'w',os.O_WRONLY|os.O_CREAT))
        audit('open',(str(self.work.parent/'read_evidence'),'r',0))
        for event,args,reason in [
            ('import',('comtypes.client',None,None,None,None),'NATIVE_IMPORT'),
            ('exec',(compile('pass',str(guard.ROOT/'work/round18/old/materialized/vendor.py'),'exec'),),'VENDOR_EXECUTION'),
            ('open',(str(self.work.parent/'forbidden'),'w',os.O_WRONLY|os.O_CREAT),'WRITE_SCOPE'),
            ('os.replace',(str(self.work/'source'),str(self.work.parent/'forbidden')),'MUTATION_SCOPE')]:
            with self.assertRaisesRegex(PermissionError,'ROUND19_GUARD_'+reason):
                audit(event,args)
        lock()
        with self.assertRaisesRegex(PermissionError,'ROUND19_GUARD_WRITE_SCOPE'):
            audit('open',(str(self.work/'materialized/input.json'),'w',os.O_WRONLY|os.O_CREAT))

    def test_command_registration_rejects_foreign_interpreter_or_output(self):
        for argv,cwd,destination in [
            (['foreign.exe','-c','pass'],guard.ROOT,None),
            (self.worker(),self.work.parent,None),
            ([sys.executable,'--out',str(self.work.parent/'outside')],guard.ROOT,None),
            ([sys.executable,'--destination',str(self.destination)],guard.ROOT,None)]:
            with self.assertRaises(ValueError):
                guard.register_command([],argv,cwd,self.work,destination)


class HistoricalChildSchemaTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('ROUND19_TEST_ROOT'))
        self.addCleanup(self.tmp.cleanup)
        self.repo=Path(self.tmp.name).resolve()/'repo'
        self.out=self.repo/'work/fixture'

    def allowed(self,argv,cwd=None,executable=None):
        from src.round19.legacy_guard import command_allowed
        return command_allowed(argv,cwd or self.repo,[self.repo.parent],self.repo,executable)

    def test_known_fixture_schemas_accept_complete_argv(self):
        from src.round19.legacy_guard import READ_UTF8_CODE
        commands=[
            [sys.executable,'-m','src.round2.probe',str(self.out),'pass'],
            [sys.executable,'-m','src.round2.worker','--output',str(self.out),'--stage','data'],
            [sys.executable,'-m','src.round2.worker','--output',str(self.out),'--stage','environment','--skip-stk','--probe-fault','missing'],
            [sys.executable,'tools/run_round2.py','--output',str(self.out),'--mechanism-test','--probe-fault','missing','--skip-stk'],
            [sys.executable,'tools/run_round2.py','--output',str(self.out),'--mechanism-test','--stage-fault','generate:timeout'],
            [sys.executable,'-c','raise SystemExit(7)'],
            [sys.executable,'-c',READ_UTF8_CODE,str(self.out/'unicode.txt')]]
        for argv in commands:
            with self.subTest(argv=argv):
                self.assertTrue(self.allowed(argv))
                self.assertFalse(self.allowed(argv+['unconsumed']))

    def test_foreign_output_cwd_interpreter_stage_and_code_rejected(self):
        probe=[sys.executable,'-m','src.round2.probe',str(self.out),'pass']
        self.assertFalse(self.allowed(probe,cwd=self.repo.parent))
        self.assertFalse(self.allowed(probe,executable='foreign.exe'))
        self.assertFalse(self.allowed(['foreign.exe']+probe[1:]))
        self.assertFalse(self.allowed(probe[:3]+[str(self.repo.parent.parent/'foreign')]+probe[4:]))
        self.assertFalse(self.allowed([sys.executable,'-m','src.round2.worker','--output',str(self.out),'--stage','stk']))
        self.assertFalse(self.allowed([sys.executable,'-c','pass']))
        self.assertFalse(self.allowed([sys.executable,'tools/run_round2.py','--output',str(self.out),'--mechanism-test','--probe-fault','missing','--native']))

    def test_platform_exception_is_exact_system_cmd_ver(self):
        cmd=Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/cmd.exe'
        self.assertTrue(self.allowed([str(cmd),'/c','ver']))
        self.assertFalse(self.allowed([str(cmd),'/c','ver','extra']))
        self.assertFalse(self.allowed([str(self.repo/'cmd.exe'),'/c','ver']))

    def test_local_platform_node_adapter_never_calls_socket_and_network_stays_denied(self):
        import platform
        import socket
        from src.round19 import legacy_guard
        callbacks=[]
        with patch.dict(os.environ,{'ROUND9_WRITE_ROOTS':json.dumps([str(self.repo.parent)]),
            'ROUND19_LEGACY_REPO':str(self.repo),'ROUND9_GUARD_LOG':str(self.repo.parent/'legacy_guard.jsonl'),
            'COMPUTERNAME':'OfflineFixtureNode'}), \
             patch.object(sys,'addaudithook',side_effect=callbacks.append), \
             patch.object(platform,'_node'),patch.object(platform,'_uname_cache',None), \
             patch.object(platform,'_syscmd_ver',return_value=('Windows','11','10.0')), \
             patch.object(socket,'gethostname',side_effect=AssertionError('socket must not be called')) as hostname:
            legacy_guard.install()
            self.assertEqual(platform.uname().node,'OfflineFixtureNode')
            hostname.assert_not_called()
            with self.assertRaisesRegex(PermissionError,'ROUND19_GUARD_NETWORK'):
                callbacks[0]('socket.gethostname',())


if __name__ == '__main__':
    unittest.main()
