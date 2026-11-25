import tempfile
import unittest
from pathlib import Path
from pause_store import paused, update, active_pool
from auto_dns import plan

class PauseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'paused_ipv4.json'
        self.host='dev.example.com'
    def write(self,path,value):
        import json
        path.write_text(json.dumps(value),encoding='utf-8')
    def test_persistence_and_host_isolation(self):
        update(self.path,self.host,'192.0.2.1',True,self.write)
        self.assertEqual(paused(self.path,self.host),{'192.0.2.1'})
        self.assertEqual(paused(self.path,'other.example.com'),set())
        self.assertEqual(paused(self.path.with_name('other.json'),self.host),set())
        update(self.path,self.host,'192.0.2.1',False,self.write)
        self.assertEqual(paused(self.path,self.host),set())
    def test_corrupt_file_fails_closed(self):
        self.path.write_text('bad',encoding='utf-8')
        with self.assertRaises(ValueError):
            paused(self.path,self.host)
    def test_paused_failure_does_not_delete_or_prevent_others(self):
        ips=['192.0.2.1','192.0.2.2','192.0.2.3']
        rows=[dict(ip=ips[0],first_ru_data=None,local_data=None,recheck=''),
              dict(ip=ips[1],first_ru_data=True,local_data=True,recheck=''),
              dict(ip=ips[2],first_ru_data=False,local_data=False,recheck='MT_DEAD')]
        active,measured=active_pool(ips,rows,{ips[0]})
        self.assertEqual(plan(active,measured,set())[0],[ips[2]])
    def test_paused_healthy_does_not_justify_deletion(self):
        ips=['192.0.2.1','192.0.2.2']
        rows=[dict(ip=ips[0],first_ru_data=True,local_data=True,recheck=''),
              dict(ip=ips[1],first_ru_data=False,local_data=False,recheck='MT_DEAD')]
        active,measured=active_pool(ips,rows,{ips[0]})
        self.assertEqual(plan(active,measured,set())[0],[])

if __name__=='__main__':
    unittest.main()
