import json
import tempfile
import unittest
from pathlib import Path
from auto_dns import plan, protect, release_healthy, read_protected, release_protection


def row(ip, first, last, repeat='MT_DEAD'):
    return dict(ip=ip, first_ru_data=first, local_data=last, recheck=repeat)


class AutoTests(unittest.TestCase):
    def setUp(self):
        self.ips=['1.1.1.1','8.8.8.8','9.9.9.9']
        self.rows=[row(self.ips[0],True,True,''),row(self.ips[1],False,False),row(self.ips[2],False,True,'OK')]

    def test_two_failures_only(self):
        self.assertEqual(plan(self.ips,self.rows,set())[0],[self.ips[1]])

    def test_all_fail(self):
        self.assertEqual(plan(self.ips,[row(ip,False,False) for ip in self.ips],set())[0],[])

    def test_all_down_explicit_permission(self):
        rows=[dict(row(ip,False,False,'DOWN'),first_api_status='DOWN') for ip in self.ips]
        self.assertEqual(plan(self.ips,rows,set())[0],[])
        self.assertEqual(plan(self.ips,rows,set(),True)[0],self.ips)
        self.assertEqual(plan(self.ips,rows,{self.ips[0]},True)[0],self.ips[1:])
        rows[0]['local_data']=None
        self.assertEqual(plan(self.ips,rows,set(),True)[0],[])

    def test_unknown_and_partial(self):
        self.assertEqual(plan(self.ips,self.rows[:2],set())[0],[])
        self.assertEqual(plan(self.ips,self.rows[:2]+[row(self.ips[2],False,None,'API_ERROR')],set())[0],[])

    def test_protected_and_no_repeat(self):
        self.assertEqual(plan(self.ips,self.rows,{self.ips[1]})[0],[])
        self.rows[1]['recheck']=''
        self.assertEqual(plan(self.ips,self.rows,set())[0],[])

    def test_mt_dead_both_nodes_and_manual_release(self):
        self.rows[1]['remote_data']=False
        self.rows[1]['first_ext_data']=False
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'protected.json'
            def write(path,data): path.write_text(json.dumps(data),encoding='utf-8')
            protect(p,'dev.example.com',[self.ips[1]],write)
            protect(p,'other.example.com',[self.ips[1]],write)
            selected,reason=plan(self.ips,self.rows,set(read_protected(p)['dev.example.com']))
            self.assertEqual(selected,[])
            self.assertIn(self.ips[1],reason)
            released=release_protection(p,'dev.example.com',self.ips[1],write)
            self.assertEqual(plan(self.ips,self.rows,released)[0],[self.ips[1]])
            self.assertEqual(read_protected(p)['other.example.com'],[self.ips[1]])

    def test_persistence_and_release(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'protected.json'
            def write(path,data): path.write_text(json.dumps(data),encoding='utf-8')
            protect(p,'dev.example.com',self.ips[1:],write)
            self.assertEqual(read_protected(p)['dev.example.com'],sorted(self.ips[1:]))
            self.assertEqual(release_healthy(p,'dev.example.com',self.rows,write),{self.ips[1]})
            p.write_text('bad',encoding='utf-8')
            with self.assertRaises(ValueError): read_protected(p)

if __name__=='__main__':
    unittest.main()
