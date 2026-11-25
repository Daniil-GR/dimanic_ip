import unittest
from auto_dns import plan

class BothUnavailableTests(unittest.TestCase):
    def test_nl_is_not_a_gate(self):
        ips=['1.1.1.1','8.8.8.8','9.9.9.9']
        rows=[dict(ip=ips[0],first_ru_data=True,local_data=True,remote_data=True,recheck=''),
              dict(ip=ips[1],first_ru_data=False,local_data=False,remote_data=False,recheck='MT_DEAD'),
              dict(ip=ips[2],first_ru_data=False,local_data=False,remote_data=True,recheck='RKN_BLOCK')]
        self.assertEqual(plan(ips,rows,set())[0],ips[1:])
        rows[0]['local_data']=False
        self.assertEqual(plan(ips,rows,set())[0],[])
