import json
import tempfile
import unittest
from pathlib import Path
from ip_history import record,removed,entries,events,import_reports

class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.path=self.root/'history.db'
        self.host='dev.example.com'
    def fail(self,ip='1.1.1.1',status='RKN_BLOCK',ext=True,at='2026-11-25T00:00:00Z'):
        return dict(ip=ip,first_ru_data=False,local_data=False,first_api_status=status,recheck=status,api_status=status,remote_data=ext,checked_at=at)
    def test_dedup_and_dates(self):
        row=self.fail()
        for _ in range(2):record(self.path,self.host,443,[row])
        r=entries(self.path)[0]
        self.assertEqual(r['failures'],1)
        self.assertTrue(r['suspected_block'])
        self.assertTrue(r['review_from'].startswith('2027-01-24'))
        self.assertTrue(r['review_to'].startswith('2027-02-23'))
    def test_mt_dead_not_block(self):
        record(self.path,self.host,443,[self.fail(status='MT_DEAD',ext=False)])
        r=entries(self.path)[0]
        self.assertFalse(r['suspected_block'])
        self.assertIsNone(r['review_from'])
    def test_single_failure_or_error_not_archived(self):
        record(self.path,self.host,443,[dict(self.fail(),recheck=''),dict(self.fail(),local_data=None),dict(self.fail(),first_api_status='API_ERROR')])
        self.assertEqual(entries(self.path),[])
    def test_recovery_and_new_failure(self):
        record(self.path,self.host,443,[self.fail()])
        record(self.path,self.host,443,[dict(ip='1.1.1.1',local_data=True,api_status='OK',checked_at='2026-11-26T00:00:00Z')])
        self.assertTrue(entries(self.path)[0]['recovered'])
        record(self.path,self.host,443,[self.fail(at='2026-11-27T00:00:00Z')])
        self.assertFalse(entries(self.path)[0]['recovered'])
        self.assertEqual(len(events(self.path)),3)
    def test_removal_and_cross_host(self):
        record(self.path,self.host,443,[self.fail()])
        removed(self.path,self.host,443,['1.1.1.1'],'2026-11-26T00:00:00Z','sandbox')
        self.assertIsNone(entries(self.path)[0]['removed_at'])
        removed(self.path,self.host,443,['1.1.1.1'],'2026-11-26T00:00:00Z','production')
        record(self.path,'other.example.com',443,[self.fail()])
        self.assertEqual(len(entries(self.path)),2)
        self.assertEqual(sum(bool(r['removed_at']) for r in entries(self.path)),1)
    def test_import_idempotent(self):
        report={'host':self.host,'port':443,'rows':[], 'finished_at':'2026-11-26T00:00:00Z','auto_result':{'status':'removed','removed':['1.1.1.1'],'measurements':[self.fail()]}}
        (self.root/'proxy-check-1.json').write_text(json.dumps(report))
        for _ in range(2):import_reports(self.path,self.root)
        self.assertEqual(len(events(self.path)),2)
        self.assertEqual(entries(self.path)[0]['failures'],1)

if __name__=='__main__':unittest.main()
