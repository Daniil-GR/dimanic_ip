import json
import tempfile
import unittest
from pathlib import Path
from target_store import save_target, restore_target

class TargetStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'last_proxy.json'
        self.report = {'scan_id':'test-1','host':'proxy.example.com','port':443}
        self.target = ('proxy.example.com',443,'example-test-secret')

    def test_restore_after_restart(self):
        save_target(self.path,self.report,self.target)
        self.assertEqual(restore_target(self.path,self.report),self.target)
        self.assertNotIn(self.target[2],json.dumps(self.report))

    def test_same_domain_different_scan_is_rejected(self):
        save_target(self.path,self.report,self.target)
        self.assertIsNone(restore_target(self.path,dict(self.report,scan_id='test-2')))

    def test_mismatched_report_is_rejected(self):
        save_target(self.path,self.report,self.target)
        self.assertIsNone(restore_target(self.path,dict(self.report,host='other.example.com')))
        self.assertIsNone(restore_target(self.path,dict(self.report,port=8443)))

    def test_missing_and_invalid_config(self):
        self.assertIsNone(restore_target(self.path,self.report))
        self.path.write_text('{',encoding='utf-8')
        self.assertIsNone(restore_target(self.path,self.report))

    def test_old_report_without_id(self):
        save_target(self.path,self.report,self.target)
        self.assertIsNone(restore_target(self.path,{'host':self.target[0],'port':443}))

    def test_save_mismatch_does_not_overwrite(self):
        save_target(self.path,self.report,self.target)
        with self.assertRaises(ValueError):
            save_target(self.path,self.report,('other.example.com',443,'different'))
        self.assertEqual(restore_target(self.path,self.report),self.target)

if __name__ == '__main__':
    unittest.main()
