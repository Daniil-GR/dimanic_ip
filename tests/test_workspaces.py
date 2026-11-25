import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import workspace_server as w

class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.patch=patch.object(w,'WORKSPACES',self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.pages=patch.object(w,'PAGES',{})
        self.pages.start()
        self.addCleanup(self.pages.stop)

    def page(self, ident):
        (self.root/ident).mkdir()
        return w.load_page(ident)

    def test_independent_state_and_monitor(self):
        a=self.page('aaaaaaaaaaaa')
        b=self.page('bbbbbbbbbbbb')
        a.STATE.update(host='dev.example.com',port=443,rows=[{'ip':'192.0.2.1'}])
        a.LAST=('dev.example.com',443,'dummy-secret')
        a.MONITOR.start(a.LAST,10,0)
        self.assertEqual(b.STATE['rows'],[])
        self.assertIsNone(b.LAST)
        self.assertFalse(b.MONITOR.enabled)
        self.assertNotEqual(a.REPORTS,b.REPORTS)
        self.assertNotEqual(a.LAST_PROXY,b.LAST_PROXY)
        self.assertTrue(w.page_list('bbbbbbbbbbbb')['pages'][0]['monitoring'])
        self.assertNotIn('dummy-secret',str(w.page_list('bbbbbbbbbbbb')))
        self.assertIs(a.API,b.API)
        self.assertEqual(a.PROTECTED,b.PROTECTED)

    def test_duplicate_host_is_rejected(self):
        a=self.page('aaaaaaaaaaaa')
        b=self.page('bbbbbbbbbbbb')
        a.STATE['host']='dev.example.com'
        with self.assertRaises(ValueError):
            w.require_unique('DEV.EXAMPLE.COM.','bbbbbbbbbbbb')
        w.require_unique('other.example.com','bbbbbbbbbbbb')
        self.assertFalse(b.MONITOR.enabled)

    def test_shared_key_guard(self):
        a=self.page('aaaaaaaaaaaa')
        self.page('bbbbbbbbbbbb')
        self.assertFalse(w.shared_settings_busy())
        a.MONITOR.start(('dev.example.com',443,'dummy'),10,0)
        self.assertTrue(w.shared_settings_busy())
        a.MONITOR.stop()
        self.assertFalse(w.shared_settings_busy())
        a.STATE['phase']='checking'
        self.assertTrue(w.shared_settings_busy())

    def test_saved_page_restores_only_its_own_report(self):
        a=self.page('aaaaaaaaaaaa')
        a.STATE.update(host='dev.example.com',port=443,scan_id='scan',phase='done',rows=[{'ip':'192.0.2.1'}])
        a.LAST=('dev.example.com',443,'dummy')
        a.save_report()
        restored=w.load_page('aaaaaaaaaaaa')
        b=self.page('bbbbbbbbbbbb')
        self.assertEqual(restored.LAST,a.LAST)
        self.assertIsNone(b.LAST)
        self.assertFalse(restored.MONITOR.enabled)

if __name__=='__main__':
    unittest.main()
