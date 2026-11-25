import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from workspace_lifecycle import retired, remove_page


class Monitor:
    def __init__(self):
        self.enabled = True
        self.committing = False
    def stop(self, message):
        self.enabled = False


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pages = {}
        self.history = self.root / 'history.sqlite3'
        self.history.write_text('history')
        self.key = self.root / 'api_key'
        self.key.write_text('shared')
    def page(self, key):
        directory = self.root / key
        directory.mkdir(exist_ok=True)
        secret = directory / 'last_proxy.json'
        secret.write_text('secret')
        (directory / 'report.json').write_text('report')
        module = SimpleNamespace(LOCK=threading.Lock(), MONITOR=Monitor(),
            STATE={'phase':'done'}, ACTIVE_PHASES=('checking','saving','key','dns'),
            PAUSE_COMMIT=False, WORKSPACE_CLOSED=threading.Event(), LAST_PROXY=secret, LAST=('host',443,'secret'))
        self.pages[key] = module
        return module
    def write(self, path, data):
        path.write_text(json.dumps(data))
    def remove(self, key):
        return remove_page(self.root,self.pages,key,lambda:self.page('new'),self.write)
    def test_delete_only_selected(self):
        a,b=self.page('main'),self.page('second')
        result=self.remove('main')
        self.assertEqual(result['next'],'second')
        self.assertTrue(retired(self.root,'main'))
        self.assertFalse(a.MONITOR.enabled)
        self.assertTrue(a.WORKSPACE_CLOSED.is_set())
        self.assertFalse(a.LAST_PROXY.exists())
        self.assertTrue((self.root/'main'/'report.json').exists())
        self.assertTrue(b.MONITOR.enabled)
        self.assertEqual(self.history.read_text(),'history')
        self.assertEqual(self.key.read_text(),'shared')
    def test_last_page_replaced(self):
        self.page('main')
        self.assertEqual(self.remove('main')['next'],'new')
        self.assertEqual(list(self.pages),['new'])
    def test_busy_page_stops_monitor_but_is_not_deleted(self):
        a=self.page('main')
        a.STATE['phase']='checking'
        with self.assertRaises(ValueError): self.remove('main')
        self.assertFalse(a.MONITOR.enabled)
        self.assertFalse(retired(self.root,'main'))
        self.assertTrue(a.LAST_PROXY.exists())
        a.STATE['phase']='done'
        self.remove('main')
        self.assertTrue(retired(self.root,'main'))
    def test_commit_in_progress_not_deleted(self):
        a=self.page('main')
        a.MONITOR.committing=True
        with self.assertRaises(ValueError): self.remove('main')
        self.assertIn('main',self.pages)
    def test_missing_page_rejected(self):
        with self.assertRaises(ValueError): self.remove('main')
    def test_failed_persistence_keeps_page(self):
        a=self.page('main');self.page('second')
        def fail(path,data): raise OSError('disk')
        with self.assertRaises(OSError): remove_page(self.root,self.pages,'main',lambda:None,fail)
        self.assertIn('main',self.pages)
        self.assertFalse(a.WORKSPACE_CLOSED.is_set())
        self.assertTrue(a.LAST_PROXY.exists())

if __name__=='__main__': unittest.main()
