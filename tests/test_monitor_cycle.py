import unittest
from monitor_cycle import Monitor

class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.m = Monitor()
        self.target = ('dev.example.com',443,'test-secret')
        self.m.start(self.target,10,100)

    def test_immediate_then_two_minutes(self):
        self.assertTrue(self.m.due(100,False))
        self.m.started(100)
        self.assertFalse(self.m.due(219,False))
        self.assertTrue(self.m.due(220,False))

    def test_never_overlap(self):
        self.m.started(100)
        self.assertFalse(self.m.due(300,True))
        self.assertTrue(self.m.due(300,False))
        self.m.started(300)
        self.assertEqual(self.m.public(300)['seconds'],120)

    def test_stop_invalidates_generation(self):
        gen=self.m.generation
        self.m.stop()
        self.assertFalse(self.m.matches(gen,self.target))
        self.assertFalse(self.m.due(999,False))
        self.m.start(self.target,10,1000)
        self.assertFalse(self.m.matches(gen,self.target))

    def test_target_bound_and_no_secret_in_state(self):
        self.assertFalse(self.m.matches(self.m.generation,('dev.example.com',443,'other')))
        self.assertNotIn('test-secret',str(self.m.public(100)))

    def test_ordinary_monitor_is_read_only_by_default(self):
        self.assertFalse(self.m.auto_cleanup)
        self.assertFalse(self.m.public(100)['auto_cleanup'])

    def test_custom_interval_and_auto(self):
        self.m.stop()
        self.m.start(self.target,10,100,300,True)
        self.m.started(100)
        self.assertFalse(self.m.due(399,False))
        self.assertTrue(self.m.due(400,False))
        self.assertTrue(self.m.public(100)['auto_cleanup'])

    def test_live_interval_change(self):
        self.m.started(100)
        self.m.set_interval(600,150)
        self.assertEqual(self.m.public(150)['seconds'],600)
        self.assertFalse(self.m.due(749,False))
        self.assertTrue(self.m.due(750,False))
        self.assertFalse(self.m.due(750,True))
        self.m.stop()
        self.m.start(self.target,10,1000)
        self.assertEqual(self.m.interval,600)

    def test_invalid_interval_and_mode(self):
        for value in (0,59,61,86460,True,'120',120.0):
            with self.assertRaises(ValueError):
                self.m.set_interval(value,100)
        self.m.stop()
        with self.assertRaises(ValueError):
            self.m.start(self.target,10,100,120,'true')
        self.assertFalse(self.m.enabled)

    def test_full_cleanup_explicit_only(self):
        self.m.stop()
        with self.assertRaises(ValueError):
            self.m.start(self.target,10,100,120,False,True)
        self.m.start(self.target,10,100,120,True,True)
        self.assertTrue(self.m.public(100)['allow_empty'])
        self.m.stop()
        self.assertFalse(self.m.public(100)['allow_empty'])

    def test_commit_blocks_restart(self):
        self.m.committing=True
        self.m.stop()
        with self.assertRaises(ValueError): self.m.start(self.target,10,100)

if __name__=='__main__':
    unittest.main()
