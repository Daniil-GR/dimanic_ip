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

    def test_commit_blocks_restart(self):
        self.m.committing=True
        self.m.stop()
        with self.assertRaises(ValueError): self.m.start(self.target,10,100)

if __name__=='__main__':
    unittest.main()
