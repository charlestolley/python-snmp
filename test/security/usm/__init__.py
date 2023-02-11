__all__ = ["DiscoveredEngineTest", "TimeKeeperTest"]

from snmp.security.usm import DiscoveredEngine, TimeKeeper
import unittest

class DiscoveredEngineTest(unittest.TestCase):
    def setUp(self):
        self.namespace = "namespace"
        self.discoveredEngine = DiscoveredEngine()
        self.discoveredEngine.assign(self.namespace)

    def testUninitialized(self):
        discoveredEngine = DiscoveredEngine()
        assigned, initialized = discoveredEngine.assign(self.namespace)
        self.assertTrue(assigned)
        self.assertFalse(initialized)

    def testMultipleAssignment(self):
        assigned, _ = self.discoveredEngine.assign("other")
        self.assertFalse(assigned)

    def testReentrancy(self):
        assigned, initialized = self.discoveredEngine.assign(self.namespace)
        self.assertTrue(assigned)
        self.assertTrue(initialized)

    def testReassignment(self):
        self.discoveredEngine.release(self.namespace)
        assigned, initialized = self.discoveredEngine.assign(self.namespace)
        self.assertTrue(assigned)
        self.assertTrue(initialized)

    def testRelease(self):
        _, _ = self.discoveredEngine.assign(self.namespace)
        first   = self.discoveredEngine.release(self.namespace)
        second  = self.discoveredEngine.release(self.namespace)

        self.assertFalse(first)
        self.assertTrue(second)

    def testReclaim(self):
        self.discoveredEngine.release(self.namespace)
        assigned, initialized = self.discoveredEngine.assign("other")
        self.assertTrue(assigned)
        self.assertFalse(initialized)

class TimeKeeperTest(unittest.TestCase):
    def setUp(self):
        self.engineID = b"engineID"
        self.engineBoots = 4887
        self.engineTime = 1942
        self.timestamp = 8264.0

        self.timekeeper = TimeKeeper()
        _ = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime,
            timestamp=self.timestamp,
        )

    def testUnknownEngine(self):
        engineBoots, engineTime = self.timekeeper.getEngineTime(b"unknown")
        self.assertEqual(engineBoots, 0)
        self.assertEqual(engineTime, 0)

    def testGetEngineTime(self):
        delta = 23.7
        deltaInt = int(delta)

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta,
        )

        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + deltaInt)

    # When msgEngineTime is less than expected (meaning the message was delayed
    # in transit), it should not affect the local notion of snmpEngineTime
    def testSlowMessage(self):
        delta = 5

        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime + delta,
            timestamp = self.timestamp + delta + 1,
        )

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta + 2
        )

        self.assertTrue(valid)
        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + delta + 2)

    # When msgEngineTime is greater than expected (meaning the message was
    # delivered more quickly than any past message), it should cause the local
    # notion of snmpEngineTime to be updated.
    def testFastMessage(self):
        delta = 5

        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime + delta,
            timestamp = self.timestamp + delta - 1,
        )

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta + 2
        )

        self.assertTrue(valid)
        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + delta + 3)

    def testReboot(self):
        newEngineBoots = self.engineBoots + 1
        newEngineTime = 3
        timestamp = self.timestamp + newEngineTime + 2
        delta = 5

        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            newEngineBoots,
            newEngineTime,
            timestamp=timestamp,
        )

        invalid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime + 1,
            timestamp = self.timestamp + 1,
        )

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = timestamp + delta
        )

        self.assertTrue(valid)
        self.assertFalse(invalid)
        self.assertEqual(engineBoots, newEngineBoots)
        self.assertEqual(engineTime, newEngineTime + delta)

    def testMaxBoots(self):
        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            0x7fffffff,
            0,
            timestamp=self.timestamp + 1,
        )

        self.assertFalse(valid)

    def testExpired(self):
        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime,
            self.timestamp + 151,
        )

        self.assertFalse(valid)

if __name__ == '__main__':
    unittest.main()
