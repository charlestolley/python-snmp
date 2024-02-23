__all__ = ["TimeKeeperTest"]

import unittest

from snmp.security.usm.timekeeper import *

class TimeKeeperTest(unittest.TestCase):
    def setUp(self):
        self.engineID = b"someEngineID"
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

    def test_getEngineTime_returns_zeros_for_unfamiliar_engineID(self):
        engineBoots, engineTime = self.timekeeper.getEngineTime(b"unknown")
        self.assertEqual(engineBoots, 0)
        self.assertEqual(engineTime, 0)

    def test_getEngineTime_computes_engineTime_from_timestamp(self):
        delta = 23.7
        deltaInt = int(delta)

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta,
        )

        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + deltaInt)

    def test_delayed_message_does_not_affect_the_local_notion_of_time(self):
        delta = 5

        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime + delta,
            timestamp = self.timestamp + delta + 3,
        )

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta + 2
        )

        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + delta + 2)

    def test_messages_that_seem_early_update_the_local_notion_of_time(self):
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

        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + delta + 3)

    def test_hint_affects_notion_of_time_before_the_first_update(self):
        timekeeper = TimeKeeper()
        timekeeper.hint(
            self.engineID,
            self.engineBoots,
            self.engineTime,
            timestamp=self.timestamp,
        )

        newEngineBoots = self.engineBoots + 9
        newEngineTime = 3906
        delta = 5

        timekeeper.hint(
            self.engineID,
            newEngineBoots,
            newEngineTime,
            timestamp = self.timestamp,
        )

        engineBoots, engineTime = timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta,
        )

        self.assertEqual(engineBoots, newEngineBoots)
        self.assertEqual(engineTime, newEngineTime + delta)

    def test_update_overrides_past_hints(self):
        timekeeper = TimeKeeper()
        timekeeper.hint(
            self.engineID,
            self.engineBoots,
            self.engineTime,
            timestamp=self.timestamp,
        )

        delta = 5
        timekeeper.hint(
            self.engineID,
            self.engineBoots + 9,
            3906,
            timestamp = self.timestamp,
        )

        valid = timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime + delta,
            timestamp = self.timestamp + delta,
        )

        engineBoots, engineTime = timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta,
        )

        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + delta)

    def test_hint_does_not_affect_notion_of_time_after_the_first_update(self):
        delta = 5

        self.timekeeper.hint(
            self.engineID,
            self.engineBoots + 9,
            3906,
            timestamp = self.timestamp,
        )

        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime + delta,
            timestamp = self.timestamp + delta,
        )

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta,
        )

        self.assertTrue(valid)
        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + delta)

    def test_update_with_an_old_value_of_engineBoots_is_ignored(self):
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

    def test_all_times_are_invalid_once_the_reboot_counter_maxes_out(self):
        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            0x7fffffff,
            0,
            timestamp=self.timestamp + 1,
        )

        self.assertFalse(valid)

    def test_a_message_is_invalid_after_150_seconds(self):
        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime,
            self.timestamp + 151,
        )

        self.assertFalse(valid)

if __name__ == '__main__':
    unittest.main()
