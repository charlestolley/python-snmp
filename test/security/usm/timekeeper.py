__all__ = ["EngineTimeTest", "TimeKeeperTest"]

import time
import unittest

from snmp.security.usm.timekeeper import EngineTime, TimeKeeper

class EngineTimeTest(unittest.TestCase):
    def setUp(self):
        self.engineBoots = 4887
        self.engineTime = 1942
        self.timestamp = 8264.0

        self.et = EngineTime(
            self.engineBoots,
            self.engineTime,
            self.timestamp,
            True,
        )

    def test_snmpEngineTime_computes_seconds_since_the_last_boot(self):
        delta = 5
        engineTime = self.et.snmpEngineTime(self.timestamp + delta)
        self.assertEqual(engineTime, self.engineTime + delta)

    def test_snmpEngineTime_rounds_down(self):
        delta = 23.9
        deltaInt = 23
        engineTime = self.et.snmpEngineTime(self.timestamp + delta)
        self.assertEqual(engineTime, self.engineTime + deltaInt)

    def test_update_with_larger_engineTime_updates_local_notion(self):
        delta = 5
        offset = 1.9

        self.et.update(
            self.engineBoots,
            self.engineTime + delta,
            self.timestamp + delta - offset,
        )

        engineTime = self.et.snmpEngineTime(self.timestamp + delta)
        self.assertEqual(engineTime, self.engineTime + delta + int(offset))

    def test_update_local_notion_even_for_fractional_changes(self):
        self.et.update(
            self.engineBoots,
            self.engineTime + 1,
            self.timestamp + 0.6,
        )

        engineTime = self.et.snmpEngineTime(self.timestamp + 1.5)
        self.assertEqual(engineTime, self.engineTime + 1)
        engineTime = self.et.snmpEngineTime(self.timestamp + 1.7)
        self.assertEqual(engineTime, self.engineTime + 2)

    def test_slow_update_does_not_change_the_notion_of_time(self):
        delta = 12
        delay = 3

        self.et.update(
            self.engineBoots,
            self.engineTime - delay,
            self.timestamp,
        )

        engineTime = self.et.snmpEngineTime(self.timestamp + delta)
        self.assertEqual(engineTime, self.engineTime + delta)

    def test_update_has_no_effect_if_engineBoots_is_too_low(self):
        delta = 5
        self.et.update(
            self.engineBoots - 1,
            self.engineTime + 7852,
            self.timestamp + 1,
        )

        engineTime = self.et.snmpEngineTime(self.timestamp + delta)
        self.assertEqual(engineTime, self.engineTime + delta)

    def test_update_resets_engineTime_when_engineBoots_is_incremented(self):
        self.et.update(self.engineBoots + 1, 0, self.timestamp + 1)
        engineTime = self.et.snmpEngineTime(self.timestamp + 5)
        self.assertEqual(self.et.snmpEngineBoots, self.engineBoots + 1)
        self.assertEqual(engineTime, 4)

    def test_update_engineBoots_maxes_out_at_32_bit_signed_max(self):
        self.et.update(1 << 31, 0, self.timestamp + 1)
        self.assertEqual(self.et.snmpEngineBoots, (1 << 31) - 1)
        et = EngineTime(1 << 31, 0, self.timestamp)
        self.assertEqual(et.snmpEngineBoots, (1 << 31) - 1)

    def test_hint_has_no_effect_if_authenticated(self):
        self.et.hint(self.engineBoots + 1, 0, self.timestamp)
        engineTime = self.et.snmpEngineTime(self.timestamp)
        self.assertEqual(engineTime, self.engineTime)

    def test_hint_clobbers_the_previous_notion(self):
        et = EngineTime(self.engineBoots, self.engineTime, self.timestamp)

        et.hint(self.engineBoots + 3, 99, self.timestamp)
        engineTime = et.snmpEngineTime(self.timestamp)
        self.assertEqual(engineTime, 99)

        et.hint(self.engineBoots - 1, self.engineTime * 2, self.timestamp)
        engineTime = et.snmpEngineTime(self.timestamp)
        self.assertEqual(engineTime, self.engineTime * 2)

    def test_update_clobbers_unauthenticated_notion(self):
        et = EngineTime(
            self.engineBoots + 3,
            self.engineTime * 9,
            self.timestamp,
        )

        et.update(self.engineBoots, self.engineTime, self.timestamp)
        self.assertEqual(et.snmpEngineBoots, self.engineBoots)
        self.assertEqual(et.snmpEngineTime(self.timestamp), self.engineTime)

    def test_valid_indicates_that_engineBoots_has_not_maxed_out(self):
        self.assertTrue(self.et.valid)
        self.et.update((1 << 31) - 2, 0, self.timestamp)
        self.assertTrue(self.et.valid)
        self.et.update(1 << 31, 0, self.timestamp)
        self.assertFalse(self.et.valid)

    def test_computeAge_tells_how_long_since_the_message_was_generated(self):
        delay = 123
        age = self.et.computeAge(self.engineTime, self.timestamp + delay)
        self.assertEqual(age, delay)

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
            self.timestamp,
        )

    def test_getEngineTime_returns_zeros_for_unfamiliar_engineID(self):
        eboots, etime = self.timekeeper.getEngineTime(b"unknown", time.time())
        self.assertEqual(eboots, 0)
        self.assertEqual(etime, 0)

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
            self.timestamp,
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
            self.timestamp,
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
            timestamp,
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
            self.timestamp + 1,
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
