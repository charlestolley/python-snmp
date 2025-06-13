__all__ = ["LocalEngineTimeTest", "RemoteEngineTimeTest", "TimeKeeperTest"]

import unittest

from snmp.exception import UsmNotInTimeWindow
from snmp.security.usm.timekeeper import EngineTime, TimeKeeper

class LocalEngineTimeTest(unittest.TestCase):
    def setUp(self):
        self.engineBoots = 10
        self.timestamp = 11.0

        self.et = EngineTime(self.timestamp, self.engineBoots, True)

    def test_constructor_constrains_snmpEngineBoots_to_32_bit_signed(self):
        et = EngineTime(self.timestamp, 1<<31, True)
        self.assertEqual(et.snmpEngineBoots, ((1<<31)-1))

    def test_constructor_raises_ValueError_for_negative_snmpEngineBoots(self):
        self.assertRaises(ValueError, EngineTime, self.timestamp, -1, True)

    def test_snmpEngineTime_computes_seconds_since_the_last_boot(self):
        timestamp = self.timestamp + 16.0
        engineTime = self.et.snmpEngineTime(timestamp)
        self.assertEqual(engineTime, 16)

    def test_snmpEngineTime_does_not_round_but_truncates(self):
        timestamp = self.timestamp + 21.99
        engineTime = self.et.snmpEngineTime(timestamp)
        self.assertEqual(engineTime, 21)

    def test_wrong_snmpEngineBoots_is_OutsideTimeWindow(self):
        self.assertRaises(
            UsmNotInTimeWindow,
            self.et.verifyTimeliness,
            self.timestamp,
            self.engineBoots - 1,
            0,
        )

    def test_a_message_is_valid_if_it_is_less_than_151_seconds_old(self):
        timestamp = self.timestamp + 150.9
        self.et.verifyTimeliness(timestamp, self.engineBoots, 0)

    def test_a_message_is_OutsideTimeWindow_after_151_seconds(self):
        timestamp = self.timestamp + 151

        self.assertRaises(
            UsmNotInTimeWindow,
            self.et.verifyTimeliness,
            timestamp,
            self.engineBoots,
            0,
        )

    def test_remote_engine_error_tolerated_under_151_seconds(self):
        self.et.verifyTimeliness(self.timestamp, self.engineBoots, 1)
        self.et.verifyTimeliness(self.timestamp, self.engineBoots, 58)
        self.et.verifyTimeliness(self.timestamp, self.engineBoots, 150)

    def test_remote_engine_error_of_151_seconds_is_OutsideTimeWindow(self):
        self.assertRaises(
            UsmNotInTimeWindow,
            self.et.verifyTimeliness,
            self.timestamp,
            self.engineBoots,
            151,
        )

    def test_snmpEngineBoots_is_valid_under_int32_max(self):
        engineBoots = (1 << 31) - 2
        et = EngineTime(self.timestamp, engineBoots, True)
        et.verifyTimeliness(self.timestamp, engineBoots, 0)

    def test_snmpEngineBoots_of_int32_max_is_OutsideTimeWindow(self):
        engineBoots = (1 << 31) - 1
        et = EngineTime(self.timestamp, engineBoots, True)

        self.assertRaises(
            UsmNotInTimeWindow,
            et.verifyTimeliness,
            self.timestamp,
            engineBoots,
            0,
        )

class RemoteEngineTimeTest(unittest.TestCase):
    def setUp(self):
        self.engineBoots = 48
        self.engineTime = 49
        self.timestamp = 50.0

        self.et = EngineTime(self.timestamp)
        self.et.update(self.timestamp, self.engineBoots, self.engineTime)

    def test_update_with_greater_engineBoots_sets_engineTime(self):
        self.et.update(
            self.timestamp + 3.0,
            self.engineBoots + 1,
            1,
        )

        engineTime = self.et.snmpEngineTime(self.timestamp + 5.0)
        self.assertEqual(self.et.snmpEngineBoots, self.engineBoots + 1)
        self.assertEqual(engineTime, 3)

    def test_update_with_lesser_engineBoots_has_no_effect(self):
        self.et.update(
            self.timestamp + 3.0,
            self.engineBoots - 1,
            59,
        )

        engineTime = self.et.snmpEngineTime(self.timestamp + 5.0)
        self.assertEqual(engineTime, self.engineTime + 5.0)
        self.assertEqual(self.et.snmpEngineBoots, self.engineBoots)

    def test_update_with_greater_engineTime_reflected_in_calculation(self):
        self.et.update(
            self.timestamp + 3.0,
            self.engineBoots,
            self.engineTime + 5,
        )

        engineTime = self.et.snmpEngineTime(self.timestamp + 5.0)
        self.assertEqual(engineTime, self.engineTime + 7)

    def test_update_with_lesser_engineTime_does_not_change_calculation(self):
        self.et.update(
            self.timestamp + 3.0,
            self.engineBoots,
            self.engineTime + 1,
        )

        engineTime = self.et.snmpEngineTime(self.timestamp + 5.0)
        self.assertEqual(engineTime, self.engineTime + 5)

    def test_update_picks_up_fractional_changes(self):
        self.et.update(
            self.timestamp + 0.625,
            self.engineBoots,
            self.engineTime + 1,
        )

        engineTime = self.et.snmpEngineTime(self.timestamp + 1.5)
        self.assertEqual(engineTime, self.engineTime + 1)
        engineTime = self.et.snmpEngineTime(self.timestamp + 1.625)
        self.assertEqual(engineTime, self.engineTime + 2)

    def test_update_engineBoots_maxes_out_at_int32_max(self):
        self.et.update(self.timestamp + 3.0, 1 << 31, 0)
        self.assertEqual(self.et.snmpEngineBoots, (1 << 31) - 1)

    def test_hint_clobbers_the_previous_hint(self):
        et = EngineTime(self.timestamp)
        et.hint(self.timestamp, self.engineBoots + 3, 115)

        engineTime = et.snmpEngineTime(self.timestamp)
        self.assertEqual(engineTime, 115)

        et.hint(self.timestamp, self.engineBoots - 1, self.engineTime * 2)
        engineTime = et.snmpEngineTime(self.timestamp)
        self.assertEqual(engineTime, self.engineTime * 2)

    def test_update_clobbers_hint(self):
        et = EngineTime(self.timestamp)
        et.hint(self.timestamp, self.engineBoots + 3, self.engineTime * 9)

        et.update(self.timestamp, self.engineBoots, self.engineTime)
        self.assertEqual(et.snmpEngineBoots, self.engineBoots)
        self.assertEqual(et.snmpEngineTime(self.timestamp), self.engineTime)

    def test_hint_has_no_effect_after_update(self):
        et = EngineTime(self.timestamp)
        et.update(self.timestamp, self.engineBoots, self.engineTime)

        self.et.hint(self.timestamp + 3.0, self.engineBoots + 1, 0)
        engineTime = self.et.snmpEngineTime(self.timestamp)
        self.assertEqual(engineTime, self.engineTime)

class TimeKeeperTest(unittest.TestCase):
    def setUp(self):
        self.engineID = b"someEngineID"
        self.engineBoots = 4887
        self.engineTime = 1942
        self.timestamp = 8264.0

        self.timekeeper = TimeKeeper()
        _ = self.timekeeper.updateAndVerify(
            self.engineID,
            self.timestamp,
            self.engineBoots,
            self.engineTime,
        )

    def test_getEngineTime_computes_engineTime_from_timestamp(self):
        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            self.timestamp + 15.7,
        )

        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + 15)

    def test_getEngineTime_returns_zeros_for_unfamiliar_engineID(self):
        engineBoots, engineTime = self.timekeeper.getEngineTime(
            b"unknown",
            self.timestamp,
        )

        self.assertEqual(engineBoots, 0)
        self.assertEqual(engineTime, 0)

    def test_each_engine_time_is_tracked_independently(self):
        e1 = b"Engine ID #1"
        e2 = b"Engine ID #2"
        e3 = b"Engine ID #3"

        tk = TimeKeeper()
        _ = tk.updateAndVerify(e1, self.timestamp, 3, 29)
        _ = tk.updateAndVerify(e2, self.timestamp + 0.25, 9, 229)
        _ = tk.updateAndVerify(e3, self.timestamp + 0.5, 543, 12)

        self.assertEqual((3, 100), tk.getEngineTime(e1, self.timestamp + 71.0))
        self.assertEqual((9, 300), tk.getEngineTime(e2, self.timestamp + 72.0))
        self.assertEqual((543, 15), tk.getEngineTime(e3, self.timestamp + 3.5))

    def test_a_message_is_valid_if_it_is_less_than_151_seconds_old(self):
        self.timekeeper.updateAndVerify(
            self.engineID,
            self.timestamp + 150.9,
            self.engineBoots,
            self.engineTime,
        )

    def test_a_message_is_invalid_if_it_is_151_seconds_old(self):
        self.assertRaises(
            UsmNotInTimeWindow,
            self.timekeeper.updateAndVerify,
            self.engineID,
            self.timestamp + 151.0,
            self.engineBoots,
            self.engineTime,
        )

    def test_a_message_is_valid_if_engineBoots_advances(self):
        self.timekeeper.updateAndVerify(
            self.engineID,
            self.timestamp + 3.0,
            self.engineBoots + 1,
            1,
        )

    def test_a_message_is_invalid_if_engineBoots_is_too_low(self):
        self.assertRaises(
            UsmNotInTimeWindow,
            self.timekeeper.updateAndVerify,
            self.engineID,
            self.timestamp + 3.0,
            self.engineBoots - 1,
            self.engineTime,
        )

    def test_a_message_is_invalid_if_engineBoots_has_the_max_value(self):
        self.assertRaises(
            UsmNotInTimeWindow,
            self.timekeeper.updateAndVerify,
            self.engineID,
            self.timestamp + 1.0,
            (1 << 31) - 1,
            0,
        )

if __name__ == '__main__':
    unittest.main()
