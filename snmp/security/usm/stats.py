__all__ = [
    "usmStatsUnsupportedSecLevelsInstance",
    "usmStatsNotInTimeWindowsInstance",
    "usmStatsUnknownUserNamesInstance",
    "usmStatsUnknownEngineIDsInstance",
    "usmStatsWrongDigestsInstance",
    "usmStatsDecryptionErrorsInstance",
]

from snmp.smi import OID

usmStats = OID.parse("1.3.6.1.6.3.15.1.1")
usmStatsUnsupportedSecLevelsInstance= usmStats.extend(1, 0)
usmStatsNotInTimeWindowsInstance    = usmStats.extend(2, 0)
usmStatsUnknownUserNamesInstance    = usmStats.extend(3, 0)
usmStatsUnknownEngineIDsInstance    = usmStats.extend(4, 0)
usmStatsWrongDigestsInstance        = usmStats.extend(5, 0)
usmStatsDecryptionErrorsInstance    = usmStats.extend(6, 0)
