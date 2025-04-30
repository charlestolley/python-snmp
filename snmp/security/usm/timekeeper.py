__all__ = ["TimeKeeper"]

from snmp.exception import OutsideTimeWindow
from snmp.typing import *

class EngineTime:
    class NegativeEngineBoots(ValueError):
        pass

    class PriorToReboot(OutsideTimeWindow):
        pass

    class ReconfigRequired(OutsideTimeWindow):
        pass

    class TooEarly(OutsideTimeWindow):
        pass

    class TooOld(OutsideTimeWindow):
        pass

    MAX_ENGINE_BOOTS: ClassVar[int] = (1 << 31) - 1
    TIME_WINDOW_SIZE: ClassVar[int] = 150

    def __init__(self,
        timestamp: float,
        snmpEngineBoots: int = 0,
        authoritative: bool = False,
    ):
        self.authenticated = False
        self.authoritative = authoritative
        self.latestBootTime = timestamp
        self.snmpEngineBoots = snmpEngineBoots

    @property
    def snmpEngineBoots(self) -> int:
        return self._snmpEngineBoots

    @snmpEngineBoots.setter
    def snmpEngineBoots(self, engineBoots: int) -> None:
        if engineBoots < 0:
            raise self.NegativeEngineBoots(engineBoots)

        self._snmpEngineBoots = min(engineBoots, self.MAX_ENGINE_BOOTS)

    @property
    def valid(self) -> bool:
        return self.snmpEngineBoots < self.MAX_ENGINE_BOOTS

    def snmpEngineTime(self, timestamp: float) -> int:
        return int(timestamp - self.latestBootTime)

    def setEngineTime(self, timestamp: float, engineTime: int) -> None:
        self.latestBootTime = timestamp - engineTime

    def computeAge(self, timestamp: float, engineTime: int) -> int:
        return self.snmpEngineTime(timestamp) - engineTime

    def hint(self,
        timestamp: float,
        engineBoots: int,
        engineTime: int,
    ) -> None:
        if not self.authenticated:
            self.snmpEngineBoots = engineBoots
            self.setEngineTime(timestamp, engineTime)

    def update(self,
        timestamp: float,
        engineBoots: int,
        engineTime: int,
    ) -> None:
        if self.authenticated:
            if engineBoots == self.snmpEngineBoots:
                if engineTime > self.snmpEngineTime(timestamp):
                    self.setEngineTime(timestamp, engineTime)
            elif engineBoots > self.snmpEngineBoots:
                self.snmpEngineBoots = engineBoots
                self.setEngineTime(timestamp, engineTime)
        else:
            self.snmpEngineBoots = engineBoots
            self.setEngineTime(timestamp, engineTime)
            self.authenticated = True

    def verifyTimeliness(self,
        timestamp: float,
        msgBoots: int,
        msgTime: int,
    ) -> None:
        if msgBoots != self.snmpEngineBoots:
            raise self.PriorToReboot()

        age = self.computeAge(timestamp, msgTime)
        if age > self.TIME_WINDOW_SIZE:
            raise self.TooOld()
        elif self.authoritative and (-1 * age) > self.TIME_WINDOW_SIZE:
            raise self.TooEarly()
        elif not self.valid:
            raise self.ReconfigRequired()

class TimeKeeper:
    def __init__(self) -> None:
        self.table: Dict[bytes, EngineTime] = {}

    def assertEntry(self, engineID: bytes, timestamp: float) -> EngineTime:
        try:
            et = self.table[engineID]
        except KeyError as err:
            et = EngineTime(timestamp)
            self.table[engineID] = et

        return et

    def getEngineTime(self,
        engineID: bytes,
        timestamp: float,
    ) -> Tuple[int, int]:
        et = self.assertEntry(engineID, timestamp)
        return et.snmpEngineBoots, et.snmpEngineTime(timestamp)

    def hint(self,
        engineID: bytes,
        timestamp: float,
        msgBoots: int,
        msgTime: int,
    ) -> None:
        et = self.assertEntry(engineID, timestamp)
        et.hint(timestamp, msgBoots, msgTime)

    def updateAndVerify(self,
        engineID: bytes,
        timestamp: float,
        msgBoots: int,
        msgTime: int,
    ) -> None:
        et = self.assertEntry(engineID, timestamp)
        et.update(timestamp, msgBoots, msgTime)
        et.verifyTimeliness(timestamp, msgBoots, msgTime)
