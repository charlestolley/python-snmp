__all__ = ["TimeKeeper"]

from threading import Lock
from time import time

from snmp.typing import *

class EngineTime:
    MAX_ENGINE_BOOTS: ClassVar[int] = (1 << 31) - 1

    def __init__(self,
        engineBoots: int,
        engineTime: int,
        timestamp: float,
        authenticated: bool = False,
    ) -> None:
        self.authenticated = authenticated
        self.snmpEngineBoots = engineBoots
        self.setEngineTime(engineTime, timestamp)

    @property
    def snmpEngineBoots(self) -> int:
        return self._snmpEngineBoots

    @snmpEngineBoots.setter
    def snmpEngineBoots(self, engineBoots: int) -> None:
        self._snmpEngineBoots = min(engineBoots, self.MAX_ENGINE_BOOTS)

    @property
    def valid(self) -> bool:
        return self.snmpEngineBoots < self.MAX_ENGINE_BOOTS

    def snmpEngineTime(self, timestamp: float) -> int:
        return int(timestamp - self.latestBootTime)

    def setEngineTime(self, engineTime: int, timestamp: float) -> None:
        self.latestBootTime = timestamp - engineTime

    def computeAge(self, engineTime: int, timestamp: float) -> int:
        return self.snmpEngineTime(timestamp) - engineTime

    def hint(self,
        engineBoots: int,
        engineTime: int,
        timestamp: float,
    ) -> None:
        if not self.authenticated:
            self.snmpEngineBoots = engineBoots
            self.setEngineTime(engineTime, timestamp)

    def update(self,
        engineBoots: int,
        engineTime: int,
        timestamp: float,
    ) -> None:
        if self.authenticated:
            if engineBoots == self.snmpEngineBoots:
                if engineTime > self.snmpEngineTime(timestamp):
                    self.setEngineTime(engineTime, timestamp)
            elif engineBoots > self.snmpEngineBoots:
                self.snmpEngineBoots = engineBoots
                self.setEngineTime(engineTime, timestamp)
        else:
            self.snmpEngineBoots = engineBoots
            self.setEngineTime(engineTime, timestamp)
            self.authenticated = True

class TimeKeeper:
    TIME_WINDOW_SIZE: ClassVar[int] = 150

    def __init__(self) -> None:
        self.lock = Lock()
        self.table: Dict[bytes, EngineTime] = {}

    def assertEntry(self,
        engineID: bytes,
        msgBoots: int,
        msgTime: int,
        timestamp: float,
        authenticated: bool = False,
    ) -> EngineTime:
        try:
            et = self.table[engineID]
        except KeyError as err:
            et = EngineTime(msgBoots, msgTime, timestamp, authenticated)
            self.table[engineID] = et

        return et

    def getEngineTime(self,
        engineID: bytes,
        timestamp: Optional[float] = None,
    ) -> Tuple[int, int]:
        if timestamp is None:
            timestamp = time()

        with self.lock:
            try:
                et = self.table[engineID]
            except KeyError:
                return 0, 0

            return et.snmpEngineBoots, et.snmpEngineTime(timestamp)

    def hint(self,
        engineID: bytes,
        msgBoots: int,
        msgTime: int,
        timestamp: float,
    ) -> None:
        with self.lock:
            et = self.assertEntry(engineID, msgBoots, msgTime, timestamp)
            et.hint(msgBoots, msgTime, timestamp)

    def updateAndVerify(self,
        engineID: bytes,
        msgBoots: int,
        msgTime: int,
        timestamp: float,
    ) -> bool:
        with self.lock:
            et = self.assertEntry(engineID, msgBoots, msgTime, timestamp, True)
            et.update(msgBoots, msgTime, timestamp)

            return (msgBoots == et.snmpEngineBoots
                and et.computeAge(msgTime, timestamp) <= self.TIME_WINDOW_SIZE
                and et.valid
            )
