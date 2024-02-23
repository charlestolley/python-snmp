__all__ = ["TimeKeeper"]

from threading import Lock
from time import time

from snmp.typing import *

class TimeEntry:
    def __init__(self,
        engineBoots: int,
        latestBootTime: Optional[float] = None,
        authenticated: bool = False,
    ) -> None:
        if latestBootTime is None:
            latestBootTime = time()

        self.authenticated = authenticated
        self.snmpEngineBoots = engineBoots
        self.latestBootTime = latestBootTime
        self.latestReceivedEngineTime = 0

    def snmpEngineTime(self, timestamp: float) -> int:
        return int(timestamp - self.latestBootTime)

class TimeKeeper:
    MAX_ENGINE_BOOTS: ClassVar[int] = (1 << 31) - 1
    TIME_WINDOW_SIZE: ClassVar[int] = 150

    def __init__(self) -> None:
        self.lock = Lock()
        self.table: Dict[bytes, TimeEntry] = {}

    def getEngineTime(self,
        engineID: bytes,
        timestamp: Optional[float] = None,
    ) -> Tuple[int, int]:
        if timestamp is None:
            timestamp = time()

        with self.lock:
            try:
                entry = self.table[engineID]
            except KeyError:
                return 0, 0

            return entry.snmpEngineBoots, entry.snmpEngineTime(timestamp)

    def hint(self,
        engineID: bytes,
        msgBoots: int = 0,
        msgTime: int = 0,
        timestamp: Optional[float] = None,
    ) -> None:
        self.updateAndVerify(engineID, msgBoots, msgTime, False, timestamp)

    def updateAndVerify(self,
        engineID: bytes,
        msgBoots: int,
        msgTime: int,
        auth: bool = True,
        timestamp: Optional[float] = None,
    ) -> bool:
        if timestamp is None:
            timestamp = time()

        with self.lock:
            try:
                entry = self.table[engineID]
            except KeyError as err:
                entry = TimeEntry(msgBoots, timestamp - msgTime, auth)
                self.table[engineID] = entry

            withinTimeWindow = False
            if not entry.authenticated:
                entry.snmpEngineBoots = msgBoots
                entry.latestBootTime = timestamp - msgTime
                entry.latestReceivedEngineTime = msgTime
                withinTimeWindow = True
            elif auth:
                if msgBoots > entry.snmpEngineBoots:
                    entry.snmpEngineBoots = msgBoots
                    entry.latestBootTime = timestamp
                    entry.latestReceivedEngineTime = 0

                if msgBoots == entry.snmpEngineBoots:
                    if msgTime > entry.latestReceivedEngineTime:
                        calculatedBootTime = timestamp - msgTime
                        if calculatedBootTime < entry.latestBootTime:
                            entry.latestBootTime = calculatedBootTime

                        entry.latestReceivedEngineTime = msgTime
                        withinTimeWindow = True
                    else:
                        snmpEngineTime = entry.snmpEngineTime(timestamp)
                        difference = snmpEngineTime - msgTime
                        if difference <= self.TIME_WINDOW_SIZE:
                            withinTimeWindow = True

                if entry.snmpEngineBoots == self.MAX_ENGINE_BOOTS:
                    withinTimeWindow = False

            if auth:
                entry.authenticated = True

            return withinTimeWindow
