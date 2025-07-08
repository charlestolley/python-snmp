__all__ = ["EngineTime", "TimeKeeper", "UsmNotInTimeWindow"]

from snmp.exception import IncomingMessageError

class UsmNotInTimeWindow(IncomingMessageError):
    pass

class EngineTime:
    class NegativeEngineBoots(ValueError):
        pass

    class PriorToReboot(UsmNotInTimeWindow):
        pass

    class ReconfigRequired(UsmNotInTimeWindow):
        pass

    class TooEarly(UsmNotInTimeWindow):
        pass

    class TooOld(UsmNotInTimeWindow):
        pass

    MAX_ENGINE_BOOTS = (1 << 31) - 1
    TIME_WINDOW_SIZE = 150

    def __init__(self, timestamp, snmpEngineBoots = 0, authoritative = False):
        self.authenticated = False
        self.authoritative = authoritative
        self.latestBootTime = timestamp
        self.snmpEngineBoots = snmpEngineBoots

    @property
    def snmpEngineBoots(self):
        return self._snmpEngineBoots

    @snmpEngineBoots.setter
    def snmpEngineBoots(self, engineBoots):
        if engineBoots < 0:
            raise self.NegativeEngineBoots(engineBoots)

        self._snmpEngineBoots = min(engineBoots, self.MAX_ENGINE_BOOTS)

    @property
    def valid(self):
        return self.snmpEngineBoots < self.MAX_ENGINE_BOOTS

    def snmpEngineTime(self, timestamp):
        return int(timestamp - self.latestBootTime)

    def setEngineTime(self, timestamp, engineTime):
        self.latestBootTime = timestamp - engineTime

    def computeAge(self, timestamp, engineTime):
        return self.snmpEngineTime(timestamp) - engineTime

    def hint(self, timestamp, engineBoots, engineTime):
        if not self.authenticated:
            self.snmpEngineBoots = engineBoots
            self.setEngineTime(timestamp, engineTime)

    def update(self, timestamp, engineBoots, engineTime):
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

    def verifyTimeliness(self, timestamp, msgBoots, msgTime):
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
    def __init__(self):
        self.table = {}

    def assertEntry(self, engineID, timestamp):
        try:
            et = self.table[engineID]
        except KeyError as err:
            et = EngineTime(timestamp)
            self.table[engineID] = et

        return et

    def getEngineTime(self, engineID, timestamp):
        et = self.assertEntry(engineID, timestamp)
        return et.snmpEngineBoots, et.snmpEngineTime(timestamp)

    def hint(self, engineID, timestamp, msgBoots, msgTime):
        et = self.assertEntry(engineID, timestamp)
        et.hint(timestamp, msgBoots, msgTime)

    def updateAndVerify(self, engineID, timestamp, msgBoots, msgTime):
        et = self.assertEntry(engineID, timestamp)
        et.update(timestamp, msgBoots, msgTime)
        et.verifyTimeliness(timestamp, msgBoots, msgTime)
