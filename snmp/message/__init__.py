__all__ = ["MessageProcessingModel", "RequestHandle"]

from abc import abstractmethod
import enum

class MessageProcessingModel(enum.IntEnum):
    SNMPv1  = 0
    SNMPv2c = 1
    SNMPv3  = 3

class RequestHandle:
    @abstractmethod
    def addCallback(self, func, idNum):
        ...

    @abstractmethod
    def push(self, response):
        ...
