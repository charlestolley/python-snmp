__all__ = ["AuthProtocol", "PrivProtocol", "UserBasedSecurityModule"]

class AuthProtocol:
    def __init__(self, key):
        raise NotImplementedError()

    def __eq__(self, other):
        return NotImplemented

    @classmethod
    def computeKey(cls, secret):
        raise NotImplementedError()

    @classmethod
    def localizeKey(cls, key, engineID):
        raise NotImplementedError()

    @classmethod
    def localize(cls, secret, engineID):
        return cls.localizeKey(cls.computeKey(secret), engineID)

    @property
    def msgAuthenticationParameters(self):
        raise NotImplementedError()

    def sign(self, data):
        raise NotImplementedError()

class PrivProtocol:
    def __init__(self, key):
        raise NotImplementedError()

    def decrypt(self, data, engineBoots, engineTime, salt):
        raise NotImplementedError()

    def encrypt(self, data, engineBoots, engineTime):
        raise NotImplementedError()

from .implementation import *
from .users import *
