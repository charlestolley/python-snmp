from snmp.security.usm import AuthProtocol, PrivProtocol
from snmp.utils import typename

class DummyAuthProtocol(AuthProtocol):
    def __init__(self, key):
        self.key = key

    def __eq__(self, other):
        if not isinstance(other, DummyAuthProtocol):
            return NotImplemented

        return self.key == other.key

    def __repr__(self):
        return f"{typename(self)}({self.key!r})"

    @classmethod
    def computeKey(cls, secret):
        return secret

    @classmethod
    def localizeKey(cls, key, engineID):
        return key + engineID

    @property
    def msgAuthenticationParameters(self):
        return bytes(2)

    def sign(self, data):
        return len(data).to_bytes(2, "little", signed=False)

class DummyPrivProtocol(PrivProtocol):
    def __init__(self, key):
        self.key = key

    def __eq__(self, other):
        if type(other) != type(self):
            return NotImplemented

        return self.key == other.key

    def __repr__(self):
        return f"{typename(self)}({self.key!r})"

    def decrypt(self, data, engineBoots, engineTime, salt):
        return data

    def encrypt(self, data, engineBoots, engineTime):
        return data, b"salt"
