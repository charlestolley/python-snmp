__all__ = [
    "AuthenticationNotEnabled", "InvalidSignature", "PrivacyNotEnabled",
    "Credentials", "AuthCredentials", "AuthPrivCredentials",
    "LocalizedCredentials",
]

from snmp.exception import *
from snmp.security.levels import *
from snmp.security.usm.parameters import UnsignedUsmParameters
from snmp.smi import OctetString
from snmp.utils import *
from snmp.v3.message import *

class AuthenticationNotEnabled(SNMPException):
    pass

class PrivacyNotEnabled(SNMPException):
    pass

class InvalidSignature(IncomingMessageError):
    pass

class WrongSignatureLength(InvalidSignature):
    pass

class LocalizedCredentials:
    def __eq__(self, other):
        if type(self) == type(other):
            return True
        else:
            return NotImplemented

    def __repr__(self):
        return f"{typename(self)}()"

    def withoutPrivacy(self):
        return self

    def sign(self, message):
        raise AuthenticationNotEnabled()

    def signaturePlaceholder(self):
        raise AuthenticationNotEnabled()

    def verifySignature(self, signature):
        raise AuthenticationNotEnabled()

    def decrypt(self, encryptedPDU, msgBoots, msgTime, salt):
        raise PrivacyNotEnabled()

    def encrypt(self, scopedPDU, snmpEngineBoots, snmpEngineTime):
        raise PrivacyNotEnabled()

class LocalizedAuthCredentials(LocalizedCredentials):
    def __init__(self, auth):
        super().__init__()
        self.auth = auth

    def __eq__(self, other):
        result = super().__eq__(other)
        if result is True:
            return self.auth == other.auth
        else:
            return result

    def __repr__(self):
        return f"{typename(self)}({self.auth!r})"

    def sign(self, message):
        wholeMsg = message.encode()
        ptr = message.findSecurityParameters(wholeMsg)
        padding = UnsignedUsmParameters.findPadding(ptr)
        signature = self.auth.sign(wholeMsg)
        return padding.replace(signature)

    def signaturePlaceholder(self):
        return self.auth.msgAuthenticationParameters

    def verifySignature(self, signature):
        padding = self.signaturePlaceholder()

        if len(signature) != len(padding):
            raise WrongSignatureLength(signature)

        wholeMsg = signature.replace(padding)
        computed = self.auth.sign(wholeMsg)

        if computed != signature:
            raise InvalidSignature(signature, computed)

class LocalizedAuthPrivCredentials(LocalizedAuthCredentials):
    def __init__(self, auth, priv):
        super().__init__(auth)
        self.priv = priv

    def __eq__(self, other):
        result = super().__eq__(other)
        if result is True:
            return self.priv == other.priv
        else:
            return result

    def __repr__(self):
        return f"{typename(self)}({self.auth!r}, {self.priv!r})"

    def withoutPrivacy(self):
        return LocalizedAuthCredentials(self.auth)

    def decrypt(self, encryptedPDU, msgBoots, msgTime, salt):
        ciphertext = encryptedPDU.data
        plaintext = self.priv.decrypt(ciphertext, msgBoots, msgTime, salt)
        return SNMPv3WireMessage.decodePlaintext(plaintext)

    def encrypt(self, scopedPDU, snmpEngineBoots, snmpEngineTime):
        ciphertext, salt = self.priv.encrypt(
            scopedPDU.encode(),
            snmpEngineBoots,
            snmpEngineTime,
        )

        return OctetString(ciphertext), salt

class Credentials:
    def __init__(self):
        self.maxSecurityLevel = noAuthNoPriv

    def localize(self, engineID):
        return LocalizedCredentials()

class AuthCredentials(Credentials):
    def __init__(self, authProtocol, authSecret):
        super().__init__()
        self.maxSecurityLevel = authNoPriv
        self.authProtocol = authProtocol
        self.authKey = self.authProtocol.computeKey(authSecret)

    def localizeAuth(self, engineID):
        key = self.authProtocol.localizeKey(self.authKey, engineID)
        return self.authProtocol(key)

    def localize(self, engineID):
        return LocalizedAuthCredentials(self.localizeAuth(engineID))

class AuthPrivCredentials(AuthCredentials):
    def __init__(self,
        authProtocol,
        privProtocol,
        authSecret = None,
        privSecret = None,
        secret = None,
    ):
        if secret is None:
            if authSecret is None:
                raise TypeError("missing required argument: 'authSecret'")
            elif privSecret is None:
                raise TypeError("missing required argument: 'privSecret'")

            super().__init__(authProtocol, authSecret)
            self.privKey = self.authProtocol.computeKey(privSecret)
        else:
            if authSecret is not None:
                errmsg = "'authSecret' and 'secret' are mutually exclusive"
                raise TypeError(errmsg)
            elif privSecret is not None:
                errmsg = "'privSecret' and 'secret' are mutually exclusive"
                raise TypeError(errmsg)

            super().__init__(authProtocol, secret)
            self.privKey = self.authKey

        self.maxSecurityLevel = authPriv
        self.privProtocol = privProtocol

    def localizePriv(self, engineID):
        key = self.authProtocol.localizeKey(self.privKey, engineID)
        return self.privProtocol(key)

    def localize(self, engineID):
        auth = self.localizeAuth(engineID)
        priv = self.localizePriv(engineID)
        return LocalizedAuthPrivCredentials(auth, priv)
