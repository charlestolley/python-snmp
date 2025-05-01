__all__ = ["UserBasedSecurityModule"]

from time import time

from snmp.exception import *
from snmp.message.v3 import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.models import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *
from snmp.v3.message import *

from . import AuthProtocol, DecryptionError, PrivProtocol
from .parameters import *
from .timekeeper import *
from .users import *

class UnknownUserName(IncomingMessageError):
    pass

class UnknownEngineID(IncomingMessageError):
    pass

class WrongDigest(IncomingMessageError):
    pass

class UserBasedSecurityModule(SecurityModule[SNMPv3Message]):
    MODEL = SecurityModel.USM

    def __init__(self) -> None:
        self.timekeeper = TimeKeeper()
        self.users = UserRegistry()

    def addUser(self,
        userName: str,
        authProtocol: Optional[Type[AuthProtocol]] = None,
        authSecret: Optional[bytes] = None,
        privProtocol: Optional[Type[PrivProtocol]] = None,
        privSecret: Optional[bytes] = None,
        secret: Optional[bytes] = None,
        default: Optional[bool] = None,
        defaultSecurityLevel: Optional[SecurityLevel] = None,
        namespace: str = "",
    ) -> None:
        self.users.addUser(
            userName.encode(),
            namespace,
            default=default,
            authProtocol=authProtocol,
            privProtocol=privProtocol,
            authSecret=authSecret,
            privSecret=privSecret,
            secret=secret,
            defaultSecurityLevel=defaultSecurityLevel,
        )

    def getDefaultSecurityLevel(self,
        userName: str,
        namespace: str = "",
    ) -> SecurityLevel:
        return self.users.getDefaultSecurityLevel(
            userName.encode(),
            namespace,
        )

    def getDefaultUser(self, namespace: str = "") -> Optional[str]:
        user = self.users.getDefaultUser(namespace)
        return user.decode() if user is not None else None

    def registerRemoteEngine(self,
        engineID: bytes,
        namespace: str = "",
    ) -> bool:
        return self.users.assign(engineID, namespace)

    def unregisterRemoteEngine(self,
        engineID: bytes,
        namespace: str = "",
    ) -> None:
        _ = self.users.release(engineID, namespace)

    def prepareOutgoing(self,
        message: SNMPv3Message,
        engineID: bytes,
        securityName: bytes,
        timestamp: Optional[float] = None,
    ) -> bytes:
        if timestamp is None:
            timestamp = time()

        if message.header.flags.authFlag:
            user = self.users.getCredentials(engineID, securityName)
            msgAuthenticationParameters = user.signaturePlaceholder()
            engineTime = self.timekeeper.getEngineTime(engineID, timestamp)
            snmpEngineBoots, snmpEngineTime = engineTime
            msgPrivacyParameters = b''

            if message.header.flags.privFlag:
                message.encryptedPDU, msgPrivacyParameters = user.encrypt(
                    message.scopedPDU,
                    snmpEngineBoots,
                    snmpEngineTime,
                )

        else:
            snmpEngineBoots = 0
            snmpEngineTime = 0
            msgAuthenticationParameters = b''
            msgPrivacyParameters = b''

        securityParameters = UnsignedUsmParameters(
            engineID,
            snmpEngineBoots,
            snmpEngineTime,
            securityName,
            msgAuthenticationParameters,
            msgPrivacyParameters,
        )

        wireMessage = SNMPv3WireMessage(
            message.header,
            message.encryptedPDU if message.header.flags.privFlag else message.scopedPDU,
            OctetString(securityParameters.encode()),
        )

        if message.header.flags.authFlag:
            wholeMsg = user.sign(wireMessage)
        else:
            wholeMsg = wireMessage.encode()

        return wholeMsg

    def processIncoming(self,
        message: SNMPv3Message,
        timestamp: Optional[float] = None,
    ) -> None:
        if timestamp is None:
            timestamp = time()

        securityParameters = SignedUsmParameters.decodeExact(
            message.securityParameters.original,
        )

        message.securityEngineID = securityParameters.engineID
        message.securityName     = securityParameters.userName
        remoteIsAuthoritative = True

        if not message.header.flags.authFlag:
            if remoteIsAuthoritative:
                self.timekeeper.hint(
                    securityParameters.engineID,
                    timestamp,
                    securityParameters.engineBoots,
                    securityParameters.engineTime,
                )

            return

        try:
            user = self.users.getCredentials(
                securityParameters.engineID,
                securityParameters.userName,
            )
        except InvalidEngineID as err:
            raise UnknownEngineID(securityParameters.engineID) from err
        except InvalidUserName as err:
            raise UnknownUserName(securityParameters.userName) from err

        user.verifySignature(securityParameters.signature)

        try:
            self.timekeeper.updateAndVerify(
                securityParameters.engineID,
                timestamp,
                securityParameters.engineBoots,
                securityParameters.engineTime,
            )
        except InvalidEngineID as err:
            raise UnknownEngineID(securityParameters.engineID) from err

        if message.header.flags.privFlag:
            try:
                message.scopedPDU = user.decrypt(
                    message.encryptedPDU,
                    securityParameters.engineBoots,
                    securityParameters.engineTime,
                    securityParameters.salt,
                )
            except ValueError as err:
                raise DecryptionError(str(err)) from err
