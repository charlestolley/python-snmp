__all__ = ["UserBasedSecurityModule"]

from time import time

from snmp.exception import *
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.models import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *
from snmp.v3.message import *

from . import AuthProtocol, PrivProtocol
from .credentials import LocalizedCredentials
from .parameters import *
from .stats import *
from .timekeeper import *
from .users import *

class UserBasedSecurityModule(SecurityModule):
    MODEL = SecurityModel.USM

    def __init__(self,
        namespace: Optional[str] = None,
        engineID: Optional[bytes] = None,
        engineBoots: int = 0,
    ):
        self.timekeeper = TimeKeeper()
        self.users = UserRegistry()

        if engineID is not None:
            if namespace is None:
                raise TypeError("missing the required 'namespace' argument")

            now = time()
            self.engineTime = EngineTime(now, engineBoots, authoritative=True)
            self.namespace = namespace

        self.engineID = engineID

        self.unsupportedSecLevels   = 0
        self.notInTimeWindows       = 0
        self.unknownUserNames       = 0
        self.unknownEngineIDs       = 0
        self.wrongDigests           = 0
        self.decryptionErrors       = 0

    def addUser(self,
        userName: bytes,
        namespace: str,
        default: Optional[bool] = None,
        authProtocol: Optional[Type[AuthProtocol]] = None,
        privProtocol: Optional[Type[PrivProtocol]] = None,
        authSecret: Optional[bytes] = None,
        privSecret: Optional[bytes] = None,
        secret: Optional[bytes] = None,
        defaultSecurityLevel: Optional[SecurityLevel] = None,
    ) -> None:
        self.users.addUser(
            userName,
            namespace,
            default,
            authProtocol,
            privProtocol,
            authSecret,
            privSecret,
            secret,
            defaultSecurityLevel,
        )

    def defaultSecurityLevel(self,
        userName: bytes,
        namespace: str,
    ) -> SecurityLevel:
        return self.users.defaultSecurityLevel(userName, namespace)

    def defaultUserName(self, namespace: str) -> Optional[bytes]:
        return self.users.defaultUserName(namespace)

    ### Methods for outgoing messages

    def outgoingNamespace(self, message: SNMPv3Message) -> str:
        if message.securityEngineID == self.engineID:
            return self.namespace
        else:
            try:
                return next(iter(message.securityName.namespaces))
            except StopIteration as err:
                userName = message.securityName.userName
                errmsg = f"No namespace given for user {userName}"
                raise TypeError(errmsg) from err

    def outgoingUser(self, message: SNMPv3Message) -> LocalizedCredentials:
        return self.users.credentials(
            message.securityName.userName,
            self.outgoingNamespace(message),
            message.securityEngineID,
        )

    def outgoingTime(self,
        message: SNMPv3Message,
        timestamp: float,
    ) -> Tuple[int, int]:
        engineID = message.securityEngineID
        if engineID == self.engineID:
            snmpEngineBoots = self.engineTime.snmpEngineBoots
            snmpEngineTime = self.engineTime.snmpEngineTime(timestamp)
            return snmpEngineBoots, snmpEngineTime
        elif message.header.flags.authFlag:
            return self.timekeeper.getEngineTime(engineID, timestamp)
        else:
            return 0, 0

    def prepareOutgoing(self,
        message: SNMPv3Message,
        timestamp: Optional[float] = None,
    ) -> bytes:
        if timestamp is None:
            timestamp = time()

        scopedPduData = message.scopedPDU
        placeholder = b""
        salt = b""

        engineBoots, engineTime = self.outgoingTime(message, timestamp)

        if message.header.flags.authFlag:
            user = self.outgoingUser(message)
            placeholder = user.signaturePlaceholder()

            if message.header.flags.privFlag:
                scopedPduData, salt = user.encrypt(
                    message.scopedPDU,
                    engineBoots,
                    engineTime,
                )

        securityParameters = UnsignedUsmParameters(
            message.securityEngineID,
            engineBoots,
            engineTime,
            message.securityName.userName,
            placeholder,
            salt,
        )

        wireMessage = SNMPv3WireMessage(
            message.header,
            scopedPduData,
            OctetString(securityParameters.encode())
        )

        if message.header.flags.authFlag:
            return user.sign(wireMessage)
        else:
            return wireMessage.encode()

    ### Methods for incoming messages

    def candidateNamespaces(self, sp: SignedUsmParameters) -> List[str]:
        if self.engineID is not None and sp.engineID == self.engineID:
            if self.users.exists(sp.userName, self.namespace):
                return [self.namespace]
            else:
                return []
        else:
            return list(self.users.namespaces(sp.userName))

    def authenticate(self,
        securityParameters: SignedUsmParameters,
        namespaces: List[str],
    ) -> List[str]:
        authMatch = None
        authEnabled = False
        authenticated = list()

        if not namespaces:
            raise UsmUnknownUserName(securityParameters.userName)

        for namespace in namespaces:
            user = self.users.credentials(
                securityParameters.userName,
                namespace,
                securityParameters.engineID,
            )

            if authMatch is None:
                try:
                    user.verifySignature(securityParameters.signature)
                except AuthenticationNotEnabled:
                    pass
                except InvalidSignature:
                    authEnabled = True
                else:
                    authMatch = user.withoutPrivacy()
                    authenticated.append(namespace)
            elif user.withoutPrivacy() == authMatch:
                authenticated.append(namespace)

        if authenticated:
            return authenticated
        elif authEnabled:
            raise UsmWrongDigest(securityParameters.signature)
        else:
            raise UsmUnsupportedSecLevel(authNoPriv)

    def decrypt(self,
        encryptedPDU: OctetString,
        securityParameters: SignedUsmParameters,
        namespaces: Iterable[str],
    ) -> Tuple[ScopedPDU, List[str]]:
        privMatch = None
        privEnabled = False
        successful = list()

        for namespace in namespaces:
            user = self.users.credentials(
                securityParameters.userName,
                namespace,
                securityParameters.engineID,
            )

            if privMatch is None:
                try:
                    scopedPDU = user.decrypt(
                        encryptedPDU,
                        securityParameters.engineBoots,
                        securityParameters.engineTime,
                        securityParameters.salt,
                    )
                except PrivacyNotEnabled:
                    pass
                except Exception:
                    privEnabled = True
                else:
                    privMatch = user
                    successful.append(namespace)
            elif user == privMatch:
                successful.append(namespace)

        if successful:
            return scopedPDU, successful
        elif privEnabled:
            raise UsmDecryptionError(encryptedPDU)
        else:
            raise UsmUnsupportedSecLevel(authPriv)

    def verifyIncomingTime(self,
        message: SNMPv3WireMessage,
        sp: SignedUsmParameters,
        timestamp: float,
    ) -> None:
        if sp.engineID == self.engineID:
            if message.header.flags.authFlag:
                self.engineTime.verifyTimeliness(
                    timestamp,
                    sp.engineBoots,
                    sp.engineTime,
                )
            else:
                pass
        else:
            if message.header.flags.authFlag:
                self.timekeeper.updateAndVerify(
                    sp.engineID,
                    timestamp,
                    sp.engineBoots,
                    sp.engineTime,
                )
            else:
                self.timekeeper.hint(
                    sp.engineID,
                    timestamp,
                    sp.engineBoots,
                    sp.engineTime,
                )

    def processIncoming(self,
        message: SNMPv3WireMessage,
        timestamp: Optional[float] = None,
    ) -> SNMPv3Message:
        if timestamp is None:
            timestamp = time()

        sp_original = message.securityParameters.original
        sp = SignedUsmParameters.decodeExact(sp_original)

        try:
            reportSecurityLevel = noAuthNoPriv

            if message.header.flags.privFlag:
                reportable = message.header.flags.reportableFlag
                requestID = 0
                contextName = b""
            else:
                scopedPDU = message.scopedPduData
                reportable = scopedPDU.pdu.CONFIRMED_CLASS
                requestID = scopedPDU.pdu.requestID
                contextName = scopedPDU.contextName

            if reportable and sp.engineID != self.engineID:
                raise UnknownEngineID(sp.engineID)

            namespaces = self.candidateNamespaces(sp)

            if message.header.flags.authFlag:
                namespaces = self.authenticate(sp, namespaces)
                reportSecurityLevel = authNoPriv

                if message.header.flags.privFlag:
                    scopedPDU, namespaces = self.decrypt(
                        message.scopedPduData,
                        sp,
                        namespaces,
                    )

                    reportable = scopedPDU.pdu.CONFIRMED_CLASS
                    requestID = scopedPDU.pdu.requestID
                    contextName = scopedPDU.contextName

                    if reportable and sp.engineID != self.engineID:
                        raise UnknownEngineID(sp.engineID)

            self.verifyIncomingTime(message, sp, timestamp)

        except UsmUnsupportedSecLevel as err:
            self.unsupportedSecLevels += 1
            if reportable:
                oid = usmStatsUnsupportedSecLevelsInstance
                value = Counter32(self.unsupportedSecLevels)
            else:
                raise
        except UsmNotInTimeWindow as err:
            self.notInTimeWindows += 1
            if reportable:
                oid = usmStatsNotInTimeWindowsInstance
                value = Counter32(self.notInTimeWindows)
            else:
                raise
        except UsmUnknownUserName as err:
            self.unknownUserNames += 1
            if reportable:
                oid = usmStatsUnknownUserNamesInstance
                value = Counter32(self.unknownUserNames)
            else:
                raise
        except UnknownEngineID as err:
            self.unknownEngineIDs += 1
            if reportable and self.engineID is not None:
                oid = usmStatsUnknownEngineIDsInstance
                value = Counter32(self.unknownEngineIDs)
            else:
                raise
        except UsmWrongDigest as err:
            self.wrongDigests += 1
            if reportable:
                oid = usmStatsWrongDigestsInstance
                value = Counter32(self.wrongDigests)
            else:
                raise
        except UsmDecryptionError as err:
            self.decryptionErrors += 1
            if reportable:
                oid = usmStatsDecryptionErrorsInstance
                value = Counter32(self.decryptionErrors)
            else:
                raise
        else:
            return SNMPv3Message(
                message.header,
                scopedPDU,
                sp.engineID,
                SecurityName(sp.userName, *namespaces),
            )

        raise ReportMessage(
            SNMPv3Message(
                HeaderData(
                    message.header.msgID,
                    message.header.maxSize,
                    MessageFlags(reportSecurityLevel),
                    self.MODEL,
                ),
                ScopedPDU(
                    ReportPDU(VarBind(oid, value), requestID=requestID),
                    self.engineID,
                    contextName,
                ),
                self.engineID,
                SecurityName(sp.userName, self.namespace),
            )
        )
