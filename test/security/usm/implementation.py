__all__ = [
    "UsmOutgoingTest",
    "UsmOutgoingNoAuthTest",
    "UsmOutgoingNoAuthNonAuthoritativeTest",
    "UsmOutgoingNoAuthAuthoritativeTest",
    "UsmOutgoingAuthTest",
    "UsmOutgoingAuthNonAuthoritativeTest",
    "UsmOutgoingAuthAuthoritativeTest",
    "UsmOutgoingAuthPrivTest",
    "IncomingMessageTest",
    "UnknownEngineIDTest",
    "UnknownUserNameTest",
    "UnsupportedSecLevelTest",
    "UnsupportedPrivacyTest",
    "WrongDigestsTest",
    "DecryptionErrors",
    "SuccessfulIncomingMessageTest",
    "SuccessfulIncomingPrivateMessageTest",
    "ScopedPduPaddingTest",
]

import time
import unittest

from snmp.exception import *
from snmp.ber import *
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.usm.auth import *
from snmp.security.usm.credentials import *
from snmp.security.usm.implementation import *
from snmp.security.usm.parameters import *
from snmp.security.usm.timekeeper import *
from snmp.smi import *
from snmp.v3.message import *

try:
    from snmp.security.usm.priv import *
except ImportError:
    privacySupported = False
else:
    privacySupported = True

from . import DummyAuthProtocol, DummyPrivProtocol

class UsmOutgoingTest(unittest.TestCase):
    def setUp(self):
        self.msgID = 0x12345678
        self.msgMaxSize = 1472
        self.msgFlags = MessageFlags(authNoPriv, reportable=True)
        self.msgSecurityModel = SecurityModel.USM

        self.userName = b"userName"
        self.namespace = "namespace"
        self.engineID = b"engineID"

        self.usm = UserBasedSecurityModule()
        self.usm.addUser(
            self.userName.decode(),
            namespace=self.namespace,
            authProtocol=DummyAuthProtocol,
            authSecret=b"authSecret",
        )

        self.message = SNMPv3Message(
            HeaderData(
                self.msgID,
                self.msgMaxSize,
                self.msgFlags,
                self.msgSecurityModel,
            ),
            ScopedPDU(GetRequestPDU(requestID=-0x789abcdf), self.engineID),
            self.engineID,
            SecurityName(self.userName, self.namespace),
        )

    def test_header_fields_properly_encoded(self):
        wholeMsg = self.usm.prepareOutgoing(self.message)

        tag, ptr = decodeExact(wholeMsg)
        self.assertEqual(tag, Sequence.TAG)

        tag, version, ptr = decode(ptr)

        header, ptr = HeaderData.decode(ptr)
        self.assertEqual(header.msgID, self.msgID)
        self.assertEqual(header.maxSize, self.msgMaxSize)
        self.assertEqual(header.flags, self.msgFlags)
        self.assertEqual(header.securityModel, self.msgSecurityModel)

    def test_securityEngineID_and_securityName_properly_encoded(self):
        wholeMsg = self.usm.prepareOutgoing(self.message)
        tag, ptr = decodeExact(wholeMsg)
        self.assertEqual(tag, Sequence.TAG)

        tag, version, ptr = decode(ptr)
        tag, header, ptr = decode(ptr)

        spString, ptr = OctetString.decode(ptr)
        securityParameters = SignedUsmParameters.decodeExact(spString.original)
        self.assertEqual(securityParameters.engineID, self.engineID)
        self.assertEqual(securityParameters.userName, self.userName)

class UsmOutgoingNoAuthTest(unittest.TestCase):
    def setUp(self):
        self.userName = b"userName"
        self.namespace = "namespace"
        self.engineID = b"engineID"

        self.usm = UserBasedSecurityModule()
        self.usm.addUser(self.userName.decode(), namespace=self.namespace)

        self.message = SNMPv3Message(
            HeaderData(
                1234,
                1234,
                MessageFlags(reportable=True),
                SecurityModel.USM,
            ),
            ScopedPDU(GetRequestPDU(requestID=1234), self.engineID),
            self.engineID,
            SecurityName(self.userName, self.namespace),
        )

    def test_userName_does_not_have_to_be_defined(self):
        usm = UserBasedSecurityModule()
        wholeMsg = usm.prepareOutgoing(self.message)

    def test_namespace_is_not_required(self):
        message = SNMPv3Message(
            self.message.header,
            self.message.scopedPDU,
            self.message.securityEngineID,
            SecurityName(self.userName),
        )

        wholeMsg = self.usm.prepareOutgoing(message)

    def test_msgAuthenticationParameters_contains_empty_string(self):
        wholeMsg = self.usm.prepareOutgoing(self.message)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        self.assertEqual(securityParameters.signature, b"")

    def test_msgPrivacyParameters_contains_empty_string(self):
        wholeMsg = self.usm.prepareOutgoing(self.message)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        self.assertEqual(securityParameters.salt, b"")

class UsmOutgoingNoAuthNonAuthoritativeTest(unittest.TestCase):
    def setUp(self):
        self.userName = b"userName"
        self.namespace = "namespace"
        self.engineID = b"engineID"

        self.usm = UserBasedSecurityModule()
        self.usm.addUser(self.userName.decode(), namespace=self.namespace)

        self.message = SNMPv3Message(
            HeaderData(
                1234,
                1234,
                MessageFlags(reportable=True),
                SecurityModel.USM,
            ),
            ScopedPDU(GetRequestPDU(requestID=1234), self.engineID),
            self.engineID,
            SecurityName(self.userName, self.namespace),
        )

        responseMsg = SNMPv3WireMessage(
            HeaderData(
                1234,
                1234,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(ResponsePDU(requestID=1234), self.engineID),
            OctetString(
                UnsignedUsmParameters(
                    self.engineID,
                    9,
                    4321,
                    self.userName,
                    b"",
                    b"",
                ).encode(),
            ),
        ).encode()

        self.response = SNMPv3WireMessage.decodeExact(responseMsg)

    def test_time_parameters_are_zero_for_the_initial_request(self):
        wholeMsg = self.usm.prepareOutgoing(self.message)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        self.assertEqual(securityParameters.engineBoots, 0)
        self.assertEqual(securityParameters.engineTime, 0)

    def test_time_parameters_are_zero_even_after_receiving_a_response(self):
        _ = self.usm.prepareOutgoing(self.message, 720.0)
        _ = self.usm.processIncoming(self.response, 721.0)

        message = SNMPv3Message(
            HeaderData(
                725,
                1234,
                MessageFlags(reportable=True),
                SecurityModel.USM,
            ),
            ScopedPDU(GetRequestPDU(requestID=730), self.engineID),
            self.engineID,
            SecurityName(self.userName, self.namespace),
        )

        wholeMsg = self.usm.prepareOutgoing(message, 735.0)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        self.assertEqual(securityParameters.engineBoots, 0)
        self.assertEqual(securityParameters.engineTime, 0)

class UsmOutgoingNoAuthAuthoritativeTest(unittest.TestCase):
    def setUp(self):
        self.userName = b"userName"
        self.namespace = "namespace"
        self.engineID = b"engineID"
        self.engineBoots = 750

        self.usm = UserBasedSecurityModule(
            engineID=self.engineID,
            namespace=self.namespace,
            engineBoots=self.engineBoots,
        )

        self.timestamp = time.time()
        self.usm.addUser(self.userName.decode(), namespace=self.namespace)

        self.message = SNMPv3Message(
            HeaderData(
                1234,
                1234,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(ResponsePDU(requestID=1234), self.engineID),
            self.engineID,
            SecurityName(self.userName, self.namespace),
        )

    def test_time_parameters_give_the_time_when_the_message_was_sent(self):
        timestamp = self.timestamp + 774.0
        wholeMsg = self.usm.prepareOutgoing(self.message, timestamp)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        self.assertEqual(securityParameters.engineBoots, self.engineBoots)
        self.assertEqual(securityParameters.engineTime, 774)

class UsmOutgoingAuthTest(unittest.TestCase):
    def setUp(self):
        self.userName = b"authUser"
        self.namespace = "auth-capable"
        self.engineID = b"UsmOutgoingAuthTest"

        self.authProtocol = DummyAuthProtocol
        self.authSecret = b"a useful and secure password"

        self.usm = UserBasedSecurityModule()
        self.usm.addUser(
            self.userName.decode(),
            namespace=self.namespace,
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        self.message = SNMPv3Message(
            HeaderData(
                91827,
                1824,
                MessageFlags(authNoPriv, reportable=True),
                SecurityModel.USM,
            ),
            ScopedPDU(GetRequestPDU(requestID=3223), self.engineID),
            self.engineID,
            SecurityName(self.userName, self.namespace),
        )

    def test_ValueError_if_userName_not_valid_in_namespace(self):
        message = SNMPv3Message(
            self.message.header,
            self.message.scopedPDU,
            self.engineID,
            SecurityName(b"invalid user", self.namespace),
        )

        self.assertRaises(ValueError, self.usm.prepareOutgoing, message)

    def test_TypeError_if_securityName_has_no_namespace(self):
        message = SNMPv3Message(
            self.message.header,
            self.message.scopedPDU,
            self.engineID,
            SecurityName(self.userName),
        )

        self.assertRaises(TypeError, self.usm.prepareOutgoing, message)

    def test_AuthenticationNotEnabled_if_user_does_not_support_auth(self):
        self.usm.addUser("noAuthUser", namespace=self.namespace)
        message = SNMPv3Message(
            self.message.header,
            self.message.scopedPDU,
            self.engineID,
            SecurityName(b"noAuthUser", self.namespace),
        )

        self.assertRaises(
            AuthenticationNotEnabled,
            self.usm.prepareOutgoing,
            message,
        )

    def test_signed_using_the_credentials_for_the_given_namespace(self):
        self.usm.addUser(
            self.userName.decode(),
            namespace="a second namespace",
            authProtocol=HmacMd5,
            authSecret=b"secret #2",
        )

        message = SNMPv3Message(
            self.message.header,
            self.message.scopedPDU,
            self.engineID,
            SecurityName(self.userName, "a second namespace"),
        )

        wholeMsg = self.usm.prepareOutgoing(message)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        signature = securityParameters.signature

        msg = signature.replace(bytes(len(signature)))
        auth = HmacMd5(HmacMd5.localize(b"secret #2", self.engineID))
        digest = auth.sign(msg)
        self.assertEqual(digest, signature)

    def test_securityName_may_reference_multiple_namespaces(self):
        self.usm.addUser(
            self.userName.decode(),
            namespace="a second namespace",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        message = SNMPv3Message(
            self.message.header,
            self.message.scopedPDU,
            self.engineID,
            SecurityName(self.userName, self.namespace, "a second namespace"),
        )

        wholeMsg = self.usm.prepareOutgoing(message)

    def test_msgPrivacyParameters_contains_empty_string(self):
        wholeMsg = self.usm.prepareOutgoing(self.message)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        self.assertEqual(securityParameters.salt, b"")

class UsmOutgoingAuthNonAuthoritativeTest(unittest.TestCase):
    def setUp(self):
        self.userName = b"authUser"
        self.namespace = "auth-capable"
        self.engineID = b"UsmOutgoingAuthNonAuthoritativeTest"

        self.authProtocol = DummyAuthProtocol
        self.authSecret = b"a useful and secure password"

        authKey = self.authProtocol.localize(self.authSecret, self.engineID)
        self.auth = self.authProtocol(authKey)

        self.usm = UserBasedSecurityModule()
        self.usm.addUser(
            self.userName.decode(),
            namespace=self.namespace,
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        self.message = SNMPv3Message(
            HeaderData(
                91827,
                1824,
                MessageFlags(authNoPriv, reportable=True),
                SecurityModel.USM,
            ),
            ScopedPDU(GetRequestPDU(requestID=3223), self.engineID),
            self.engineID,
            SecurityName(self.userName, self.namespace),
        )

    def test_time_parameters_zero_for_unknown_engine(self):
        wholeMsg = self.usm.prepareOutgoing(self.message)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        self.assertEqual(securityParameters.engineBoots, 0)
        self.assertEqual(securityParameters.engineTime, 0)

    def test_time_parameters_use_hint_if_no_better_info_available(self):
        discoveryReplyString = SNMPv3WireMessage(
            HeaderData(
                932,
                1234,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind("1.3.6.1.6.3.15.1.1.4.0", Counter32(1)),
                    requestID=937,
                ),
                self.engineID,
            ),
            OctetString(
                UnsignedUsmParameters(
                    self.engineID,
                    959,
                    960,
                    self.userName,
                    b"",
                    b"",
                ).encode(),
            ),
        ).encode()

        discoveryReply = SNMPv3WireMessage.decodeExact(discoveryReplyString)
        _ = self.usm.processIncoming(discoveryReply)

        wholeMsg = self.usm.prepareOutgoing(self.message, time.time() + 24.0)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        self.assertEqual(securityParameters.engineBoots, 959)
        self.assertEqual(securityParameters.engineTime, 984)

    def test_time_parameters_based_on_auth_message_if_available(self):
        responseUnsigned = SNMPv3WireMessage(
            HeaderData(
                991,
                1234,
                MessageFlags(authNoPriv),
                SecurityModel.USM,
            ),
            ScopedPDU(ResponsePDU(requestID=996), self.engineID),
            OctetString(
                UnsignedUsmParameters(
                    self.engineID,
                    1016,
                    1017,
                    self.userName,
                    self.auth.msgAuthenticationParameters,
                    b"",
                ).encode(),
            ),
        ).encode()

        padding = UnsignedUsmParameters.findPadding(
            SNMPv3WireMessage.findSecurityParameters(responseUnsigned),
        )

        responseString = padding.replace(self.auth.sign(responseUnsigned))
        response = SNMPv3WireMessage.decodeExact(responseString)

        _ = self.usm.processIncoming(response)

        wholeMsg = self.usm.prepareOutgoing(self.message, time.time() + 73.0)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        self.assertEqual(securityParameters.engineBoots, 1016)
        self.assertEqual(securityParameters.engineTime, 1090)

class UsmOutgoingAuthAuthoritativeTest(unittest.TestCase):
    def setUp(self):
        self.userName = b"authUser"
        self.namespace = "auth-capable"
        self.engineID = b"UsmOutgoingAuthAuthoritativeTest"
        self.engineBoots = 543

        self.authProtocol = DummyAuthProtocol
        self.authSecret = b"a useful and secure password"

        self.usm = UserBasedSecurityModule(
            engineID=self.engineID,
            namespace=self.namespace,
            engineBoots=self.engineBoots,
        )

        self.usm.addUser(
            self.userName.decode(),
            namespace=self.namespace,
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        self.message = SNMPv3Message(
            HeaderData(
                91827,
                1824,
                MessageFlags(authNoPriv, reportable=True),
                SecurityModel.USM,
            ),
            ScopedPDU(GetRequestPDU(requestID=3223), self.engineID),
            self.engineID,
            SecurityName(self.userName, self.namespace),
        )

    def test_time_parameters_included(self):
        wholeMsg = self.usm.prepareOutgoing(self.message, time.time() + 88.0)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        self.assertEqual(securityParameters.engineBoots, self.engineBoots)
        self.assertEqual(securityParameters.engineTime, 88)

class UsmOutgoingAuthPrivTest(unittest.TestCase):
    def setUp(self):
        self.userName = b"authPrivUser"
        self.namespace = "default namespace"
        self.engineID = b"UsmOutgoingAuthPrivTest"

        self.usm = UserBasedSecurityModule()
        self.usm.addUser(
            self.userName.decode(),
            namespace=self.namespace,
            authProtocol=DummyAuthProtocol,
            privProtocol=DummyPrivProtocol,
            secret=b"for your eyes only",
        )

        self.message = SNMPv3Message(
            HeaderData(
                8364,
                2901,
                MessageFlags(authPriv, True),
                SecurityModel.USM,
            ),
            ScopedPDU(GetRequestPDU(requestID=19), self.engineID),
            self.engineID,
            SecurityName(self.userName, self.namespace),
        )

    def test_Authentication_or_Privacy_NotEnabled_if_auth_not_supported(self):
        userName = b"noAuthUser"
        namespace = "default namespace"

        usm = UserBasedSecurityModule()
        usm.addUser(userName.decode(), namespace=namespace)

        message = SNMPv3Message(
            HeaderData(
                224,
                1924,
                MessageFlags(authPriv, True),
                SecurityModel.USM,
            ),
            ScopedPDU(GetRequestPDU(requestID=8432), self.engineID),
            self.engineID,
            SecurityName(userName, namespace),
        )

        try:
            usm.prepareOutgoing(message)
        except (AuthenticationNotEnabled, PrivacyNotEnabled):
            pass
        else:
            self.assertTrue(False)

    def test_PrivacyNotEnabled_if_priv_not_supported(self):
        userName = b"authOnlyUser"
        namespace = "default namespace"

        usm = UserBasedSecurityModule()
        usm.addUser(
            userName.decode(),
            namespace=namespace,
            authProtocol=DummyAuthProtocol,
            authSecret=b"don't tell anyone"
        )

        message = SNMPv3Message(
            HeaderData(
                224,
                1924,
                MessageFlags(authPriv, True),
                SecurityModel.USM,
            ),
            ScopedPDU(GetRequestPDU(requestID=8432), self.engineID),
            self.engineID,
            SecurityName(userName, namespace),
        )

        self.assertRaises(PrivacyNotEnabled, usm.prepareOutgoing, message)

    def test_msgPrivacyParameters_is_not_empty(self):
        wholeMsg = self.usm.prepareOutgoing(self.message)
        spString = SNMPv3WireMessage.findSecurityParameters(wholeMsg)
        securityParameters = SignedUsmParameters.decodeExact(spString)
        salt = securityParameters.salt
        self.assertGreater(len(salt), 0)

    def test_scopedPduData_is_an_OCTET_STRING(self):
        wholeMsg = self.usm.prepareOutgoing(self.message)
        tag, ptr = decodeExact(wholeMsg)
        tag, version, ptr   = decode(ptr)
        tag, header, ptr    = decode(ptr)
        tag, sp, ptr        = decode(ptr)
        tag, scopedPDU      = decodeExact(ptr)
        self.assertEqual(tag, OctetString.TAG)

class IncomingMessageTest(unittest.TestCase):
    def setUp(self):
        self.usm = UserBasedSecurityModule()
        self.response = ResponsePDU(
            VarBind("1.2.3.4.5.6", Integer(123456)),
            requestID = 0x87654321,
        )

    def test_ParseError_for_invalid_securityParameters(self):
        wireMessage = SNMPv3WireMessage(
            HeaderData(
                0x12345678,
                1472,
                MessageFlags(noAuthNoPriv),
                SecurityModel.USM,
            ),
            ScopedPDU(self.response, b"remote engine ID", b"test context"),
            OctetString(b"not a valid security parameters string"),
        )

        self.assertRaises(ParseError, self.usm.processIncoming, wireMessage)

class UnknownEngineIDTest(unittest.TestCase):
    def setUp(self):
        self.userName = b"testUser"
        self.authProtocol = HmacSha256
        self.authSecret = b"unguessable"
        self.privProtocol = DummyPrivProtocol
        self.privSecret = b"dummy"

        self.local = UserBasedSecurityModule(engineID=b"local", namespace="")
        self.remote = UserBasedSecurityModule(engineID=b"remote", namespace="")

        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        self.remote.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        self.messageID = 0x630b6c41
        self.requestID = -0x359cbaf1

    def makeHeader(self, flags):
        return HeaderData(self.messageID, 1500, flags, SecurityModel.USM)

    def makeMessage(self, header, pdu, engineID, context=b""):
        return SNMPv3Message(
            header,
            ScopedPDU(pdu.withRequestID(self.requestID), engineID, context),
            engineID,
            SecurityName(self.userName, "")
        )

    def test_usm_with_no_engineID_does_not_report_unknownEngineID(self):
        local = UserBasedSecurityModule()
        local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        header = self.makeHeader(MessageFlags(authNoPriv, True))
        message = self.makeMessage(header, GetRequestPDU(), b"local")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(local.unknownEngineIDs, 0)
        self.assertRaises(UnknownEngineID, local.processIncoming, wireMessage)
        self.assertEqual(local.unknownEngineIDs, 1)

    def test_report_UnknownEngineID_if_securityEngineID_does_not_match(self):
        pdu = GetRequestPDU()
        header = self.makeHeader(MessageFlags(authNoPriv, True))
        message = self.makeMessage(header, pdu, b"wrong", b"testCtx")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unknownEngineIDs, 0)

        try:
            self.local.processIncoming(wireMessage)
        except ReportMessage as report:
            message = report.message
            header = message.header
            scopedPDU = message.scopedPDU
            pdu = scopedPDU.pdu

            self.assertFalse(header.flags.authFlag)
            self.assertEqual(header.msgID, self.messageID)
            self.assertEqual(scopedPDU.contextName, b"testCtx")
            self.assertEqual(pdu.requestID, self.requestID)

            self.assertGreaterEqual(len(pdu.variableBindings), 1)
            vb = pdu.variableBindings[0]

            self.assertEqual(vb.name, OID(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0))
            self.assertEqual(vb.value.TAG, Counter32.TAG)
            self.assertEqual(vb.value.value, 1)
        else:
            self.assertTrue(False)

        self.assertEqual(self.local.unknownEngineIDs, 1)

    def test_reportable_flag_True_ignored_if_the_payload_is_unencrypted(self):
        header = self.makeHeader(MessageFlags(authNoPriv, True))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)
        message = self.local.processIncoming(wireMessage)

    def test_reportable_flag_False_ignored_if_the_payload_is_unencrypted(self):
        remote = UserBasedSecurityModule(engineID=b"remote", namespace="")

        # Use the wrong authSecret to make sure it reports the unknown
        # engine ID before attempting to verify the signature
        remote.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret + b"\0",
        )

        pdu = GetRequestPDU()
        header = self.makeHeader(MessageFlags(authNoPriv, False))
        message = self.makeMessage(header, pdu, b"wrong", b"testCtx")
        wholeMsg = remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unknownEngineIDs, 0)

        try:
            self.local.processIncoming(wireMessage)
        except ReportMessage as report:
            message = report.message
            header = message.header
            scopedPDU = message.scopedPDU
            pdu = scopedPDU.pdu

            self.assertFalse(header.flags.authFlag)
            self.assertEqual(header.msgID, self.messageID)
            self.assertEqual(scopedPDU.contextName, b"testCtx")
            self.assertEqual(pdu.requestID, self.requestID)

            self.assertGreaterEqual(len(pdu.variableBindings), 1)
            vb = pdu.variableBindings[0]

            self.assertEqual(vb.name, OID(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0))
            self.assertEqual(vb.value.TAG, Counter32.TAG)
            self.assertEqual(vb.value.value, 1)
        else:
            self.assertTrue(False)

        self.assertEqual(self.local.unknownEngineIDs, 1)

    def test_send_report_if_reportable_flag_set_and_payload_is_encrypted(self):
        header = self.makeHeader(MessageFlags(authPriv, True))
        message = self.makeMessage(header, ResponsePDU(), b"wrong", b"testCtx")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unknownEngineIDs, 0)

        try:
            self.local.processIncoming(wireMessage)
        except ReportMessage as report:
            message = report.message
            header = message.header
            scopedPDU = message.scopedPDU
            pdu = scopedPDU.pdu

            self.assertFalse(header.flags.authFlag)
            self.assertEqual(header.msgID, self.messageID)
            self.assertEqual(scopedPDU.contextName, b"")
            self.assertEqual(pdu.requestID, 0)

            self.assertGreaterEqual(len(pdu.variableBindings), 1)
            vb = pdu.variableBindings[0]

            self.assertEqual(vb.name, OID(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0))
            self.assertEqual(vb.value.TAG, Counter32.TAG)
            self.assertEqual(vb.value.value, 1)
        else:
            self.assertTrue(False)

        self.assertEqual(self.local.unknownEngineIDs, 1)

    def test_send_report_after_decrypt_if_reportable_flag_wrongly_unset(self):
        pdu = GetRequestPDU()
        header = self.makeHeader(MessageFlags(authPriv, False))
        message = self.makeMessage(header, pdu, b"wrong", b"testCtx")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unknownEngineIDs, 0)

        try:
            self.local.processIncoming(wireMessage)
        except ReportMessage as report:
            message = report.message
            header = message.header
            scopedPDU = message.scopedPDU
            pdu = scopedPDU.pdu
            securityName = message.securityName

            self.assertTrue(header.flags.authFlag)
            self.assertEqual(securityName.userName, self.userName)
            self.assertEqual(len(securityName.namespaces), 1)
            self.assertIn("", securityName.namespaces)

            self.assertEqual(header.msgID, self.messageID)
            self.assertEqual(scopedPDU.contextName, b"testCtx")
            self.assertEqual(pdu.requestID, self.requestID)

            self.assertGreaterEqual(len(pdu.variableBindings), 1)
            vb = pdu.variableBindings[0]

            self.assertEqual(vb.name, OID(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0))
            self.assertEqual(vb.value.TAG, Counter32.TAG)
            self.assertEqual(vb.value.value, 1)
        else:
            self.assertTrue(False)

        self.assertEqual(self.local.unknownEngineIDs, 1)

class UnknownUserNameTest(unittest.TestCase):
    def setUp(self):
        self.local = UserBasedSecurityModule(engineID=b"local", namespace="")
        self.remote = UserBasedSecurityModule(engineID=b"remote", namespace="")

        self.userName = b"unknown"

        self.remote.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=DummyAuthProtocol,
            privProtocol=DummyPrivProtocol,
            secret=b"doesn't matter",
        )

        self.messageID = 0x3459b155
        self.requestID = 0x3b2650d4

    def makeHeader(self, flags):
        return HeaderData(self.messageID, 1500, flags, SecurityModel.USM)

    def makeMessage(self, header, pdu, engineID, context=b""):
        return SNMPv3Message(
            header,
            ScopedPDU(pdu.withRequestID(self.requestID), engineID, context),
            engineID,
            SecurityName(self.userName, ""),
        )

    def test_UnknownUserName_for_authenticated_message(self):
        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unknownUserNames, 0)
        self.assertRaises(
            UnknownUserName,
            self.local.processIncoming,
            wireMessage
        )
        self.assertEqual(self.local.unknownUserNames, 1)

    def test_authoritative_ignores_right_userName_in_wrong_namespace(self):
        self.local.addUser(self.userName.decode(), namespace="anything")

        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, SNMPv2TrapPDU(), b"local")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unknownUserNames, 0)
        self.assertRaises(
            UnknownUserName,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.unknownUserNames, 1)

    def test_authoritative_engine_does_not_send_report_if_not_reportable(self):
        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, SNMPv2TrapPDU(), b"local")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unknownUserNames, 0)
        self.assertRaises(
            UnknownUserName,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.unknownUserNames, 1)

    def test_authoritative_engine_sends_report_if_reportable(self):
        pdu = GetRequestPDU()
        header = self.makeHeader(MessageFlags(authNoPriv, True))
        message = self.makeMessage(header, pdu, b"local", b"testContextName")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unknownUserNames, 0)

        try:
            self.local.processIncoming(wireMessage)
        except ReportMessage as report:
            message = report.message
            header = message.header
            scopedPDU = message.scopedPDU
            pdu = scopedPDU.pdu

            self.assertFalse(header.flags.authFlag)
            self.assertEqual(header.msgID, self.messageID)
            self.assertEqual(scopedPDU.contextName, b"testContextName")
            self.assertEqual(pdu.requestID, self.requestID)

            self.assertGreaterEqual(len(pdu.variableBindings), 1)
            vb = pdu.variableBindings[0]

            self.assertEqual(vb.name, OID(1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0))
            self.assertEqual(vb.value.TAG, Counter32.TAG)
            self.assertEqual(vb.value.value, 1)
        else:
            self.assertTrue(False)

        self.assertEqual(self.local.unknownUserNames, 1)

    def test_report_fields_contain_defaults_if_message_is_encrypted(self):
        pdu = GetRequestPDU()
        header = self.makeHeader(MessageFlags(authPriv, True))
        message = self.makeMessage(header, pdu, b"local", b"testContextName")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unknownUserNames, 0)

        try:
            self.local.processIncoming(wireMessage)
        except ReportMessage as report:
            message = report.message
            header = message.header
            scopedPDU = message.scopedPDU
            pdu = scopedPDU.pdu

            self.assertFalse(header.flags.authFlag)
            self.assertEqual(header.msgID, self.messageID)
            self.assertEqual(scopedPDU.contextName, b"")
            self.assertEqual(pdu.requestID, 0)

            self.assertGreaterEqual(len(pdu.variableBindings), 1)
            vb = pdu.variableBindings[0]

            self.assertEqual(vb.name, OID(1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0))
            self.assertEqual(vb.value.TAG, Counter32.TAG)
            self.assertEqual(vb.value.value, 1)
        else:
            self.assertTrue(False)

        self.assertEqual(self.local.unknownUserNames, 1)

class UnsupportedSecLevelTest(unittest.TestCase):
    def setUp(self):
        self.local = UserBasedSecurityModule(engineID=b"local", namespace="")
        self.remote = UserBasedSecurityModule(engineID=b"remote", namespace="")

        self.userName = b"unsupportedSecLevelUser"
        self.messageID = 0x68b362aa
        self.requestID = 0x58b9793e

        self.remote.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=DummyAuthProtocol,
            authSecret=b"very secret",
        )

    def makeHeader(self, flags):
        return HeaderData(self.messageID, 1500, flags, SecurityModel.USM)

    def makeMessage(self, header, pdu, engineID, context=b""):
        return SNMPv3Message(
            header,
            ScopedPDU(pdu.withRequestID(self.requestID), engineID, context),
            engineID,
            SecurityName(self.userName, ""),
        )

    def test_auth_is_not_enabled_for_user(self):
        self.local.addUser(self.userName.decode(), namespace="")

        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unsupportedSecLevels, 0)
        self.assertRaises(
            UnsupportedSecLevel,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.unsupportedSecLevels, 1)

    def test_user_defined_in_multiple_namespaces_but_none_support_auth(self):
        self.local.addUser(self.userName.decode(), namespace="A")
        self.local.addUser(self.userName.decode(), namespace="B")
        self.local.addUser(self.userName.decode(), namespace="C")

        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unsupportedSecLevels, 0)
        self.assertRaises(
            UnsupportedSecLevel,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.unsupportedSecLevels, 1)

    def test_authoritative_engine_does_not_send_report_if_not_reportable(self):
        self.local.addUser(self.userName.decode(), namespace="")

        pdu = SNMPv2TrapPDU()
        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, pdu, b"local")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unsupportedSecLevels, 0)
        self.assertRaises(
            UnsupportedSecLevel,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.unsupportedSecLevels, 1)

    def test_authoritative_engine_sends_report_if_reportable(self):
        self.local.addUser(self.userName.decode(), namespace="")

        pdu = GetRequestPDU()
        header = self.makeHeader(MessageFlags(authNoPriv, True))
        message = self.makeMessage(header, pdu, b"local", b"testContextName")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unsupportedSecLevels, 0)

        try:
            self.local.processIncoming(wireMessage)
        except ReportMessage as report:
            message = report.message
            header = message.header
            scopedPDU = message.scopedPDU
            pdu = scopedPDU.pdu

            self.assertFalse(header.flags.authFlag)
            self.assertEqual(header.msgID, self.messageID)
            self.assertEqual(scopedPDU.contextName, b"testContextName")
            self.assertEqual(pdu.requestID, self.requestID)

            self.assertGreaterEqual(len(pdu.variableBindings), 1)
            vb = pdu.variableBindings[0]

            self.assertEqual(vb.name, OID(1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0))
            self.assertEqual(vb.value.TAG, Counter32.TAG)
            self.assertEqual(vb.value.value, 1)
        else:
            self.assertTrue(False)

        self.assertEqual(self.local.unsupportedSecLevels, 1)

class UnsupportedPrivacyTest(unittest.TestCase):
    def setUp(self):
        if not privacySupported:
            msg = "The requisite encryption libraries are not installed"
            self.skipTest(msg)

        self.local = UserBasedSecurityModule(engineID=b"local", namespace="")
        self.remote = UserBasedSecurityModule(engineID=b"remote", namespace="")

        self.userName = b"allOutInTheOpen"
        self.authProtocol = HmacSha256
        self.authSecret = b"authentic"

        self.remote.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            privProtocol=DummyPrivProtocol,
            authSecret=self.authSecret,
            privSecret=b"private",
        )

        self.messageID = 0x1d0d13ff
        self.requestID = -0x187cf28d

    def makeHeader(self, flags):
        return HeaderData(self.messageID, 1500, flags, SecurityModel.USM)

    def makeMessage(self, header, pdu, engineID, context=b""):
        return SNMPv3Message(
            header,
            ScopedPDU(pdu.withRequestID(self.requestID), engineID, context),
            engineID,
            SecurityName(self.userName, ""),
        )

    def test_priv_is_not_enabled_for_user(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        header = self.makeHeader(MessageFlags(authPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unsupportedSecLevels, 0)
        self.assertRaises(
            UnsupportedSecLevel,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.unsupportedSecLevels, 1)

    def test_user_supports_auth_in_multiple_namespaces_but_not_priv(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="A",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        self.local.addUser(
            self.userName.decode(),
            namespace="B",
            authProtocol=self.authProtocol,
            secret=self.authSecret,
        )

        header = self.makeHeader(MessageFlags(authPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unsupportedSecLevels, 0)
        self.assertRaises(
            UnsupportedSecLevel,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.unsupportedSecLevels, 1)

    def test_authoritative_engine_does_not_send_report_if_not_reportable(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        pdu = SNMPv2TrapPDU()
        header = self.makeHeader(MessageFlags(authPriv))
        message = self.makeMessage(header, pdu, b"local")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unsupportedSecLevels, 0)
        self.assertRaises(
            UnsupportedSecLevel,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.unsupportedSecLevels, 1)

    def test_authoritative_engine_sends_report_if_reportable(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        pdu = GetRequestPDU()
        header = self.makeHeader(MessageFlags(authPriv, True))
        message = self.makeMessage(header, pdu, b"local", b"testContextName")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.unsupportedSecLevels, 0)

        try:
            self.local.processIncoming(wireMessage)
        except ReportMessage as report:
            message = report.message
            header = message.header
            scopedPDU = message.scopedPDU
            pdu = scopedPDU.pdu
            securityName = message.securityName

            self.assertTrue(header.flags.authFlag)
            self.assertEqual(securityName.userName, self.userName)
            self.assertEqual(len(securityName.namespaces), 1)
            self.assertIn("", securityName.namespaces)

            self.assertEqual(header.msgID, self.messageID)
            self.assertEqual(scopedPDU.contextName, b"")
            self.assertEqual(pdu.requestID, 0)

            self.assertGreaterEqual(len(pdu.variableBindings), 1)
            vb = pdu.variableBindings[0]

            self.assertEqual(vb.name, OID(1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0))
            self.assertEqual(vb.value.TAG, Counter32.TAG)
            self.assertEqual(vb.value.value, 1)
        else:
            self.assertTrue(False)

        self.assertEqual(self.local.unsupportedSecLevels, 1)

class WrongDigestsTest(unittest.TestCase):
    def setUp(self):
        self.local = UserBasedSecurityModule(engineID=b"local", namespace="")
        self.remote = UserBasedSecurityModule(engineID=b"remote", namespace="")

        self.userName = b"A"
        self.authProtocol = HmacSha512
        self.authSecret = b"this one is right"

        self.remote.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        self.messageID = 0x4616d882
        self.requestID = -0x6b3975e2

    def makeHeader(self, flags):
        return HeaderData(self.messageID, 1500, flags, SecurityModel.USM)

    def makeMessage(self, header, pdu, engineID, context=b""):
        return SNMPv3Message(
            header,
            ScopedPDU(pdu.withRequestID(self.requestID), engineID, context),
            engineID,
            SecurityName(self.userName, "")
        )

    def test_WrongDigest_if_computed_signature_does_not_match(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=b"this one is wrong",
        )

        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.wrongDigests, 0)
        self.assertRaises(WrongDigest, self.local.processIncoming, wireMessage)
        self.assertEqual(self.local.wrongDigests, 1)

    def test_if_one_namespace_supports_auth_then_disregard_the_rest(self):
        self.local.addUser(self.userName.decode(), namespace="A")

        self.local.addUser(
            self.userName.decode(),
            namespace="B",
            authProtocol=self.authProtocol,
            authSecret=b"this one is wrong",
        )

        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.wrongDigests, 0)
        self.assertRaises(WrongDigest, self.local.processIncoming, wireMessage)
        self.assertEqual(self.local.wrongDigests, 1)

    def test_multiple_namespaces_that_compute_different_signatures(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="wrong algorithm",
            authProtocol=HmacSha384,
            authSecret=self.authSecret,
        )

        self.local.addUser(
            self.userName.decode(),
            namespace="wrong secret",
            authProtocol=self.authProtocol,
            authSecret=b"this one is wrong",
        )

        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.wrongDigests, 0)
        self.assertRaises(WrongDigest, self.local.processIncoming, wireMessage)
        self.assertEqual(self.local.wrongDigests, 1)

    def test_authoritative_engine_does_not_send_report_if_not_reportable(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=b"this one is wrong",
        )

        pdu = SNMPv2TrapPDU()
        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, pdu, b"local")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.wrongDigests, 0)
        self.assertRaises(WrongDigest, self.local.processIncoming, wireMessage)
        self.assertEqual(self.local.wrongDigests, 1)

    def test_authoritative_engine_sends_report_if_reportable(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=b"this one is wrong",
        )

        pdu = GetRequestPDU()
        header = self.makeHeader(MessageFlags(authNoPriv, True))
        message = self.makeMessage(header, pdu, b"local", b"WrongDigestsTest")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.wrongDigests, 0)

        try:
            self.local.processIncoming(wireMessage)
        except ReportMessage as report:
            message = report.message
            header = message.header
            scopedPDU = message.scopedPDU
            pdu = scopedPDU.pdu

            self.assertEqual(header.msgID, self.messageID)
            self.assertFalse(header.flags.authFlag)
            self.assertEqual(scopedPDU.contextName, b"WrongDigestsTest")
            self.assertEqual(pdu.requestID, self.requestID)

            self.assertGreaterEqual(len(pdu.variableBindings), 1)
            vb = pdu.variableBindings[0]

            self.assertEqual(vb.name, OID(1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0))
            self.assertEqual(vb.value.TAG, Counter32.TAG)
            self.assertEqual(vb.value.value, 1)
        else:
            self.assertTrue(False)

        self.assertEqual(self.local.wrongDigests, 1)

class DecryptionErrors(unittest.TestCase):
    def setUp(self):
        if not privacySupported:
            msg = "The requisite encryption libraries are not installed"
            self.skipTest(msg)

        self.local = UserBasedSecurityModule(engineID=b"local", namespace="")
        self.remote = UserBasedSecurityModule(engineID=b"remote", namespace="")

        self.userName = b"decryptionErrorUser"
        self.authProtocol = HmacSha256
        self.privProtocol = DesCbc
        self.authSecret = b"authentic"
        self.privSecret = b"private"

        self.remote.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        self.messageID = 0x292244c3
        self.requestID = 0x5f29cf2d

    def makeHeader(self, flags):
        return HeaderData(self.messageID, 1500, flags, SecurityModel.USM)

    def makeMessage(self, header, pdu, engineID, context=b""):
        return SNMPv3Message(
            header,
            ScopedPDU(pdu.withRequestID(self.requestID), engineID, context),
            engineID,
            SecurityName(self.userName, "")
        )

    def test_DecryptionError_if_signature_matches_but_decryption_fails(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="incorrect",
            authProtocol=self.authProtocol,
            authSecret=b"inauthentic",
        )

        self.local.addUser(
            self.userName.decode(),
            namespace="correct",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=b"public",
        )

        header = self.makeHeader(MessageFlags(authPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.decryptionErrors, 0)
        self.assertRaises(
            DecryptionError,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.decryptionErrors, 1)

    def test_if_one_namesace_supports_priv_then_disregard_the_rest(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="A",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        self.local.addUser(
            self.userName.decode(),
            namespace="B",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=self.authSecret,
        )

        header = self.makeHeader(MessageFlags(authPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.decryptionErrors, 0)
        self.assertRaises(
            DecryptionError,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.decryptionErrors, 1)

    def test_multiple_namespaces_valid_signature_but_failed_decryption(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="A",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=b"public",
        )

        self.local.addUser(
            self.userName.decode(),
            namespace="B",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=self.authSecret,
        )

        header = self.makeHeader(MessageFlags(authPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.decryptionErrors, 0)
        self.assertRaises(
            DecryptionError,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.decryptionErrors, 1)

    def test_authoritative_engine_does_not_send_report_if_not_reportable(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=b"public"
        )

        pdu = SNMPv2TrapPDU()
        header = self.makeHeader(MessageFlags(authPriv))
        message = self.makeMessage(header, pdu, b"local")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.decryptionErrors, 0)
        self.assertRaises(
            DecryptionError,
            self.local.processIncoming,
            wireMessage,
        )
        self.assertEqual(self.local.decryptionErrors, 1)

    def test_authoritative_engine_sends_report_if_reportable(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=b"public"
        )

        pdu = GetRequestPDU()
        header = self.makeHeader(MessageFlags(authPriv, True))
        message = self.makeMessage(header, pdu, b"local", b"DecryptionContext")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        self.assertEqual(self.local.decryptionErrors, 0)

        try:
            self.local.processIncoming(wireMessage)
        except ReportMessage as report:
            message = report.message
            header = message.header
            scopedPDU = message.scopedPDU
            pdu = message.scopedPDU.pdu
            securityName = message.securityName

            self.assertTrue(message.header.flags.authFlag)
            self.assertEqual(securityName.userName, self.userName)
            self.assertEqual(len(securityName.namespaces), 1)
            self.assertIn("", securityName.namespaces)

            self.assertEqual(header.msgID, self.messageID)
            self.assertEqual(scopedPDU.contextName, b"")
            self.assertEqual(pdu.requestID, 0)

            self.assertGreaterEqual(len(pdu.variableBindings), 1)
            vb = pdu.variableBindings[0]

            self.assertEqual(vb.name, OID(1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0))
            self.assertEqual(vb.value.TAG, Counter32.TAG)
            self.assertEqual(vb.value.value, 1)
        else:
            self.assertTrue(False)

        self.assertEqual(self.local.decryptionErrors, 1)

class SuccessfulIncomingMessageTest(unittest.TestCase):
    def setUp(self):
        self.local = UserBasedSecurityModule(engineID=b"local", namespace="")
        self.remote = UserBasedSecurityModule(engineID=b"remote", namespace="")

        self.userName = b"winner"
        self.authProtocol = HmacSha512
        self.authSecret = b"success!"

        self.remote.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        self.messageID = 0x0c2db104
        self.requestID = 0x298d143c

    def makeHeader(self, flags):
        return HeaderData(self.messageID, 1500, flags, SecurityModel.USM)

    def makeMessage(self, header, pdu, engineID, context=b""):
        return SNMPv3Message(
            header,
            ScopedPDU(pdu.withRequestID(self.requestID), engineID, context),
            engineID,
            SecurityName(self.userName, "")
        )

    def test_unknown_username_is_accepted_with_noAuthNoPriv(self):
        header = self.makeHeader(MessageFlags())
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(len(message.securityName.namespaces), 0)

    def test_authenticated_namespace_included_in_securityName(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(len(message.securityName.namespaces), 1)
        self.assertIn("", message.securityName.namespaces)

    def test_namespace_with_auth_disabled_not_included_in_securityName(self):
        self.local.addUser(self.userName.decode(), namespace="A")

        self.local.addUser(
            self.userName.decode(),
            namespace="B",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(len(message.securityName.namespaces), 1)
        self.assertIn("B", message.securityName.namespaces)

    def test_failing_namespace_not_included_in_securityName(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="correct",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        self.local.addUser(
            self.userName.decode(),
            namespace="incorrect",
            authProtocol=self.authProtocol,
            authSecret=b"failure...",
        )

        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(len(message.securityName.namespaces), 1)
        self.assertIn("correct", message.securityName.namespaces)

    def test_all_authenticated_namespaces_included_in_securityName(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="A",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        self.local.addUser(
            self.userName.decode(),
            namespace="B",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        header = self.makeHeader(MessageFlags(authNoPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(len(message.securityName.namespaces), 2)
        self.assertIn("A", message.securityName.namespaces)
        self.assertIn("B", message.securityName.namespaces)

    def test_authoritative_engine_accepts_message_with_a_valid_signature(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        pdu = GetRequestPDU()
        header = self.makeHeader(MessageFlags(authNoPriv, True))
        message = self.makeMessage(header, pdu, b"local", b"successContext")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(len(message.securityName.namespaces), 1)
        self.assertIn("", message.securityName.namespaces)
        self.assertEqual(message.scopedPDU.contextName, b"successContext")

class SuccessfulIncomingPrivateMessageTest(unittest.TestCase):
    def setUp(self):
        if not privacySupported:
            msg = "The requisite encryption libraries are not installed"
            self.skipTest(msg)

        self.local = UserBasedSecurityModule(engineID=b"local", namespace="")
        self.remote = UserBasedSecurityModule(engineID=b"remote", namespace="")

        self.userName = b"user"
        self.authProtocol = HmacSha256
        self.privProtocol = DesCbc
        self.authSecret = b"authentic"
        self.privSecret = b"private"

        self.remote.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        self.messageID = 0x6f391d45
        self.requestID = -0x0c0fa6b5

    def makeHeader(self, flags):
        return HeaderData(self.messageID, 1500, flags, SecurityModel.USM)

    def makeMessage(self, header, pdu, engineID, context=b""):
        return SNMPv3Message(
            header,
            ScopedPDU(pdu.withRequestID(self.requestID), engineID, context),
            engineID,
            SecurityName(self.userName, "")
        )

    def test_inauthentic_namespace_not_included_in_securityName(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="incorrect",
            authProtocol=self.authProtocol,
            authSecret=b"inauthentic",
        )

        self.local.addUser(
            self.userName.decode(),
            namespace="correct",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        header = self.makeHeader(MessageFlags(authPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(len(message.securityName.namespaces), 1)
        self.assertIn("correct", message.securityName.namespaces)
        self.assertEqual(message.scopedPDU.pdu.requestID, self.requestID)

    def test_ignore_namespace_that_does_not_support_priv(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="A",
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        self.local.addUser(
            self.userName.decode(),
            namespace="B",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        header = self.makeHeader(MessageFlags(authPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(len(message.securityName.namespaces), 1)
        self.assertIn("B", message.securityName.namespaces)

    def test_failed_namespace_not_included_in_securityName(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="A",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        self.local.addUser(
            self.userName.decode(),
            namespace="B",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=self.authSecret,
        )

        header = self.makeHeader(MessageFlags(authPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(len(message.securityName.namespaces), 1)
        self.assertIn("A", message.securityName.namespaces)

    def test_multiple_successful_namespaces_included_in_securityName(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="A",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        self.local.addUser(
            self.userName.decode(),
            namespace="B",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        header = self.makeHeader(MessageFlags(authPriv))
        message = self.makeMessage(header, ResponsePDU(), b"remote")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(len(message.securityName.namespaces), 2)
        self.assertIn("A", message.securityName.namespaces)
        self.assertIn("B", message.securityName.namespaces)

    def test_authoritative_engine_accepts_valid_message(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        pdu = GetRequestPDU()
        header = self.makeHeader(MessageFlags(authPriv, True))
        message = self.makeMessage(header, pdu, b"local", b"successContext")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(len(message.securityName.namespaces), 1)
        self.assertIn("", message.securityName.namespaces)
        self.assertEqual(message.scopedPDU.contextName, b"successContext")

class ScopedPduPaddingTest(unittest.TestCase):
    class PaddedScopedPDU(ScopedPDU):
        def encode(self):
            return super().encode() + bytes(10)

    def setUp(self):
        self.local = UserBasedSecurityModule(engineID=b"local", namespace="")
        self.remote = UserBasedSecurityModule(engineID=b"remote", namespace="")

        self.userName = b"paddington"
        self.authProtocol = HmacSha
        self.privProtocol = AesCfb128
        self.authSecret = b"lock it up"
        self.privSecret = b"hide the key"

        self.remote.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        self.messageID = 0x52448986
        self.requestID = -0x41ac61a6

    def makeHeader(self, flags):
        return HeaderData(self.messageID, 1500, flags, SecurityModel.USM)

    def makeMessage(self, header, pdu, engineID, context=b""):
        scopedPDU = self.PaddedScopedPDU(
            pdu.withRequestID(self.requestID),
            engineID,
            context,
        )

        securityName = SecurityName(self.userName, "")
        return SNMPv3Message(header, scopedPDU, engineID, securityName)

    def test_privFlag_False_and_ScopedPDU_has_padding(self):
        header = self.makeHeader(MessageFlags(authNoPriv, True))
        message = self.makeMessage(header, GetRequestPDU(), b"local")
        wholeMsg = self.remote.prepareOutgoing(message)
        self.assertRaises(ParseError, SNMPv3WireMessage.decode, wholeMsg)

    def test_privFlag_True_and_ScopedPDU_has_padding(self):
        self.local.addUser(
            self.userName.decode(),
            namespace="",
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            authSecret=self.authSecret,
            privSecret=self.privSecret,
        )

        header = self.makeHeader(MessageFlags(authPriv, True))
        message = self.makeMessage(header, GetRequestPDU(), b"local")
        wholeMsg = self.remote.prepareOutgoing(message)
        wireMessage = SNMPv3WireMessage.decodeExact(wholeMsg)

        message = self.local.processIncoming(wireMessage)
        self.assertEqual(message.header.msgID, self.messageID)
        self.assertEqual(message.scopedPDU.pdu.requestID, self.requestID)
        self.assertEqual(message.scopedPDU.contextEngineID, b"local")
        self.assertEqual(message.securityEngineID, b"local")
        self.assertEqual(message.securityName.userName, self.userName)

if __name__ == "__main__":
    unittest.main()
