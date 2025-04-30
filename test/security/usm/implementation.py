__all__ = [
    "UsmLocalizeTest", "UsmUserConfigTest",
    "UsmOutgoingTest", "UsmSyncTest", "UsmIncomingTest",
]

import re
import unittest

from snmp.exception import *
from snmp.message.v3 import *
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.usm.auth import *
from snmp.security.usm.credentials import *
from snmp.security.usm.implementation import *
from snmp.security.usm.timekeeper import *
from snmp.smi import *
from snmp.v3.message import *

from . import DummyAuthProtocol, DummyPrivProtocol

class UsmLocalizeTest(unittest.TestCase):
    def setUp(self):
        self.secret = b"maplesyrup"
        self.engineID = bytes.fromhex("000000000000000000000002")
        self.privProtocol = DummyPrivProtocol
        self.usm = UserBasedSecurityModule()

    def testAuthLocalization(self):
        authProtocol = HmacMd5
        key = bytes.fromhex("526f5eed9fcce26f8964c2930787d82b")

        credentials = AuthCredentials(authProtocol, self.secret)
        localizedCredentials = credentials.localize(self.engineID)

        self.assertIsInstance(localizedCredentials.auth, authProtocol)

        # NOTE: relies on non-public attribute
        self.assertEqual(localizedCredentials.auth.key, authProtocol(key).key)
        self.assertIsNone(localizedCredentials.priv)

    def testFullLocalization(self):
        key = bytes.fromhex("6695febc9288e36282235fc7151f128497b38f3f")

        c = AuthPrivCredentials(
            authProtocol=HmacSha,
            privProtocol=self.privProtocol,
            secret=self.secret,
        )

        credentials = c.localize(self.engineID)

        self.assertIsNotNone(credentials.auth)
        self.assertIsInstance(credentials.priv, self.privProtocol)
        self.assertEqual(credentials.priv.key, key)

class UsmUserConfigTest(unittest.TestCase):
    def setUp(self):
        self.user = "someUser"
        self.namespace = "someNamespace"
        self.authProtocol = HmacSha512
        self.privProtocol = DummyPrivProtocol
        self.authSecret = b"someAuthSecret"
        self.privSecret = b"somePrivSecret"

        self.usm = UserBasedSecurityModule()

    def testNoUsers(self):
        self.assertRaises(ValueError, self.usm.getDefaultUser)

    def testInvalidUser(self):
        self.usm.addUser(self.user)
        self.assertRaises(
            ValueError,
            self.usm.getDefaultSecurityLevel,
            "invalidUser",
        )

    def testUserNameOnly(self):
        self.usm.addUser(self.user)

        defaultSecurityLevel = self.usm.getDefaultSecurityLevel(self.user)
        self.assertEqual(defaultSecurityLevel, noAuthNoPriv)
        self.assertEqual(self.usm.getDefaultUser(), self.user)

    def testAutomaticDefaultUser(self):
        self.usm.addUser("user1")
        self.usm.addUser("user2")
        self.assertEqual(self.usm.getDefaultUser(), "user1")

    def testDefaultUser(self):
        self.usm.addUser("user1")
        self.usm.addUser("user2", default=True)
        self.assertEqual(self.usm.getDefaultUser(), "user2")

    def testNamespaces(self):
        self.usm.addUser(self.user)
        self.usm.addUser(self.user, namespace=self.namespace)
        self.usm.addUser("otherUser", default=True, namespace=self.namespace)

        self.assertEqual(self.usm.getDefaultUser(), self.user)
        self.assertEqual(self.usm.getDefaultUser(self.namespace), "otherUser")

    def testAutomaticDefaultSecurityLevel(self):
        self.usm.addUser(
            self.user,
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        defaultSecurityLevel = self.usm.getDefaultSecurityLevel(self.user)
        self.assertEqual(defaultSecurityLevel, authNoPriv)

    def testDefaultSecurityLevel(self):
        self.usm.addUser(
            self.user,
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
            privProtocol=self.authProtocol,
            privSecret=self.authSecret,
            defaultSecurityLevel=authNoPriv,
        )

        defaultSecurityLevel = self.usm.getDefaultSecurityLevel(self.user)
        self.assertEqual(defaultSecurityLevel, authNoPriv)

    def testInvalidDefaultSecurityLevel(self):
        self.assertRaises(
            ValueError,
            self.usm.addUser,
            self.user,
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
            defaultSecurityLevel=authPriv,
        )

    def testNamespaceSecurityLevels(self):
        self.usm.addUser(
            self.user,
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
            privProtocol=self.privProtocol,
            privSecret=self.privSecret,
        )

        self.usm.addUser(
            self.user,
            namespace=self.namespace,
        )

        self.assertEqual(
            self.usm.getDefaultSecurityLevel(self.user),
            authPriv,
        )

        self.assertEqual(
            self.usm.getDefaultSecurityLevel(self.user, self.namespace),
            noAuthNoPriv,
        )

class UsmOutgoingTest(unittest.TestCase):
    def setUp(self):
        self.noAuthUser = "noAuthUser"
        self.noPrivUser = "noPrivUser"
        self.user = "authPrivUser"
        self.engineID = b"remoteEngineID"

        self.authProtocol = DummyAuthProtocol
        self.privProtocol = DummyPrivProtocol

        self.usm = UserBasedSecurityModule()
        self.usm.addUser(self.noAuthUser)
        self.usm.addUser(
            self.noPrivUser,
            authProtocol=self.authProtocol,
            secret=b"",
        )
        self.usm.addUser(
            self.user,
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=b"",
            default=True,
        )

        self.usm.registerRemoteEngine(self.engineID)

        self.noAuthNoPrivEncoding = bytes.fromhex(re.sub("\n", "", """
            30 7d
               02 01 03
               30 10
                  02 04 43 23 71 5b
                  02 02 05 dc
                  04 01 04
                  02 01 03
               04 2a
                  30 28
                     04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                     02 01 00
                     02 01 00
                     04 0c 61 75 74 68 50 72 69 76 55 73 65 72
                     04 00
                     04 00
               30 3a
                  04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                  04 0b 73 6f 6d 65 43 6f 6e 74 65 78 74
                  a0 1b
                     02 04 e2 a3 05 ef
                     02 01 00
                     02 01 00
                     30 0d
                        30 0b
                           06 07 2b 06 01 02 01 01 00
                           05 00
        """))

        self.authNoPrivEncoding = bytes.fromhex(re.sub("\n", "", """
            30 7f
               02 01 03
               30 10
                  02 04 43 23 71 5b
                  02 02 05 dc
                  04 01 05
                  02 01 03
               04 2c
                  30 2a
                     04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                     02 01 00
                     02 01 00
                     04 0c 61 75 74 68 50 72 69 76 55 73 65 72
                     04 02 81 00
                     04 00
               30 3a
                  04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                  04 0b 73 6f 6d 65 43 6f 6e 74 65 78 74
                  a0 1b
                     02 04 e2 a3 05 ef
                     02 01 00
                     02 01 00
                     30 0d
                        30 0b
                           06 07 2b 06 01 02 01 01 00
                           05 00
        """))

        self.authPrivEncoding = bytes.fromhex(re.sub("\n", "", """
            30 81 85
               02 01 03
               30 10
                  02 04 43 23 71 5b
                  02 02 05 dc
                  04 01 07
                  02 01 03
               04 30
                  30 2e
                     04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                     02 01 00
                     02 01 00
                     04 0c 61 75 74 68 50 72 69 76 55 73 65 72
                     04 02 88 00
                     04 04 73 61 6c 74
               04 3c
                  30 3a
                     04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                     04 0b 73 6f 6d 65 43 6f 6e 74 65 78 74
                     a0 1b
                        02 04 e2 a3 05 ef
                        02 01 00
                        02 01 00
                        30 0d
                           30 0b
                              06 07 2b 06 01 02 01 01 00
                              05 00
        """))

        self.message = SNMPv3Message(
            HeaderData(
                0x4323715b,
                1500,
                MessageFlags(reportable=True),
                self.usm.MODEL,
            ),
            ScopedPDU(
                GetRequestPDU("1.3.6.1.2.1.1.0", requestID=-0x1d5cfa11),
                self.engineID,
                b"someContext",
            ),
        )

    def tearDown(self):
        self.usm.unregisterRemoteEngine(self.engineID)

    def testOutgoingNoAuthNoPriv(self):
        wholeMsg = self.usm.prepareOutgoing(
            self.message,
            self.engineID,
            self.user.encode(),
        )

        self.assertEqual(wholeMsg, self.noAuthNoPrivEncoding)

    def testOutgoingAuthNoPriv(self):
        self.message.header.flags = MessageFlags(authNoPriv, reportable=True)
        wholeMsg = self.usm.prepareOutgoing(
            self.message,
            self.engineID,
            self.user.encode(),
        )

        self.assertEqual(wholeMsg, self.authNoPrivEncoding)

    def testOutgoingAuthPriv(self):
        self.message.header.flags = MessageFlags(authPriv, reportable=True)
        wholeMsg = self.usm.prepareOutgoing(
            self.message,
            self.engineID,
            self.user.encode(),
        )

        self.assertEqual(wholeMsg, self.authPrivEncoding)

    def testNoAuthUser(self):
        self.message.header.flags = MessageFlags(authNoPriv, reportable=True)
        self.assertRaises(
            InvalidSecurityLevel,
            self.usm.prepareOutgoing,
            self.message,
            self.engineID,
            self.noAuthUser.encode(),
        )

    def testNoPrivUser(self):
        self.message.header.flags = MessageFlags(authPriv, reportable=True)
        self.assertRaises(
            InvalidSecurityLevel,
            self.usm.prepareOutgoing,
            self.message,
            self.engineID,
            self.noPrivUser.encode(),
        )

class UsmSyncTest(unittest.TestCase):
    def setUp(self):
        self.authProtocol = DummyAuthProtocol
        self.privProtocol = DummyPrivProtocol
        self.engineID = b"remoteEngineID"
        self.user = "someUser"

        self.usm = UserBasedSecurityModule()
        self.usm.addUser(
            self.user,
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=b"",
        )

        self.discoveryTimestamp = 29516.0
        self.illegitimateTimestamp = self.discoveryTimestamp + 0.25
        self.misledTimestamp = self.illegitimateTimestamp + 0.25
        self.reportTimestamp = self.misledTimestamp + 0.25
        self.requestTimestamp = self.reportTimestamp + 0.25
        self.responseTimestamp = self.requestTimestamp + 0.25

        self.reportEncoding = bytes.fromhex(re.sub("\n", "", """
            30 6b
               02 01 03
               30 10
                  02 04 6a e4 ed dd
                  02 02 05 dc
                  04 01 00
                  02 01 03
               04 1f
                  30 1d
                     04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                     02 01 1d
                     02 02 03 c1
                     04 00
                     04 00
                     04 00
               30 33
                  04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                  04 00
                  a8 1f
                     02 04 c3 e5 47 40
                     02 01 00
                     02 01 00
                     30 11
                        30 0f
                           06 0a 2b 06 01 06 03 0f 01 01 04 00
                           02 01 01
        """))

        self.reportMessage = SNMPv3Message.decodeExact(self.reportEncoding)

        self.requestMessage = SNMPv3Message(
            HeaderData(
                0x7090fb77,
                1500,
                MessageFlags(authNoPriv, reportable=True),
                self.usm.MODEL,
            ),
            ScopedPDU(
                GetRequestPDU("1.3.6.1.2.1.1.0", requestID=0x26cf6e26),
                self.engineID,
            ),
            securityParameters = OctetString(
                bytes.fromhex(re.sub("\n", "", """
                    30 27
                       04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                       02 01 1d
                       02 02 03 c1
                       04 08 73 6f 6d 65 55 73 65 72
                       04 02 73 00
                       04 00
                """))
            ),
        )

        self.requestEncoding = self.requestMessage.encode()

        self.responseEncoding = bytes.fromhex(re.sub("\n", "", """
            30 81 96
               02 01 03
               30 10
                  02 04 70 90 fb 77
                  02 02 05 dc
                  04 01 03
                  02 01 03
               04 2d
                  30 2b
                     04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                     02 01 1d
                     02 02 03 c2
                     04 08 73 6f 6d 65 55 73 65 72
                     04 02 99 00
                     04 04 73 61 6c 74
               04 50
                  30 4e
                     04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                     04 00
                     a2 3a
                        02 04 26 cf 6e 26
                        02 01 00
                        02 01 00
                        30 2c
                           30 2a
                              06 07 2b 06 01 02 01 01 00
                              04 1f 54 68 69 73 20 73 74 72 69 6e 67
                                    20 64 65 73 63 72 69 62 65 73 20
                                    6d 79 20 73 79 73 74 65 6d
        """))

        self.responseMessage = SNMPv3Message.decodeExact(self.responseEncoding)

        self.responseScopedPDU = ScopedPDU(
            ResponsePDU(
                VarBind(
                    "1.3.6.1.2.1.1.0",
                    OctetString(b"This string describes my system"),
                ),
                requestID=0x26cf6e26,
            ),
            self.engineID,
        )

    def testBasicIncomingMessage(self):
        self.usm.processIncoming(
            self.reportMessage,
            timestamp=self.reportTimestamp,
        )

        self.assertEqual(self.reportMessage.securityEngineID, self.engineID)
        self.assertEqual(self.reportMessage.securityName, b"")

    def testTimeSync(self):
        self.usm.processIncoming(
            self.reportMessage,
            timestamp=self.reportTimestamp,
        )

        _ = self.usm.registerRemoteEngine(self.reportMessage.securityEngineID)

        requestEncoding = self.usm.prepareOutgoing(
            self.requestMessage,
            self.engineID,
            self.user.encode(),
            timestamp=self.requestTimestamp,
        )

        self.assertEqual(requestEncoding, self.requestEncoding)

    def testResponse(self):
        self.usm.processIncoming(
            self.reportMessage,
            timestamp=self.reportTimestamp,
        )

        _ = self.usm.registerRemoteEngine(self.reportMessage.securityEngineID)

        requestEncoding = self.usm.prepareOutgoing(
            self.requestMessage,
            self.engineID,
            self.user.encode(),
            timestamp=self.requestTimestamp,
        )

        self.usm.processIncoming(
            self.responseMessage,
            timestamp=self.responseTimestamp,
        )

        self.assertEqual(
            self.responseMessage.scopedPDU,
            self.responseScopedPDU,
        )

    def testLateResponse(self):
        self.usm.processIncoming(
            self.reportMessage,
            timestamp=self.reportTimestamp,
        )

        _ = self.usm.registerRemoteEngine(self.reportMessage.securityEngineID)

        requestEncoding = self.usm.prepareOutgoing(
            self.requestMessage,
            self.engineID,
            self.user.encode(),
            timestamp=self.requestTimestamp,
        )

        self.usm.processIncoming(
            self.responseMessage,
            timestamp=self.responseTimestamp,
        )

        self.assertRaises(
            IncomingMessageError,
            self.usm.processIncoming,
            self.responseMessage,
            timestamp=self.responseTimestamp+TimeKeeper.TIME_WINDOW_SIZE+1,
        )

class UsmIncomingTest(unittest.TestCase):
    def setUp(self):
        self.authProtocol = DummyAuthProtocol
        self.privProtocol = DummyPrivProtocol
        self.engineID = b"remoteEngineID"
        self.user = "someUser"

        self.usm = UserBasedSecurityModule()
        self.usm.addUser(
            self.user,
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=b"",
        )

        _ = self.usm.registerRemoteEngine(self.engineID)

        self.inauthentic = SNMPv3Message(
            HeaderData(
                0x7090fb77,
                1500,
                MessageFlags(authPriv, False),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ResponsePDU(
                    VarBind(
                        "1.3.6.1.2.1.1.0",
                        OctetString(b"This string describes my system"),
                    ),
                    requestID=0x26cf6e26,
                ),
                b'remoteEngineID',
            ),
            securityParameters=OctetString(bytes.fromhex(re.sub("\n", "", """
                30 2b
                   04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                   02 01 1d
                   02 02 03 c2
                   04 08 73 6f 6d 65 55 73 65 72
                   04 02 23 19
                   04 04 73 61 6c 74
            """))),
        )

    def testInvalidSignature(self):
        self.assertRaisesRegex(
            IncomingMessageError,
            "[Ss]ignature",
            self.usm.processIncoming,
            self.inauthentic,
        )

if __name__ == "__main__":
    unittest.main()
