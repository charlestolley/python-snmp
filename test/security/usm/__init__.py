__all__ = [
    "DiscoveredEngineTest", "TimeKeeperTest",
    "UserTableTest", "UsmSecurityParametersTest",
    "UsmLocalizeTest", "UsmUserConfigTest",
    "UsmOutgoingTest", "UsmSyncTest", "UsmIncomingTest",
]

import random
import re
import unittest

from snmp.exception import *
from snmp.message.v3 import *
from snmp.message.v3 import pduTypes
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.usm import *
from snmp.security.usm import (
    Credentials, DiscoveredEngine, LocalizedCredentials,
    PrivProtocol, TimeKeeper, UserTable, UsmSecurityParameters,
)

from snmp.security.usm.auth import *
from snmp.smi import *
from snmp.utils import *

class DummyAuthProtocol(AuthProtocol):
    def __init__(self, key):
        pass

    @classmethod
    def computeKey(cls, secret):
        return secret

    @classmethod
    def localizeKey(cls, key, engineID):
        return bytes(0)

    @property
    def msgAuthenticationParameters(self):
        return bytes(2)

    def sign(self, data):
        return len(data).to_bytes(2, "little", signed=False)

class DummyPrivProtocol(PrivProtocol):
    def __init__(self, key):
        self.key = key

    def decrypt(self, data, engineBoots, engineTime, salt):
        return data

    def encrypt(self, data, engineBoots, engineTime):
        return data, b"salt"

class DiscoveredEngineTest(unittest.TestCase):
    def setUp(self):
        self.namespace = "namespace"
        self.discoveredEngine = DiscoveredEngine()
        self.discoveredEngine.assign(self.namespace)

    def testUninitialized(self):
        discoveredEngine = DiscoveredEngine()
        assigned, initialized = discoveredEngine.assign(self.namespace)
        self.assertTrue(assigned)
        self.assertFalse(initialized)

    def testMultipleAssignment(self):
        assigned, _ = self.discoveredEngine.assign("other")
        self.assertFalse(assigned)

    def testReentrancy(self):
        assigned, initialized = self.discoveredEngine.assign(self.namespace)
        self.assertTrue(assigned)
        self.assertTrue(initialized)

    def testReassignment(self):
        self.discoveredEngine.release(self.namespace)
        assigned, initialized = self.discoveredEngine.assign(self.namespace)
        self.assertTrue(assigned)
        self.assertTrue(initialized)

    def testRelease(self):
        _, _ = self.discoveredEngine.assign(self.namespace)
        first   = self.discoveredEngine.release(self.namespace)
        second  = self.discoveredEngine.release(self.namespace)

        self.assertFalse(first)
        self.assertTrue(second)

    def testReclaim(self):
        self.discoveredEngine.release(self.namespace)
        assigned, initialized = self.discoveredEngine.assign("other")
        self.assertTrue(assigned)
        self.assertFalse(initialized)

class TimeKeeperTest(unittest.TestCase):
    def setUp(self):
        self.engineID = b"someEngineID"
        self.engineBoots = 4887
        self.engineTime = 1942
        self.timestamp = 8264.0

        self.timekeeper = TimeKeeper()
        _ = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime,
            timestamp=self.timestamp,
        )

    def testUnknownEngine(self):
        engineBoots, engineTime = self.timekeeper.getEngineTime(b"unknown")
        self.assertEqual(engineBoots, 0)
        self.assertEqual(engineTime, 0)

    def testGetEngineTime(self):
        delta = 23.7
        deltaInt = int(delta)

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta,
        )

        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + deltaInt)

    # When msgEngineTime is less than expected (meaning the message was delayed
    # in transit), it should not affect the local notion of snmpEngineTime
    def testSlowMessage(self):
        delta = 5

        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime + delta,
            timestamp = self.timestamp + delta + 1,
        )

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta + 2
        )

        self.assertTrue(valid)
        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + delta + 2)

    # When msgEngineTime is greater than expected (meaning the message was
    # delivered more quickly than any past message), it should cause the local
    # notion of snmpEngineTime to be updated.
    def testFastMessage(self):
        delta = 5

        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime + delta,
            timestamp = self.timestamp + delta - 1,
        )

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta + 2
        )

        self.assertTrue(valid)
        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + delta + 3)

    def testAssumeLegitimacy(self):
        delta = 5

        self.timekeeper.update(
            self.engineID,
            self.engineBoots + 9,
            3906,
            timestamp = self.timestamp,
        )

        self.timekeeper.update(
            self.engineID,
            self.engineBoots,
            self.engineTime + delta,
            timestamp = self.timestamp + delta,
        )

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta,
        )

        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + delta)

    def testCorrectIllegitimateTime(self):
        delta = 5

        self.timekeeper.update(
            self.engineID,
            self.engineBoots + 9,
            3906,
            timestamp = self.timestamp,
        )

        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime + delta,
            timestamp = self.timestamp + delta,
        )

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = self.timestamp + delta,
        )

        self.assertTrue(valid)
        self.assertEqual(engineBoots, self.engineBoots)
        self.assertEqual(engineTime, self.engineTime + delta)

    def testReboot(self):
        newEngineBoots = self.engineBoots + 1
        newEngineTime = 3
        timestamp = self.timestamp + newEngineTime + 2
        delta = 5

        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            newEngineBoots,
            newEngineTime,
            timestamp=timestamp,
        )

        invalid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime + 1,
            timestamp = self.timestamp + 1,
        )

        engineBoots, engineTime = self.timekeeper.getEngineTime(
            self.engineID,
            timestamp = timestamp + delta
        )

        self.assertTrue(valid)
        self.assertFalse(invalid)
        self.assertEqual(engineBoots, newEngineBoots)
        self.assertEqual(engineTime, newEngineTime + delta)

    def testMaxBoots(self):
        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            0x7fffffff,
            0,
            timestamp=self.timestamp + 1,
        )

        self.assertFalse(valid)

    def testExpired(self):
        valid = self.timekeeper.updateAndVerify(
            self.engineID,
            self.engineBoots,
            self.engineTime,
            self.timestamp + 151,
        )

        self.assertFalse(valid)

class UserTableTest(unittest.TestCase):
    def setUp(self):
        self.credentials = LocalizedCredentials()
        self.engineID = b"someEngineID"
        self.user = b"someUser"
        self.users = UserTable()

    def testUnknownEngine(self):
        self.assertRaises(
            InvalidEngineID,
            self.users.getCredentials,
            self.engineID,
            self.user,
        )

    def testUnknownUser(self):
        self.users.assignCredentials(
            self.engineID,
            self.user,
            self.credentials,
        )

        self.assertRaises(
            InvalidUserName,
            self.users.getCredentials,
            self.engineID,
            b"invalidUser",
        )

    def testGetCredentials(self):
        self.users.assignCredentials(
            self.engineID,
            self.user,
            self.credentials,
        )

        self.assertIs(
            self.users.getCredentials(self.engineID, self.user),
            self.credentials,
        )

class UsmSecurityParametersTest(unittest.TestCase):
    def setUp(self):
        self.message = bytes.fromhex(re.sub("\n", "", """
            30 81 97
               02 01 03
               30 10
                  02 04 28 6e 48 41
                  02 02 05 dc
                  04 01 03
                  02 01 03
               04 2e
                  30 2c
                     04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                     02 02 05 d4
                     02 02 14 d0
                     04 08 73 6f 6d 65 55 73 65 72
                     04 02 9a 00
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

        self.encoding = subbytes(self.message, 26, 72)

        self.securityParameters = UsmSecurityParameters(
            b"remoteEngineID",
            1492,
            5328,
            b"someUser",
            b"\x9a\x00",
            b"salt",
        )

    def testDecode(self):
        self.assertEqual(
            UsmSecurityParameters.decode(self.encoding),
            self.securityParameters,
        )

    def testEncode(self):
        self.assertEqual(
            self.securityParameters.encode(),
            self.encoding,
        )

    def testRepr(self):
        self.assertEqual(
            eval(repr(self.securityParameters)),
            self.securityParameters,
        )

    def testSignatureIndex(self):
        securityParameters = UsmSecurityParameters.decode(self.encoding)
        self.assertIs(securityParameters.wholeMsg, self.message)
        self.assertEqual(securityParameters.signatureIndex, 64)

    def testMissingSignatureIndex(self):
        self.assertIsNone(self.securityParameters.wholeMsg)
        self.assertIsNone(self.securityParameters.signatureIndex)

    def testFindSignature(self):
        signature = UsmSecurityParameters.findSignature(self.encoding)
        self.assertEqual(signature, subbytes(self.encoding, 38, 40))

class UsmLocalizeTest(unittest.TestCase):
    def setUp(self):
        self.secret = b"maplesyrup"
        self.engineID = bytes.fromhex("000000000000000000000002")
        self.privProtocol = DummyPrivProtocol
        self.usm = UserBasedSecurityModule()

    def testUselessLocalization(self):
        credentials = self.usm.localizeCredentials(self.engineID)
        self.assertIsNone(credentials.auth)
        self.assertIsNone(credentials.priv)

    def testAuthLocalization(self):
        authProtocol = HmacMd5
        key = bytes.fromhex("526f5eed9fcce26f8964c2930787d82b")

        credentials = self.usm.localizeCredentials(
            self.engineID,
            Credentials(
                authProtocol,
                self.secret,
            ),
        )

        self.assertIsInstance(credentials.auth, authProtocol)

        # NOTE: relies on non-public attribute
        self.assertEqual(credentials.auth.key, authProtocol(key).key)
        self.assertIsNone(credentials.priv)

    def testPrivLocalization(self):
        credentials = self.usm.localizeCredentials(
            self.engineID,
            Credentials(
                privProtocol=self.privProtocol,
                privSecret=b"doesn't matter",
            ),
        )

        self.assertIsNone(credentials.auth)
        self.assertIsNone(credentials.priv)

    def testFullLocalization(self):
        key = bytes.fromhex("6695febc9288e36282235fc7151f128497b38f3f")

        credentials = self.usm.localizeCredentials(
            self.engineID,
            Credentials(
                authProtocol=HmacSha,
                privProtocol=self.privProtocol,
                secret=self.secret,
            )
        )

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

    def testDuplicateUser(self):
        self.usm.addUser(self.user)
        self.assertRaises(ValueError, self.usm.addUser, self.user)

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

    def testSingleSecret(self):
        secret = b"sharedSecret"
        key = self.authProtocol.computeKey(secret)
        self.usm.addUser(
            self.user,
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=secret,
        )

        # NOTE: this block relies on non-public behavior
        space = self.usm.getNameSpace()
        credentials = space[self.user].credentials
        self.assertEqual(credentials.authKey, key)
        self.assertEqual(credentials.privKey, key)

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
        self.usm.addUser(self.noPrivUser, authProtocol=self.authProtocol)
        self.usm.addUser(
            self.user,
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
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
        self.message.header.flags.authFlag = True
        wholeMsg = self.usm.prepareOutgoing(
            self.message,
            self.engineID,
            self.user.encode(),
        )

        self.assertEqual(wholeMsg, self.authNoPrivEncoding)

    def testOutgoingAuthPriv(self):
        self.message.header.flags.authFlag = True
        self.message.header.flags.privFlag = True
        wholeMsg = self.usm.prepareOutgoing(
            self.message,
            self.engineID,
            self.user.encode(),
        )

        self.assertEqual(wholeMsg, self.authPrivEncoding)

    def testNoAuthUser(self):
        self.message.header.flags.authFlag = True
        self.assertRaises(
            InvalidSecurityLevel,
            self.usm.prepareOutgoing,
            self.message,
            self.engineID,
            self.noAuthUser.encode(),
        )

    def testNoPrivUser(self):
        self.message.header.flags.authFlag = True
        self.message.header.flags.privFlag = True
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

        self.reportMessage = SNMPv3Message.decode(self.reportEncoding)

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

        self.responseMessage = SNMPv3Message.decode(self.responseEncoding)

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
        )

        _ = self.usm.registerRemoteEngine(self.engineID)

        self.inauthentic = SNMPv3Message(
            HeaderData(
                0x7090fb77,
                1500,
                MessageFlags(authNoPriv, False),
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
                30 27
                   04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                   02 01 1d
                   02 02 03 c2
                   04 08 73 6f 6d 65 55 73 65 72
                   04 02 23 19
                   04 00
            """))),
        )

    def testInvalidSignature(self):
        self.assertRaisesRegex(
            IncomingMessageError,
            "[Ss]ignature",
            self.usm.processIncoming,
            self.inauthentic,
        )

if __name__ == '__main__':
    unittest.main()
