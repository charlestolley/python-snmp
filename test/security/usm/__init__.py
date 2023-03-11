__all__ = [
    "DiscoveredEngineTest", "TimeKeeperTest", "UserTableTest",
    "UsmLocalizeTest", "UsmUserConfigTest", "UsmOutgoingTest",
]

import re
import unittest

from snmp.message.v3 import *
from snmp.pdu import *
from snmp.security.levels import *
from snmp.security.usm import *
from snmp.security.usm import (
    Credentials, DiscoveredEngine, PrivProtocol, TimeKeeper, UserTable,
)

from snmp.security.usm.auth import *
from snmp.types import *

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
        self.credentials = Credentials()
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

class UsmLocalizeTest(unittest.TestCase):
    class privProtocol(PrivProtocol):
        def __init__(self, key):
            self.key = key

        def decrypt(self, data, engineBoots, engineTime, salt):
            return data

        def encrypt(self, data, engineBoots, engineTime):
            return data, bytes(0)

    def setUp(self):
        self.secret = b"maplesyrup"
        self.engineID = bytes.fromhex("000000000000000000000002")
        self.usm = UserBasedSecurityModule()

    def testUselessLocalization(self):
        credentials = self.usm.localize(self.engineID)
        self.assertIsNone(credentials.auth)
        self.assertIsNone(credentials.priv)

    def testAuthLocalization(self):
        authProtocol = HmacMd5
        key = bytes.fromhex("526f5eed9fcce26f8964c2930787d82b")

        credentials = self.usm.localize(
            self.engineID,
            authProtocol,
            self.secret,
        )

        self.assertIsInstance(credentials.auth, authProtocol)

        # NOTE: relies on non-public attribute
        self.assertEqual(credentials.auth.key, authProtocol(key).key)
        self.assertIsNone(credentials.priv)

    def testPrivLocalization(self):
        credentials = self.usm.localize(
            self.engineID,
            privProtocol=self.privProtocol,
            privSecret=b"doesn't matter",
        )

        self.assertIsNone(credentials.auth)
        self.assertIsNone(credentials.priv)

    def testFullLocalization(self):
        authProtocol = HmacSha
        key = bytes.fromhex("6695febc9288e36282235fc7151f128497b38f3f")

        credentials = self.usm.localize(
            self.engineID,
            authProtocol,
            self.secret,
            self.privProtocol,
            self.secret,
        )

        self.assertIsNotNone(credentials.auth)
        self.assertIsInstance(credentials.priv, self.privProtocol)
        self.assertEqual(credentials.priv.key, key)

class UsmUserConfigTest(unittest.TestCase):
    class privProtocol(PrivProtocol):
        def __init__(self, key):
            self.key = key

        def decrypt(self, data, engineBoots, engineTime, salt):
            return data

        def encrypt(self, data, engineBoots, engineTime):
            return data, bytes(0)

    def setUp(self):
        self.user = "someUser"
        self.namespace = "someNamespace"
        self.authProtocol = HmacSha512
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
        self.usm.addUser(
            self.user,
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=secret,
        )

        # NOTE: this block relies on non-public behavior
        space = self.usm.getNameSpace()
        credentials = space[self.user].credentials
        self.assertEqual(credentials["authSecret"], secret)
        self.assertEqual(credentials["privSecret"], secret)

class UsmOutgoingTest(unittest.TestCase):
    class authProtocol(AuthProtocol):
        def __init__(self, key):
            pass

        @classmethod
        def localize(cls, secret, engineID):
            return bytes(0)

        @property
        def msgAuthenticationParameters(self):
            return bytes(2)

        def sign(self, data):
            return len(data).to_bytes(2, "little", signed=False)

    class privProtocol(PrivProtocol):
        def __init__(self, key):
            pass

        def decrypt(self, data, engineBoots, engineTime, salt):
            return data

        def encrypt(self, data, engineBoots, engineTime):
            return data, b"salt"

    def setUp(self):
        self.noAuthUser = "noAuthUser"
        self.noPrivUser = "noPrivUser"
        self.user = "authPrivUser"
        self.engineID = b"remoteEngineID"

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
            OctetString(),
            ScopedPDU(
                GetRequestPDU("1.3.6.1.2.1.1.0", requestID=-0x1d5cfa11),
                self.engineID,
                b"someContext",
            ),
        )

    def tearDown(self):
        self.usm.unregisterRemoteEngine(self.engineID)

    def testOutgoingNoAuthNoPriv(self):
        msgVersion = Integer(self.message.VERSION).encode()
        wholeMsg = self.usm.prepareOutgoing(
            msgVersion + self.message.header.encode(),
            self.message.scopedPDU.encode(),
            self.engineID,
            self.user.encode(),
            noAuthNoPriv,
        )

        self.assertEqual(wholeMsg, self.noAuthNoPrivEncoding)

    def testOutgoingAuthNoPriv(self):
        self.message.header.flags.authFlag = True
        msgVersion = Integer(self.message.VERSION).encode()
        wholeMsg = self.usm.prepareOutgoing(
            msgVersion + self.message.header.encode(),
            self.message.scopedPDU.encode(),
            self.engineID,
            self.user.encode(),
            authNoPriv,
        )

        self.assertEqual(wholeMsg, self.authNoPrivEncoding)

    def testOutgoingAuthPriv(self):
        self.message.header.flags.authFlag = True
        self.message.header.flags.privFlag = True
        msgVersion = Integer(self.message.VERSION).encode()
        wholeMsg = self.usm.prepareOutgoing(
            msgVersion + self.message.header.encode(),
            self.message.scopedPDU.encode(),
            self.engineID,
            self.user.encode(),
            authPriv,
        )

        self.assertEqual(wholeMsg, self.authPrivEncoding)

    def testNoAuthUser(self):
        self.assertRaises(
            InvalidSecurityLevel,
            self.usm.prepareOutgoing,
            b"",
            b"",
            self.engineID,
            self.noAuthUser.encode(),
            authNoPriv,
        )

    def testNoPrivUser(self):
        self.assertRaises(
            InvalidSecurityLevel,
            self.usm.prepareOutgoing,
            b"",
            b"",
            self.engineID,
            self.noPrivUser.encode(),
            authPriv,
        )

if __name__ == '__main__':
    unittest.main()
