import unittest

from Masterpassword import MasterPassword
from Passwordentry import PasswordEntry
from Settings import UserSettings
from Hashing import hashPassword
from IP import IPDetails
from Encryption import encrypt, decrypt


class TestDataProcessing(unittest.TestCase):

    #   Valid SHA-512 encrypted value is 64-bytes or 128 characters long
    def test_encryptionProtocol(self):
        testString = "TestString123"
        testBytes = testString.encode('utf-8')
        self.assertEqual(len(hashPassword(testBytes)), 128)

    #   Valid encrypted output type is in bytes
    def test_encryptionOutputType(self):
        testMessage = "Unencrypted test message"
        testBytesMessage = testMessage.encode('utf-8')
        testToken = "Q9jeh5C4IBuAGa78o0kXVChgBxE_qV3FiO7HJyDaWPA="
        testBytesToken = testToken.encode('utf-8')
        self.assertIsInstance(encrypt(testBytesMessage, testBytesToken), bytes)

    #   Valid decrypted output type is in bytes
    def test_decryptionOutputType(self):
        testMessage = "gAAAAABiTGS3XYwhs_Jgu-2jii97Hzpyh1vQWP0Q95K8xfgRegg8DqYtNdMnSxnYPZOem0d_DM5RHTJkDki-VRNXMj5WnGBFLg=="
        testBytesMessage = testMessage.encode('utf-8')
        testToken = "Q9jeh5C4IBuAGa78o0kXVChgBxE_qV3FiO7HJyDaWPA="
        testBytesToken = testToken.encode('utf-8')
        self.assertIsInstance(decrypt(testBytesMessage, testBytesToken), bytes)

    #   Valid master password has no remediation list items
    def test_masterPasswordObject(self):
        testMasterPassword = "ThisisaTestMP99101!"
        testMasterPasswordObject = MasterPassword(testMasterPassword, [])
        self.assertEqual(len(testMasterPasswordObject.WASP), 0)

    #   Valid password entry with expected values and encryptionKey has encrypted fields
    def test_passwordEntryObject(self):
        testService = "Youtube.com"
        testUsername = "davemarais@gmail.com"
        testPassword = "WihsbEIl!"
        testdate = "2022-05-10 20:06:12.319494"
        testEncryptionKey = b'Q9jeh5C4IBuAGa78o0kXVChgBxE_qV3FiO7HJyDaWPA='
        testPasswordEntryObject = PasswordEntry(testService, testUsername, testPassword, testdate, testEncryptionKey)
        self.assertNotEqual(testPasswordEntryObject.encservice, "")
        self.assertNotEqual(testPasswordEntryObject.encusername, "")
        self.assertNotEqual(testPasswordEntryObject.encpassword, "")
        self.assertNotEqual(testPasswordEntryObject.encdate, "")


class TestMasterPassword(unittest.TestCase):
    def test_masterPasswordWASP(self):
        testValue = "ThisisaTestMP99101!"
        testWASP = []
        testMasterPasswordObject = MasterPassword(testValue, testWASP)
        self.assertIsInstance(testMasterPasswordObject.WASP, list)

    def test_masterShortPasswordValue(self):
        shortValue = "ThMP12!"
        testMasterPasswordObject = MasterPassword(shortValue, [])
        self.assertEqual(testMasterPasswordObject.WASP[0], "· Password should not be shorter than 8 characters.")

    def test_masterLongPasswordValue(self):
        longValue = "ThMP12!hasgdhskagdhasdgasvdhgasdasidyasdgasiydgsadisaygdaysugdasydvyasgdaysgdviaus"
        testMasterPasswordObject = MasterPassword(longValue, [])
        self.assertEqual(testMasterPasswordObject.WASP[0], "· Password should not be longer than 64 characters.")

    def test_masterUpperCasePasswordValue(self):
        noLowerCaseValue = "THMP1234!"
        testMasterPasswordObject = MasterPassword(noLowerCaseValue, [])
        self.assertEqual(testMasterPasswordObject.WASP[0],
                         "· Password should contain at least one lower case character.")

    def test_masterLowerCasePasswordValue(self):
        noUpperCaseValue = "hjdsa1234!"
        testMasterPasswordObject = MasterPassword(noUpperCaseValue, [])
        self.assertEqual(testMasterPasswordObject.WASP[0],
                         "· Password should contain at least one upper case character.")

    def test_masterNoDigitPasswordValue(self):
        noDigitsValue = "hjdsaUHDSA!"
        testMasterPasswordObject = MasterPassword(noDigitsValue, [])
        self.assertEqual(testMasterPasswordObject.WASP[0], "· Password should contain at least one digit.")

    def test_masterNoSpecialPasswordValue(self):
        noSpecialCharacterValue = "hjdsaUHDSA123"
        testMasterPasswordObject = MasterPassword(noSpecialCharacterValue, [])
        self.assertEqual(testMasterPasswordObject.WASP[0], "· Password should contain at least one special character.")


class TestUserSettings(unittest.TestCase):
    def test_settingsFieldType(self):
        testTimeframe = 1
        testInactivity = 5
        testUserSettingsObject = UserSettings(testTimeframe, testInactivity)
        self.assertIsInstance(testUserSettingsObject.timeframe, int)
        self.assertIsInstance(testUserSettingsObject.inactivity, int)

    def test_settingsFieldValues(self):
        testTimeframe = 10
        testInactivity = 50
        testUserSettingsObject = UserSettings(testTimeframe, testInactivity)
        self.assertEqual(testUserSettingsObject.timeframe, 10)
        self.assertEqual(testUserSettingsObject.inactivity, 50)


class TestOnlineSystem(unittest.TestCase):
    def test_SystemInternetConnection(self):
        testIPObj = IPDetails()
        self.assertNotEqual(testIPObj.IP, "Unknown")
        self.assertNotEqual(testIPObj.org, "Unknown")
        self.assertNotEqual(testIPObj.city, "Unknown")
        self.assertNotEqual(testIPObj.country, "Unknown")
        self.assertNotEqual(testIPObj.region, "Unknown")

    def test_IP(self):
        testIPObj = IPDetails()
        self.assertIn(".", testIPObj.IP)


class TestOfflineSystem(unittest.TestCase):
    def test_OfflineSystemInternetConnection(self):
        testIPObj = IPDetails()
        self.assertEqual(testIPObj.IP, "Unknown")
        self.assertEqual(testIPObj.org, "Unknown")
        self.assertEqual(testIPObj.city, "Unknown")
        self.assertEqual(testIPObj.country, "Unknown")
        self.assertEqual(testIPObj.region, "Unknown")


class TestLocalSystem(unittest.TestCase):
    def test_LocalSystemDetails(self):
        testIPObj = IPDetails()
        self.assertNotEqual(testIPObj.localIP, "Unknown")
        self.assertNotEqual(testIPObj.hostname, "Unknown")


class TestEncryption(unittest.TestCase):
    def test_EncryptionMechanism(self):
        testMessage = "Unencrypted test message"
        testBytesMessage = testMessage.encode('utf-8')
        testToken = "Q9jeh5C4IBuAGa78o0kXVChgBxE_qV3FiO7HJyDaWPA="
        testBytesToken = testToken.encode('utf-8')
        encryptedValue = encrypt(testBytesMessage, testBytesToken)
        decryptedValue = decrypt(encryptedValue, testBytesToken).decode('utf-8')
        self.assertEqual(decryptedValue, testMessage)

    def test_DecryptionMechanism(self):
        testMessage = "gAAAAABigTigTtpJkqSxrBzI_OIPpNajk_DyHQ6mipJHVHiv-gJ17z3njB-ggiB0VzDz9Wcl4au9mNslT2Qe5kWIlxZaz1QVxsa2RRa10ts9sDCYyLF2wCQ="
        testBytesMessage = testMessage.encode('utf-8')
        testToken = "Q9jeh5C4IBuAGa78o0kXVChgBxE_qV3FiO7HJyDaWPA="
        testBytesToken = testToken.encode('utf-8')
        decryptedValue = decrypt(testBytesMessage, testBytesToken)
        encryptedValue = encrypt(decryptedValue, testBytesToken)
        decryptedValue = decrypt(encryptedValue, testBytesToken).decode('utf-8')
        self.assertEqual(decryptedValue, "Unencrypted test message")


class TestHashing(unittest.TestCase):
    def test_HashingMechanism(self):
        testMessage = "Unhashed test message"
        encodedMessage = testMessage.encode('utf-8')
        hashedMessage = hashPassword(encodedMessage)
        self.assertEqual(hashedMessage, "8c15e014010818050415275204aa0779628bfe6ad5d54397917d04651aab445a132e548cb86b87c3fe4258edfcc504d2f74c37071ffe56a409be527faacb8cc8")


if __name__ == '__main__':
    unittest.main()
