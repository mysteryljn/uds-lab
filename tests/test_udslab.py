import unittest
from udslab import UdsSession

class UdsTests(unittest.TestCase):
    def test_session_and_read_data(self):
        ecu=UdsSession(); self.assertEqual(ecu.handle(bytes.fromhex("10 03")),bytes.fromhex("50 03 00 32")); self.assertEqual(ecu.handle(bytes.fromhex("22 F1 90")),bytes.fromhex("62 F1 90 4F 50 45 4E 2D 53 44 56"))
    def test_security_access(self):
        ecu=UdsSession(); seed=ecu.handle(bytes.fromhex("27 01")); self.assertEqual(seed[:2],bytes.fromhex("67 01")); self.assertEqual(ecu.handle(bytes([0x27,2])+b"\0\0\0\0"),bytes.fromhex("7F 27 35")); self.assertFalse(ecu.unlocked)
    def test_unknown_service(self): self.assertEqual(UdsSession().handle(bytes.fromhex("99")),bytes.fromhex("7F 99 11"))
if __name__=="__main__": unittest.main()
