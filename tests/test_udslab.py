import unittest
from udslab import UdsSession

class UdsTests(unittest.TestCase):
    def test_session_and_read_data(self):
        ecu=UdsSession(); self.assertEqual(ecu.handle(bytes.fromhex("10 03")),bytes.fromhex("50 03 00 32")); self.assertEqual(ecu.handle(bytes.fromhex("22 F1 90")),bytes.fromhex("62 F1 90 4F 50 45 4E 2D 53 44 56"))
    def test_security_access(self):
        ecu=UdsSession(); seed=ecu.handle(bytes.fromhex("27 01")); self.assertEqual(seed[:2],bytes.fromhex("67 01")); self.assertEqual(ecu.handle(bytes([0x27,2])+b"\0\0\0\0"),bytes.fromhex("7F 27 35")); self.assertFalse(ecu.unlocked)
    def test_tester_present_rejects_malformed_requests(self):
        ecu=UdsSession()
        self.assertEqual(ecu.handle(bytes.fromhex("3E")),bytes.fromhex("7F 3E 13"))
        self.assertEqual(ecu.handle(bytes.fromhex("3E 00 00")),bytes.fromhex("7F 3E 13"))
        self.assertEqual(ecu.handle(bytes.fromhex("3E 01")),bytes.fromhex("7F 3E 12"))
        self.assertEqual(ecu.handle(bytes.fromhex("3E 00")),bytes.fromhex("7E 00"))
        self.assertEqual(ecu.handle(bytes.fromhex("3E 80")),b"")
    def test_read_dtc_by_status_mask(self):
        ecu=UdsSession()
        self.assertEqual(
            ecu.handle(bytes.fromhex("19 02 FF")),
            bytes.fromhex("59 02 FF C1 23 45 01 B1 00 01 02"),
        )
        self.assertEqual(ecu.handle(bytes.fromhex("19 02 01")), bytes.fromhex("59 02 FF C1 23 45 01"))
        self.assertEqual(ecu.handle(bytes.fromhex("19")), bytes.fromhex("7F 19 13"))
        self.assertEqual(ecu.handle(bytes.fromhex("19 01 FF")), bytes.fromhex("7F 19 12"))
    def test_unknown_service(self): self.assertEqual(UdsSession().handle(bytes.fromhex("99")),bytes.fromhex("7F 99 11"))
if __name__=="__main__": unittest.main()
