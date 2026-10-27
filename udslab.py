#!/usr/bin/env python3
import argparse
import hashlib

class UdsSession:
    def __init__(self):
        self.session=1; self.seed=None; self.unlocked=False
        self.data={0xF190:b"OPEN-SDV",0xF187:b"UDS-LAB-1.0"}
        self.dtcs=[(0xC12345,1),(0xB10001,2)]
    def _negative(self,sid,nrc): return bytes([0x7F,sid,nrc])
    def handle(self,request):
        if not request: return self._negative(0,0x13)
        sid=request[0]
        if sid==0x10:
            if len(request)!=2: return self._negative(sid,0x13)
            # The high bit of the sub-function is the standard
            # suppress-positive-response bit.  It must not be treated as
            # part of the session type (for example, 0x83 is a valid
            # suppressed ProgrammingSession request).
            subfunction=request[1]
            suppress_positive=bool(subfunction & 0x80)
            session_type=subfunction & 0x7F
            if session_type not in (1,2,3): return self._negative(sid,0x12)
            self.session=session_type
            # A security seed is scoped to the active diagnostic session.  A
            # session transition must invalidate both a pending seed and any
            # unlock state so a key captured in one session cannot be replayed
            # after switching to another session.
            self.seed=None
            self.unlocked=False
            # Positive response includes both P2ServerMax (milliseconds)
            # and P2*ServerMax (10-ms units).  Omitting P2* truncates the
            # ISO 14229 response and leaves clients without a valid timeout.
            if suppress_positive:
                return b""
            return bytes([0x50, session_type, 0x00, 0x32, 0x01, 0xF4])
        if sid==0x3E:
            # TesterPresent has exactly one subfunction byte.  Only the
            # regular request (0x00) and the suppress-positive-response
            # variant (0x80) are defined; accepting arbitrary values would
            # make malformed diagnostics look successful.
            if len(request) != 2:
                return self._negative(sid,0x13)
            if request[1] not in (0x00,0x80):
                return self._negative(sid,0x12)
            if request[1] == 0x80:
                # UDS specifies no response when the suppression bit is set.
                return b""
            return bytes([0x7E,0x00])
        if sid==0x22:
            if len(request)!=3: return self._negative(sid,0x13)
            did=int.from_bytes(request[1:3],"big")
            if did not in self.data: return self._negative(sid,0x31)
            return bytes([0x62])+request[1:3]+self.data[did]
        if sid==0x27:
            if len(request) < 2:
                return self._negative(sid,0x13)
            # The high bit is the UDS suppress-positive-response flag.  It
            # is metadata, not part of the security-access level, so 0x81
            # and 0x82 must behave like 0x01 and 0x02 respectively while
            # suppressing only a successful response.
            subfunction = request[1]
            suppress_positive = bool(subfunction & 0x80)
            level = subfunction & 0x7F
            if level not in (1,2): return self._negative(sid,0x12)
            if level==1:
                if len(request)!=2: return self._negative(sid,0x13)
                self.seed=hashlib.sha256(b"uds-lab-seed").digest()[:4]; self.unlocked=False
                if suppress_positive:
                    return b""
                return bytes([0x67,1])+self.seed
            if self.seed is None or len(request)!=6: return bytes([0x7F,0x27,0x35])
            expected=hashlib.sha256(self.seed+b"demo-key").digest()[:4]
            if request[2:]!=expected: return bytes([0x7F,0x27,0x35])
            self.unlocked=True
            if suppress_positive:
                return b""
            return bytes([0x67,2])
        if sid==0x19:
            # ReportDTCByStatusMask (subfunction 0x02) has a three-byte
            # request: service, subfunction, and status mask.  The third
            # byte of the positive response is the status *availability*
            # mask, not the number of DTCs.  The previous implementation
            # returned a positive response for truncated or unsupported
            # requests and put the DTC count in that protocol field.
            if len(request) != 3:
                return self._negative(sid,0x13)
            if request[1] != 0x02:
                return self._negative(sid,0x12)
            status_mask=request[2]
            payload=bytearray([0x59,0x02,0xFF])
            for code,status in self.dtcs:
                if status & status_mask:
                    payload.extend(code.to_bytes(3,"big")); payload.append(status)
            return bytes(payload)
        return self._negative(sid,0x11)

def parse_hex(parts):
    try: return bytes(int(part,16) for part in parts)
    except ValueError as exc: raise SystemExit(f"invalid hex byte: {exc}")

def main(argv=None):
    parser=argparse.ArgumentParser(description="Run a deterministic UDS request"); parser.add_argument("bytes",nargs="+"); args=parser.parse_args(argv)
    response=UdsSession().handle(parse_hex(args.bytes)); print(" ".join(f"{byte:02x}" for byte in response)); return 0

if __name__=="__main__": raise SystemExit(main())
