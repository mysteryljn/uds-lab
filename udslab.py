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
            if len(request)!=2 or request[1] not in (1,2,3): return self._negative(sid,0x12)
            self.session=request[1]; return bytes([0x50,request[1],0,0x32])
        if sid==0x3E: return bytes([0x7E,request[1] if len(request)>1 else 0])
        if sid==0x22:
            if len(request)!=3: return self._negative(sid,0x13)
            did=int.from_bytes(request[1:3],"big")
            if did not in self.data: return self._negative(sid,0x31)
            return bytes([0x62])+request[1:3]+self.data[did]
        if sid==0x27:
            if len(request)<2 or request[1] not in (1,2): return self._negative(sid,0x12)
            if request[1]==1:
                if len(request)!=2: return self._negative(sid,0x13)
                self.seed=hashlib.sha256(b"uds-lab-seed").digest()[:4]; self.unlocked=False; return bytes([0x67,1])+self.seed
            if self.seed is None or len(request)!=6: return bytes([0x7F,0x27,0x35])
            expected=hashlib.sha256(self.seed+b"demo-key").digest()[:4]
            if request[2:]!=expected: return bytes([0x7F,0x27,0x35])
            self.unlocked=True; return bytes([0x67,2])
        if sid==0x19:
            payload=bytearray([0x59,2,len(self.dtcs)])
            for code,status in self.dtcs: payload.extend(code.to_bytes(3,"big")); payload.append(status)
            return bytes(payload)
        return self._negative(sid,0x11)

def parse_hex(parts):
    try: return bytes(int(part,16) for part in parts)
    except ValueError as exc: raise SystemExit(f"invalid hex byte: {exc}")

def main(argv=None):
    parser=argparse.ArgumentParser(description="Run a deterministic UDS request"); parser.add_argument("bytes",nargs="+"); args=parser.parse_args(argv)
    response=UdsSession().handle(parse_hex(args.bytes)); print(" ".join(f"{byte:02x}" for byte in response)); return 0

if __name__=="__main__": raise SystemExit(main())
