"""
n1_device.py — Perangkat NFC N1 protokol Lu & Liu (perangkat sah).

Setiap kali pengguna menekan ENTER (memodelkan aksi MENEMPELKAN perangkat N1
ke N2), N1 melakukan registrasi ulang ke AS untuk memperoleh kredensial baru
(K1 dan Rn1 yang segar), lalu mengirim (AQS1, AQH1) ke N2 yang akan
meneruskannya ke AS, kemudian N1 memverifikasi balasan dari AS (APE1, APS2).
Registrasi ulang pada setiap penempelan membuat setiap sesi autentikasi
memakai nilai acak yang segar sehingga N1 dapat menempel berkali-kali tanpa
pesannya dianggap sebagai replay.

Jalankan di terminal tersendiri (setelah AS dan N2 aktif):
    python3 n1_device.py
"""

import socket

import protokol as pr
from protokol import (H, senc, sdec, aenc, verify,
                      send_msg, recv_msg, b2s, HOST, PORT)
from n2_device import N2_PORT

log = pr.Log("N1")


class N1Device:
    def __init__(self):
        self.IDN = b"IDN1"
        self.K = None          # dibangkitkan ulang setiap tempel
        self.Rn = None
        self.H_RnA = None
        self.as_pub = None

    def connect_as(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        return s

    def fetch_pubkey(self):
        s = self.connect_as()
        send_msg(s, {"type": "get_pubkey"})
        self.as_pub = pr.pub_from_bytes(recv_msg(s)["pub"])
        s.close()
        log.info("AS public key obtained")

    def register(self, sid):
        # Setiap tempel membangkitkan kredensial baru: K1 dan Rn1 segar.
        self.K = pr.os.urandom(32)
        self.Rn = pr.os.urandom(16)
        log.step("PROVISION", f"generating fresh credential, contacting AS [key K1 + nonce Rn1={b2s(self.Rn)}]", sid=sid)
        RQE = aenc(self.K, self.as_pub)
        RQS = senc(self.IDN + b"||" + self.Rn, self.K)
        s = self.connect_as()
        send_msg(s, {"sid": sid, "phase": "register", "RQE": RQE, "RQS": RQS})
        log.send("provisioning request sent to AS [RQE=enc K1, RQS=enc (ID,Rn1)]", sid=sid)
        resp = recv_msg(s)
        s.close()
        if resp.get("status") != "ok":
            log.fail(f"provisioning refused: {resp.get('message', resp.get('reason'))}", sid=sid, reason=resp.get("reason"))
            return False
        if not verify(resp["RPE"], H(self.IDN, self.Rn), self.as_pub):
            log.fail("AS signature (RPE) verification failed", sid=sid, reason="rpe_invalid")
            return False
        sp, self.H_RnA = sdec(resp["RPS"], self.K).split(b"||")
        self.SP_expiry = int(sp.decode())
        log.ok(f"provisioning done [survival period until {pr.fmt_time(self.SP_expiry)}; "
               f"server nonce hash H(RnA1)={b2s(self.H_RnA)}]", sid=sid)
        return True

    def authenticate(self, sid):
        # Persamaan (5) & (6)
        AQS1 = senc(self.IDN + b"||" + self.Rn + b"||" + self.H_RnA, self.K)
        AQH1 = H(self.IDN, self.Rn, self.H_RnA)
        log.step("AUTH", f"building tap message [AQS1=enc (ID,Rn1,H(RnA1)); AQH1=integrity hash={b2s(AQH1)}]", sid=sid)

        # Tulis pesan ke capture.bin: memodelkan penyerang yang menyadap saluran.
        import os
        with open(os.path.join(os.path.dirname(__file__), "capture.bin"), "wb") as f:
            f.write(self.Rn + b"::SEP::" + AQS1 + b"::SEP::" + AQH1)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, N2_PORT))
        send_msg(s, {"sid": sid, "from": "N1", "AQS1": AQS1, "AQH1": AQH1})
        log.send("AQS1, AQH1 sent to reader N2", sid=sid)
        resp = recv_msg(s)
        s.close()

        if resp is None or resp.get("status") != "ok":
            rcode = resp.get("reason") if resp else "no_reply"
            rmsg = resp.get("message", rcode) if resp else "no reply"
            log.fail(f"authentication failed: {rmsg}", sid=sid, reason=rcode)
            return
        # verifikasi APE1 = E_prk{H(IDN1)}
        if not verify(resp["APE1"], H(self.IDN), self.as_pub):
            log.fail("AS signature (APE1) verification failed", sid=sid, reason="ape1_invalid")
            return
        # buka APS2 = SK1{H{IDN1, Rn1, H(RnA1)}}
        content = sdec(resp["APS2"], self.K)
        if content != H(self.IDN, self.Rn, self.H_RnA):
            log.fail("APS2 content does not match local data", sid=sid, reason="aps2_mismatch")
            return
        log.ok("AUTHENTICATION SUCCESS — N1 verified end-to-end with AS", sid=sid)

    def run(self):
        log.banner("NFC TAG N1 (IDN1) — legitimate tag")
        self.fetch_pubkey()
        print()
        while True:
            try:
                input(f"{log.c}>>> [N1]{pr.Log.RESET} press ENTER to tap N1 on the reader "
                      f"(Ctrl+C to quit)... ")
            except (EOFError, KeyboardInterrupt):
                print()
                log.info("N1 stopped.")
                break
            sid = pr.new_sid()         # ID sesi korelasi untuk satu penempelan
            if self.register(sid):     # registrasi ulang setiap tempel
                self.authenticate(sid)
            print()


if __name__ == "__main__":
    N1Device().run()
