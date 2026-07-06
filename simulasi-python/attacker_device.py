"""
attacker_device.py — Perangkat penyerang untuk demonstrasi serangan REPLAY.

Skenario sesuai instruksi penelitian:
  - Penyerang menyadap pesan autentikasi (AQS1, AQH1) milik N1 dari sesi sah,
    lalu MEMUTAR ULANG pesan yang sama ke N2 -> AS.
  - Nonce penyerang dipaksa sama dengan Rn milik IDN1, yaitu nonce yang
    terkandung dalam pesan sadapan tersebut.

Pada model ini, setiap kali N1 menempel, N1 melakukan registrasi ulang dengan
Rn baru sehingga pesan autentikasi sah selalu segar. AS mencatat hash
bagian-dalam milik N1, yaitu H(IDN1, Rn1, H(RnA1)), yang telah diproses.
Akibatnya:
  - Autentikasi sah N1 selalu membawa hash segar sehingga diterima berulang.
  - Pesan yang diputar ulang penyerang membawa hash yang sama dengan sesi sah
    sehingga dikenali AS sebagai replay dan DITOLAK.

Alur penggunaan:
  1. Jalankan AS, N2, dan N1. Tempelkan N1 sekali (tekan ENTER di terminal N1)
     agar terjadi satu sesi sah; penyerang menyadap pesannya.
  2. Pada terminal ini, tekan ENTER untuk menempelkan "perangkat palsu" yang
     memutar ulang pesan sadapan tersebut.

Jalankan di terminal tersendiri:
    python3 attacker_device.py
"""

import socket

import protokol as pr
from protokol import (H, senc, sdec, aenc, verify,
                      send_msg, recv_msg, b2s, HOST, PORT)
from n2_device import N2_PORT

log = pr.Log("ATTACKER")


class Attacker:
    def __init__(self):
        self.IDN = b"IDN1"               # menyamar sebagai IDN1
        self.as_pub = None
        # Nonce penyerang DIPAKSA sama dengan Rn milik IDN1.
        # Pada protokol nyata, ini merepresentasikan Rn1 yang telah disadap.
        self.captured_AQS1 = None
        self.captured_AQH1 = None
        self.forced_Rn = None

    def fetch_pubkey(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        send_msg(s, {"type": "get_pubkey"})
        self.as_pub = pr.pub_from_bytes(recv_msg(s)["pub"])
        s.close()
        log.info("AS public key obtained (public information)")

    def sniff_from_file(self):
        """Membaca pesan N1 yang disadap dari berkas bersama capture.bin.

        Berkas ini ditulis oleh N1 setiap kali ia mengautentikasi (lihat
        mekanisme di bawah). Memodelkan penyerang yang menyadap saluran.
        """
        import os
        path = os.path.join(os.path.dirname(__file__), "capture.bin")
        if not os.path.exists(path):
            return False
        with open(path, "rb") as f:
            data = f.read()
        rn, aqs1, aqh1 = data.split(b"::SEP::", 2)
        self.forced_Rn = rn
        self.captured_AQS1 = aqs1
        self.captured_AQH1 = aqh1
        return True

    def replay(self):
        if self.captured_AQS1 is None:
            log.fail("no captured N1 tap yet — "
                     "tap a legitimate N1 first (ENTER in the N1 terminal)", reason="no_capture")
            return

        sid = pr.new_sid()
        log.step("REPLAY", "replaying captured AQS1, AQH1 of tag IDN1", sid=sid)
        log.info(f"attacker nonce forced equal to captured Rn1 (Rn={b2s(self.forced_Rn)}); "
                 f"attacker only copies the bytes, cannot read the content", sid=sid)
        log.send(f"captured AQS1, AQH1 sent to reader N2 [integrity hash AQH1={b2s(self.captured_AQH1)}]", sid=sid)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, N2_PORT))
        send_msg(s, {"sid": sid, "from": "ATTACKER",
                     "AQS1": self.captured_AQS1, "AQH1": self.captured_AQH1})
        resp = recv_msg(s)
        s.close()

        if resp is None or resp.get("status") != "ok":
            rcode = resp.get("reason") if resp else "no_reply"
            rmsg = resp.get("message", rcode) if resp else "no reply"
            log.warn(f"ATTACK FAILED — rejected: {rmsg}", sid=sid, reason=rcode)
            log.info("Protection works: the replayed tap was not accepted by AS.", sid=sid)
            return
        log.fail("ATTACK SUCCEEDED (not expected in this model)", sid=sid, reason="attack_succeeded")

    def run(self):
        log.banner("ATTACKER DEVICE — REPLAY attack demonstration")
        self.fetch_pubkey()
        log.info("Attacker impersonates tag IDN1 by replaying its captured tap (nonce = Rn1).")
        print()
        while True:
            try:
                input(f"{log.c}>>> [ATTACKER]{pr.Log.RESET} press ENTER to "
                      f"tap the cloned device on the reader (Ctrl+C to quit)... ")
            except (EOFError, KeyboardInterrupt):
                print()
                log.info("Attacker stopped.")
                break
            if not self.sniff_from_file():
                log.fail("capture file capture.bin does not exist yet — "
                         "run one legitimate N1 tap first")
                print()
                continue
            self.replay()
            print()


if __name__ == "__main__":
    Attacker().run()
