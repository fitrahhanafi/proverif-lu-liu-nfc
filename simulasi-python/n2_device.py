"""
n2_device.py — Perangkat NFC N2 protokol Lu & Liu.

N2 berperan ganda: peserta autentikasi sekaligus PERANTARA antara N1 (atau
penyerang) dengan AS. Alur:
    1. N2 membuka socket dengar untuk menerima (AQS1, AQH1) dari N1.
    2. Setiap kali menerima sentuhan, N2 melakukan registrasi ulang ke AS
       untuk memperoleh kredensial baru (K2 dan Rn2 yang segar).
    3. N2 membungkus pesan N1 menjadi (AQS2, AQH2) lalu meneruskannya ke AS,
       memvalidasi kesegaran timestamp (TS1) pada balasan AS, lalu meneruskan
       balasan (APS2, APE1) ke pemanggil.

Tekan ENTER pada terminal N1/attacker menandai "perangkat ditempelkan".
N2 sendiri berjalan sebagai layanan yang menunggu sentuhan dari N1.

Jalankan di terminal tersendiri (setelah AS aktif):
    python3 n2_device.py
"""

import socket
import threading

import protokol as pr
from protokol import (H, senc, sdec, aenc, verify,
                      send_msg, recv_msg, b2s, HOST, PORT)

log = pr.Log("N2")
N2_PORT = 5006   # port dengar N2 untuk menerima sentuhan dari N1/attacker


class N2Device:
    def __init__(self):
        self.IDN = b"IDN2"
        self.K = None       # dibangkitkan ulang setiap sentuhan
        self.Rn = None
        self.RnA = None
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
        # Setiap sentuhan membangkitkan kredensial baru: K2 dan Rn2 segar.
        self.K = pr.os.urandom(32)
        self.Rn = pr.os.urandom(16)
        log.step("PROVISION", f"generating fresh credential, contacting AS [key K2 + nonce Rn2={b2s(self.Rn)}]", sid=sid)
        RQE = aenc(self.K, self.as_pub)                 # E_puk{K2}
        RQS = senc(self.IDN + b"||" + self.Rn, self.K)  # SK2{IDN2, Rn2}
        s = self.connect_as()
        send_msg(s, {"sid": sid, "phase": "register", "RQE": RQE, "RQS": RQS})
        log.send("provisioning request sent to AS [RQE=enc K2, RQS=enc (ID,Rn2)]", sid=sid)
        resp = recv_msg(s)
        s.close()
        if resp.get("status") != "ok":
            log.fail(f"provisioning refused: {resp.get('message', resp.get('reason'))}", sid=sid, reason=resp.get("reason"))
            return False
        # verifikasi RPE = E_prk{H(IDN2, Rn2)}
        if not verify(resp["RPE"], H(self.IDN, self.Rn), self.as_pub):
            log.fail("AS signature (RPE) verification failed — provisioning aborted", sid=sid, reason="rpe_invalid")
            return False
        sp, self.H_RnA = sdec(resp["RPS"], self.K).split(b"||")
        self.SP_expiry = int(sp.decode())
        log.ok(f"provisioning done [survival period until {pr.fmt_time(self.SP_expiry)}; "
               f"server nonce hash H(RnA2)={b2s(self.H_RnA)}]", sid=sid)
        return True

    # Menerima (AQS1, AQH1) dari N1/penyerang, lalu menjadi perantara ke AS
    def handle_touch(self, conn, addr):
        msg = recv_msg(conn)
        if msg is None:
            return
        sid = msg.get("sid")
        AQS1, AQH1 = msg["AQS1"], msg["AQH1"]
        peer = msg.get("from", "?")
        peer_addr = f"{addr[0]}:{addr[1]}"
        print()
        log.info(f"tap received from {peer}", sid=sid)
        log.recv(f"tag message received [AQS1=enc auth data, AQH1=integrity hash={b2s(AQH1)}]", sid=sid, peer=peer_addr)

        # Registrasi ulang N2 setiap sentuhan: kredensial K2, Rn2 segar.
        if not self.register(sid):
            send_msg(conn, {"status": "reject", "reason": "n2_provisioning_failed", "message": "N2 provisioning failed"})
            return

        # Bungkus menjadi AQS2, AQH2 (Persamaan 7 & 8)
        AQS2 = senc(self.IDN + b"||" + self.Rn + b"||" + self.H_RnA + b"||" + AQS1,
                    self.K)
        AQH2 = H(self.IDN, self.Rn, self.H_RnA, AQH1)
        log.step("RELAY", f"wrapping tag message into reader message [AQS2=enc (N2 data + AQS1), AQH2=integrity hash={b2s(AQH2)}]", sid=sid)

        # Teruskan ke AS
        s = self.connect_as()
        send_msg(s, {"sid": sid, "phase": "auth", "AQS2": AQS2, "AQH2": AQH2})
        log.send("AQS2, AQH2 forwarded to AS", sid=sid)
        resp = recv_msg(s)
        s.close()

        if resp.get("status") != "ok":
            rcode = resp.get("reason")
            rmsg = resp.get("message", rcode)
            log.warn(f"AS rejected the request: {rmsg}", sid=sid, reason=rcode)
            send_msg(conn, {"status": "reject", "reason": rcode, "message": rmsg})
            return

        # Verifikasi APE2 = E_prk{H(IDN2)} lalu buka APS1
        if not verify(resp["APE2"], H(self.IDN), self.as_pub):
            log.fail("AS signature (APE2) verification failed", sid=sid, reason="ape2_invalid")
            send_msg(conn, {"status": "reject", "reason": "ape2_invalid", "message": "APE2 invalid"})
            return
        h_n2_hex, ts1_raw, inner_hex = sdec(resp["APS1"], self.K).split(b"||", 2)
        if h_n2_hex != H(self.IDN, self.Rn, self.H_RnA).hex().encode():
            log.fail("N2 confirmation hash from AS does not match", sid=sid, reason="hash_n2_mismatch")
            send_msg(conn, {"status": "reject", "reason": "hash_n2_mismatch", "message": "N2 hash invalid"})
            return

        # ---- Validasi kesegaran TS1 (waktu nyata) ----
        TS1 = int(ts1_raw.decode())
        selisih = abs(pr.now_unix() - TS1)
        if selisih > pr.TS_TOLERANCE:
            log.warn(f"AS timestamp not fresh: gap {selisih}s > tolerance "
                     f"{pr.TS_TOLERANCE}s — response rejected", sid=sid, reason="ts1_stale")
            send_msg(conn, {"status": "reject", "reason": "ts1_stale", "message": "TS1 expired"})
            return
        log.ok(f"N2 verified by AS [timestamp TS1={pr.fmt_time(TS1)}, "
               f"gap {selisih}s <= tolerance {pr.TS_TOLERANCE}s]", sid=sid)

        # Teruskan APS2 (=inner) dan APE1 ke N1
        send_msg(conn, {"status": "ok",
                        "APS2": bytes.fromhex(inner_hex.decode()),
                        "APE1": resp["APE1"]})
        log.send("APS2, APE1 relayed back to the tag (N1)", sid=sid)

    def run(self):
        log.banner("NFC READER N2 (IDN2) — participant + relay")
        self.fetch_pubkey()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, N2_PORT))
        srv.listen(8)
        print()
        log.info(f"reader N2 ready; listening on {HOST}:{N2_PORT}")
        log.info("Waiting for a tap from N1 or the attacker")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.handle_touch, args=(conn, addr),
                             daemon=True).start()


if __name__ == "__main__":
    try:
        N2Device().run()
    except KeyboardInterrupt:
        print()
        log.info("N2 stopped.")
