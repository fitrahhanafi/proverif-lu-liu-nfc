"""
as_server.py — Authentication Server (AS) protokol Lu & Liu.

AS adalah server TCP terpusat. Setiap koneksi masuk membawa satu pesan
permintaan dengan field "phase":
    - "register"  : fase pendaftaran (RQE, RQS) -> (RPE, RPS)
    - "auth"      : fase autentikasi (AQS2, AQH2) -> (APS1, APE1, APE2)

AS menyimpan kredensial perangkat di basis data dalam memori. Untuk
mendemonstrasikan proteksi terhadap replay, AS mencatat hash bagian-dalam
milik N1, yaitu H(IDN1, Rn1, H(RnA1)), yang telah diproses pada himpunan
seen_inner. Setiap sesi sah membangkitkan Rn baru melalui registrasi ulang
sehingga hash ini selalu segar, sedangkan pesan yang diputar ulang membawa
hash lama sehingga ditolak. Hash bagian-dalam N1 dipilih sebagai penanda,
bukan AQH2, karena registrasi ulang N2 pada setiap sentuhan membuat AQH2
selalu berubah.

AS juga menegakkan waktu nyata: survival period (SP) sebagai batas kedaluwarsa
kredensial, dan timestamp (TS1) yang kesegarannya divalidasi oleh N2.

Setiap penolakan dikirim ke klien dengan field "reason" berupa kode ringkas
yang konsisten (mis. replay_detected, sp_expired_n1) dan field "message"
berupa penjelasan manusiawi.

Jalankan di terminal tersendiri:
    python3 as_server.py
"""

import socket
import threading

import protokol as pr
from protokol import (H, senc, sdec, aenc, adec, sign,
                      send_msg, recv_msg, b2s, HOST, PORT)

log = pr.Log("AS")


class AuthServer:
    def __init__(self):
        self.priv, self.pub = pr.generate_as_keypair()
        # database: IDN(hex) -> dict(Rn, K, RnA)
        self.db = {}
        # himpunan hash bagian-dalam milik N1, H(IDN1, Rn1, H(RnA1)), yang
        # sudah pernah diproses. Dipakai sebagai penanda anti-replay: setiap
        # sesi sah membangkitkan Rn baru (registrasi ulang) sehingga hash ini
        # selalu segar, sedangkan pesan yang diputar ulang membawa hash lama.
        self.seen_inner = set()
        # himpunan sid yang sudah pernah terlihat, untuk menandai awal setiap
        # transaksi (registrasi → autentikasi) dengan pemisah di konsol.
        self.seen_sids = set()
        self.lock = threading.Lock()

    # ----- fase pendaftaran -----
    def handle_register(self, conn, msg, sid, peer):
        RQE, RQS = msg["RQE"], msg["RQS"]
        K = adec(RQE, self.priv)                       # buka E_puk{K}
        idn, rn = sdec(RQS, K).split(b"||")            # buka SK{IDN, Rn}
        log.recv(f"provisioning request from {idn.decode()} "
                 f"[RQE=enc key, RQS=enc (ID,nonce); nonce Rn={b2s(rn)}]", sid=sid, peer=peer)

        # Asumsi otorisasi pendaftaran: AS hanya melayani identitas dikenal.
        if idn not in (b"IDN1", b"IDN2"):
            msg_txt = f"tag identity {idn.decode()} not authorised — provisioning refused"
            log.warn(msg_txt, sid=sid, reason="unauthorized_identity")
            send_msg(conn, {"status": "reject", "reason": "unauthorized_identity", "message": msg_txt})
            return

        RnA = pr.os.urandom(16)
        # SP sebagai waktu nyata: kredensial berlaku hingga reg_time + SP_DURATION.
        reg_time = pr.now_unix()
        expiry = reg_time + pr.SP_DURATION
        SP = str(expiry).encode()          # SP berisi waktu kedaluwarsa (Unix)
        with self.lock:
            self.db[idn] = {"Rn": rn, "K": K, "RnA": RnA, "expiry": expiry}
        log.ok(f"{idn.decode()} credential provisioned "
               f"[server nonce RnA={b2s(RnA)}; survival period valid until "
               f"{pr.fmt_time(expiry)} ({pr.SP_DURATION}s)]", sid=sid)

        RPE = sign(H(idn, rn), self.priv)              # E_prk{H(IDN,Rn)}
        RPS = senc(SP + b"||" + H(RnA), K)             # SK{SP, H(RnA)}
        send_msg(conn, {"status": "ok", "RPE": RPE, "RPS": RPS})
        log.send(f"provisioning reply sent [RPE=AS signature, RPS=enc (SP, H(RnA)={b2s(H(RnA))})]", sid=sid)

    # ----- fase autentikasi -----
    def handle_auth(self, conn, msg, sid, peer):
        import time as _t
        t0 = _t.time()

        def reject(text, reason):
            # reason: kode ringkas konsisten yang dikirim ke klien (N2, penyerang)
            # text: pesan manusiawi untuk log AS
            log.warn(text, sid=sid, reason=reason)
            send_msg(conn, {"status": "reject", "reason": reason, "message": text})

        AQS2, AQH2 = msg["AQS2"], msg["AQH2"]
        log.recv(f"authentication request via reader "
                 f"[AQS2=enc auth data, AQH2=integrity hash={b2s(AQH2)}]", sid=sid, peer=peer)

        # ---- Buka AQS2 dengan K2 dari database ----
        if b"IDN2" not in self.db:
            reject("N2 not provisioned yet", "n2_unregistered"); return
        rec2 = self.db[b"IDN2"]
        try:
            id2, rn2, hrna2, AQS1_inner = sdec(AQS2, rec2["K"]).split(b"||", 3)
        except Exception:
            reject("AQS2 could not be decrypted with N2 key", "aqs2_decrypt_fail"); return

        # ---- Verifikasi data N2 terhadap database ----
        if not (id2 == b"IDN2" and rn2 == rec2["Rn"] and hrna2 == H(rec2["RnA"])):
            reject("N2 credential check failed", "n2_credential_mismatch"); return
        log.ok("N2 credential matches record (ID, nonce, server nonce hash)", sid=sid)

        # ---- Buka AQS1_inner dengan K1 dari database ----
        if b"IDN1" not in self.db:
            reject("N1 not provisioned yet", "n1_unregistered"); return
        rec1 = self.db[b"IDN1"]
        try:
            id1, rn1, hrna1 = sdec(AQS1_inner, rec1["K"]).split(b"||", 2)
        except Exception:
            reject("inner AQS1 could not be decrypted with N1 key", "aqs1_decrypt_fail"); return

        # ---- Verifikasi data N1 terhadap database ----
        if not (id1 == b"IDN1" and rn1 == rec1["Rn"] and hrna1 == H(rec1["RnA"])):
            reject("N1 credential check failed", "n1_credential_mismatch"); return
        log.ok("N1 credential matches record (ID, nonce, server nonce hash)", sid=sid)

        # ---- Proteksi replay: tolak hash bagian-dalam N1 yang pernah dipakai ----
        inner_hash = H(id1, rn1, hrna1)
        with self.lock:
            if inner_hash in self.seen_inner:
                log.warn(f"N1 tap hash H(IDN1,Rn1,H(RnA1))={b2s(inner_hash)} already seen "
                         f"before — REPLAY detected", sid=sid, reason="replay_detected",
                         inner_hash=inner_hash.hex())
                send_msg(conn, {"status": "reject", "reason": "replay_detected",
                                "message": "replay detected (this N1 tap was already used)"})
                return

        # ---- Verifikasi integritas berlapis AQH2 ----
        aqh1 = H(id1, rn1, hrna1)
        aqh2_calc = H(id2, rn2, hrna2, aqh1)
        if aqh2_calc != AQH2:
            reject("recomputed AQH2 does not match — integrity check failed", "aqh2_integrity_fail"); return
        log.ok("message-chain integrity verified (recomputed AQH2 = received AQH2)", sid=sid)

        # ---- Penegakan SP (survival period): tolak kredensial kedaluwarsa ----
        now = pr.now_unix()
        if now > rec1["expiry"]:
            reject(f"N1 credential expired (survival period ended {pr.fmt_time(rec1['expiry'])})", "sp_expired_n1"); return
        if now > rec2["expiry"]:
            reject(f"N2 credential expired (survival period ended {pr.fmt_time(rec2['expiry'])})", "sp_expired_n2"); return
        log.ok(f"survival period still valid "
               f"[N1 until {pr.fmt_time(rec1['expiry'])}, N2 until {pr.fmt_time(rec2['expiry'])}]", sid=sid)

        # ---- Catat hash bagian-dalam N1 sebagai sudah diproses ----
        with self.lock:
            self.seen_inner.add(inner_hash)

        # ---- Susun respons APS1, APE1, APE2 ----
        # TS1 sebagai waktu nyata (Unix). Seluruh bagian biner di-hex-kan agar
        # pemisah "||" tidak ambigu terhadap byte mentah hash.
        TS1 = pr.now_unix()
        inner = senc(H(id1, rn1, hrna1), rec1["K"])           # SK1{H{...N1...}}
        APS1_plain = (H(id2, rn2, hrna2).hex().encode() + b"||" +
                      str(TS1).encode() + b"||" +
                      inner.hex().encode())
        APS1 = senc(APS1_plain, rec2["K"])                    # SK2{H{N2}, TS1, inner}
        APE1 = sign(H(b"IDN1"), self.priv)                    # E_prk{H(IDN1)}
        APE2 = sign(H(b"IDN2"), self.priv)                    # E_prk{H(IDN2)}
        send_msg(conn, {"status": "ok", "APS1": APS1, "APE1": APE1, "APE2": APE2})
        latency = int((_t.time() - t0) * 1000)
        log.send(f"auth reply sent [APS1=enc response, APE1/APE2=AS signatures, TS1=timestamp {pr.fmt_time(TS1)}]", sid=sid)
        log.ok(f"N1 and N2 mutually authenticated (processing time {latency}ms)", sid=sid, latency_ms=latency)

    # ----- dispatcher -----
    def serve_conn(self, conn, addr):
        peer = f"{addr[0]}:{addr[1]}"
        try:
            msg = recv_msg(conn)
            if msg is None:
                return
            sid = msg.get("sid")
            phase = msg.get("phase")
            # Pemisah transaksi: cetak sekali saat sid pertama kali muncul,
            # yaitu pada registrasi pertama dari satu penempelan.
            if sid and phase in ("register", "auth"):
                with self.lock:
                    first = sid not in self.seen_sids
                    if first:
                        self.seen_sids.add(sid)
                if first:
                    log.rule(sid)
            if msg.get("type") == "get_pubkey":
                send_msg(conn, {"pub": pr.pub_to_bytes(self.pub)})
            elif phase == "register":
                self.handle_register(conn, msg, sid, peer)
            elif phase == "auth":
                log.info("incoming authentication request", sid=sid)
                self.handle_auth(conn, msg, sid, peer)
        except Exception as e:
            log.fail(f"error handling connection: {e}", reason="exception")
        finally:
            conn.close()

    def run(self):
        log.banner("AUTHENTICATION SERVER (AS) — Lu & Liu NFC Protocol")
        log.info(f"RSA-2048 keypair generated; listening on {HOST}:{PORT}")
        log.info("Waiting for provisioning and authentication requests")
        print()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(8)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.serve_conn, args=(conn, addr),
                             daemon=True).start()


if __name__ == "__main__":
    try:
        AuthServer().run()
    except KeyboardInterrupt:
        print()
        log.info("AS stopped.")
