"""
protokol.py — Primitif kriptografi dan utilitas bersama untuk simulasi
protokol autentikasi NFC Lu & Liu.

Implementasi konkret dari notasi protokol:
    E_puk / E_prk : RSA-2048 (OAEP untuk enkripsi, PSS untuk tanda tangan)
    SK_i          : AES-256-CBC
    H             : SHA-256

Catatan pemetaan terhadap notasi paper:
    aenc/adec   <-> E_puk{...}        (distribusi shared key)
    sign/verify <-> E_prk{H(...)}     (pembuktian asal pesan oleh AS)
    senc/sdec   <-> SK_i{...}         (enkripsi konten)
    H           <-> H(...)            (integritas, one-way)
"""

import json
import os
import socket
import struct
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# --------------------------------------------------------------------------
# Fungsi hash H(...)
# --------------------------------------------------------------------------
def H(*parts: bytes) -> bytes:
    """SHA-256 atas gabungan beberapa bytes. Memodelkan H pada protokol."""
    h = hashlib.sha256()
    for p in parts:
        h.update(struct.pack(">I", len(p)))  # panjang per-bagian agar tidak ambigu
        h.update(p)
    return h.digest()


# --------------------------------------------------------------------------
# Enkripsi simetris SK_i{...}  (AES-256-CBC)
# --------------------------------------------------------------------------
def senc(plaintext: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    padlen = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([padlen]) * padlen
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(padded) + enc.finalize()


def sdec(ciphertext: bytes, key: bytes) -> bytes:
    iv, body = ciphertext[:16], ciphertext[16:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(body) + dec.finalize()
    padlen = padded[-1]
    if padlen < 1 or padlen > 16:
        raise ValueError("padding tidak valid")
    return padded[:-padlen]


# --------------------------------------------------------------------------
# Enkripsi asimetris E_puk{...}  (RSA-OAEP)
# --------------------------------------------------------------------------
def aenc(plaintext: bytes, pubkey) -> bytes:
    return pubkey.encrypt(
        plaintext,
        apad.OAEP(mgf=apad.MGF1(algorithm=hashes.SHA256()),
                  algorithm=hashes.SHA256(), label=None),
    )


def adec(ciphertext: bytes, privkey) -> bytes:
    return privkey.decrypt(
        ciphertext,
        apad.OAEP(mgf=apad.MGF1(algorithm=hashes.SHA256()),
                  algorithm=hashes.SHA256(), label=None),
    )


# --------------------------------------------------------------------------
# Tanda tangan digital E_prk{H(...)}  (RSA-PSS)
# --------------------------------------------------------------------------
def sign(message: bytes, privkey) -> bytes:
    return privkey.sign(
        message,
        apad.PSS(mgf=apad.MGF1(hashes.SHA256()),
                 salt_length=apad.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify(signature: bytes, message: bytes, pubkey) -> bool:
    from cryptography.exceptions import InvalidSignature
    try:
        pubkey.verify(
            signature, message,
            apad.PSS(mgf=apad.MGF1(hashes.SHA256()),
                     salt_length=apad.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# Pembangkit kunci RSA AS
# --------------------------------------------------------------------------
def generate_as_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


def pub_to_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def pub_from_bytes(data: bytes):
    return serialization.load_pem_public_key(data)


# --------------------------------------------------------------------------
# Framing pesan di atas TCP: setiap pesan = JSON, field bytes di-hex-kan,
# dikirim dengan prefiks panjang 4 byte (big-endian).
# --------------------------------------------------------------------------
def _hexify(obj):
    if isinstance(obj, bytes):
        return {"__b__": obj.hex()}
    if isinstance(obj, dict):
        return {k: _hexify(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_hexify(v) for v in obj]
    return obj


def _unhexify(obj):
    if isinstance(obj, dict):
        if "__b__" in obj and len(obj) == 1:
            return bytes.fromhex(obj["__b__"])
        return {k: _unhexify(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_unhexify(v) for v in obj]
    return obj


def send_msg(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(_hexify(obj)).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_msg(sock: socket.socket):
    raw = _recv_exact(sock, 4)
    if raw is None:
        return None
    (length,) = struct.unpack(">I", raw)
    body = _recv_exact(sock, length)
    if body is None:
        return None
    return _unhexify(json.loads(body.decode("utf-8")))


def _recv_exact(sock: socket.socket, n: int):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# --------------------------------------------------------------------------
# Utilitas tampilan
# --------------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 5005

# --------------------------------------------------------------------------
# Parameter waktu nyata (nilai wajar dunia nyata)
# --------------------------------------------------------------------------
SP_DURATION = 3600     # masa berlaku kredensial (survival period), detik = 1 jam
TS_TOLERANCE = 30      # toleransi kesegaran timestamp, detik (mengikuti praktik TOTP)


def now_unix() -> int:
    """Waktu Unix saat ini dalam detik (bilangan bulat)."""
    import time
    return int(time.time())


def fmt_time(unix_ts: int) -> str:
    """Format waktu Unix menjadi HH:MM:SS untuk tampilan log."""
    import datetime
    return datetime.datetime.fromtimestamp(unix_ts).strftime("%H:%M:%S")


def b2s(b: bytes, n: int = 12) -> str:
    """Ringkasan hex singkat untuk log."""
    return b.hex()[:n] + ("…" if len(b.hex()) > n else "")


def new_sid() -> str:
    """ID sesi pendek (4 heksadesimal) untuk korelasi antar-terminal."""
    return os.urandom(2).hex()


class Log:
    """Pencatat log dengan level keparahan, ID sesi korelasi, kode alasan,
    warna ANSI per peran, dan keluaran terstruktur JSONL ke berkas.

    Format konsol:  HH:MM:SS.mmm  LEVEL  ROLE  [sid]  pesan
    Setiap baris juga ditulis ke berkas log_<role>.jsonl.
    """
    COLORS = {
        "AS": "\033[96m",        # cyan
        "N1": "\033[92m",        # green
        "N2": "\033[93m",        # yellow
        "ATTACKER": "\033[91m",  # red
    }
    LEVEL_COLOR = {
        "INFO": "\033[37m", "STEP": "\033[1m", "SEND": "\033[90m",
        "RECV": "\033[90m", "OK": "\033[92m", "WARN": "\033[33m",
        "ERROR": "\033[91m",
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[90m"

    def __init__(self, role: str, to_file: bool = True):
        self.role = role
        self.c = self.COLORS.get(role, "")
        self._fp = None
        if to_file:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                f"log_{role.lower()}.jsonl")
            self._fp = open(path, "a", buffering=1, encoding="utf-8")

    # ---- inti: satu titik cetak untuk konsol + berkas ----
    def _emit(self, level: str, msg: str, sid=None, reason=None, **fields):
        import datetime
        now = datetime.datetime.now()
        ts_ms = now.strftime("%H:%M:%S.%f")[:-3]
        sid_txt = f"[{sid}]" if sid else "[----]"

        lvl_c = self.LEVEL_COLOR.get(level, "")
        line = (f"{self.DIM}{ts_ms}{self.RESET}  "
                f"{lvl_c}{level:<5}{self.RESET}  "
                f"{self.c}{self.role:<8}{self.RESET}  "
                f"{self.DIM}{sid_txt}{self.RESET}  {msg}")
        if reason:
            line += f"  {self.DIM}reason={reason}{self.RESET}"
        print(line)

        if self._fp:
            import json
            rec = {"time": now.isoformat(timespec="milliseconds"),
                   "level": level, "role": self.role,
                   "sid": sid, "event": _strip_ansi(msg)}
            if reason:
                rec["reason"] = reason
            rec.update(fields)
            self._fp.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # ---- API yang dipakai program ----
    def banner(self, text: str):
        import datetime
        now = datetime.datetime.now().strftime("%H:%M:%S")
        bar = "═" * 64
        print(f"{self.c}{self.BOLD}╔{bar}╗{self.RESET}")
        print(f"{self.c}{self.BOLD}║ {text:<52} {now:>9} ║{self.RESET}")
        print(f"{self.c}{self.BOLD}╚{bar}╝{self.RESET}")

    def info(self, text, sid=None, **f):
        self._emit("INFO", text, sid, **f)

    def step(self, label, text, sid=None, **f):
        self._emit("STEP", f"{self.BOLD}{label}{self.RESET} {text}", sid,
                   step=label, **f)

    def ok(self, text, sid=None, **f):
        self._emit("OK", f"✓ {text}", sid, **f)

    def warn(self, text, sid=None, reason=None, **f):
        self._emit("WARN", f"⚠ {text}", sid, reason=reason, **f)

    def fail(self, text, sid=None, reason=None, **f):
        self._emit("ERROR", f"✗ {text}", sid, reason=reason, **f)

    def recv(self, text, sid=None, peer=None, **f):
        msg = f"← {text}"
        if peer:
            msg += f"  {self.DIM}peer={peer}{self.RESET}"
        self._emit("RECV", msg, sid, peer=peer, **f)

    def send(self, text, sid=None, **f):
        self._emit("SEND", f"→ {text}", sid, **f)

    def rule(self, sid=None):
        """Pemisah transaksi: baris kosong lalu garis dengan label sid.
        Hanya tampil di konsol (tidak ditulis ke berkas JSONL)."""
        label = f"transaction [{sid}]" if sid else "transaction"
        print()
        print(f"{self.c}{'─' * 46}  {label}{self.RESET}")


def _strip_ansi(s: str) -> str:
    """Membuang kode warna ANSI agar berkas JSONL bersih."""
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)
