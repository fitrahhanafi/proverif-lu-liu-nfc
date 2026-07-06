# Simulasi Protokol Autentikasi Perangkat NFC Lu & Liu (Python)

Simulasi ini mengimplementasikan protokol autentikasi perangkat *Near Field Communication* (NFC) Lu & Liu secara konkret menggunakan **algoritma kriptografi nyata** dan komunikasi antar-proses melalui **TCP socket**. Simulasi berfungsi untuk memvisualisasikan alur protokol pada skenario normal serta mendemonstrasikan **ketahanan terhadap serangan pengulangan (*replay attack*)**, sekaligus melengkapi hasil analisis formal yang dilakukan menggunakan ProVerif.

> Bagian ini merupakan komponen simulasi dari Tugas Akhir mengenai analisis keamanan protokol autentikasi perangkat NFC Lu & Liu. Untuk model formalnya, lihat folder `proverif/`.

---

## Daftar Isi

- [Arsitektur Simulasi](#arsitektur-simulasi)
- [Berkas dalam Folder Ini](#berkas-dalam-folder-ini)
- [Pemetaan Notasi Protokol ke Kriptografi Nyata](#pemetaan-notasi-protokol-ke-kriptografi-nyata)
- [Prasyarat](#prasyarat)
- [Cara Menjalankan](#cara-menjalankan)
  - [Skenario Normal](#skenario-normal-autentikasi-berhasil)
  - [Skenario Serangan Replay](#skenario-serangan-replay)
- [Mekanisme Keamanan yang Didemonstrasikan](#mekanisme-keamanan-yang-didemonstrasikan)
- [Membaca Log](#membaca-log)
- [Batasan Simulasi](#batasan-simulasi)
- [Referensi](#referensi)

---

## Arsitektur Simulasi

Simulasi terdiri atas tiga entitas yang berjalan sebagai proses terpisah dan berkomunikasi melalui TCP pada `localhost` (`127.0.0.1`):

| Entitas | Peran | Port |
| --- | --- | --- |
| **AS** (`as_server.py`) | *Authentication Server* — server terpusat yang melayani pendaftaran & autentikasi | `5005` (mendengarkan) |
| **N2** (`n2_device.py`) | Perangkat NFC kedua, sekaligus **perantara** (*relay*) antara N1/penyerang dan AS | `5006` (mendengarkan) |
| **N1** (`n1_device.py`) | Perangkat NFC pertama (perangkat sah), memulai penempelan (*tap*) | — (klien) |
| **Penyerang** (`attacker_device.py`) | Perangkat palsu yang memutar ulang pesan sadapan milik N1 | — (klien) |

Alur komunikasi pada fase autentikasi:

```
N1  ──(AQS1, AQH1)──►  N2  ──(AQS2, AQH2)──►  AS
                        │                       │
N1  ◄──(APS2, APE1)──  N2  ◄──(APS1,APE1,APE2)──┘
```

N2 berperan ganda: peserta autentikasi sekaligus perelai pesan N1 menuju AS.

---

## Berkas dalam Folder Ini

| Berkas | Keterangan |
| --- | --- |
| `protokol.py` | Modul bersama: primitif kriptografi (`aenc`, `sign`, `senc`, `H`), *framing* pesan TCP, parameter waktu, dan utilitas *logging* |
| `as_server.py` | *Authentication Server* (AS) |
| `n1_device.py` | Perangkat NFC N1 (perangkat sah) |
| `n2_device.py` | Perangkat NFC N2 (peserta + perelai) |
| `attacker_device.py` | Perangkat penyerang (demonstrasi serangan *replay*) |

Berkas yang dihasilkan saat program berjalan (**tidak perlu diunggah**, sebaiknya masuk `.gitignore`):

| Berkas | Keterangan |
| --- | --- |
| `log_*.jsonl` | Log terstruktur per entitas (`log_as.jsonl`, `log_n1.jsonl`, dst.) |
| `capture.bin` | Berkas sadapan yang ditulis N1 dan dibaca penyerang (memodelkan penyadapan saluran) |

---

## Pemetaan Notasi Protokol ke Kriptografi Nyata

Simulasi mengimplementasikan notasi abstrak protokol menggunakan algoritma standar:

| Notasi Protokol | Implementasi Nyata | Fungsi di `protokol.py` |
| --- | --- | --- |
| $E_{puk}\{\dots\}$ (enkripsi kunci publik) | **RSA-2048** dengan *padding* OAEP (SHA-256) | `aenc` / `adec` |
| $E_{prk}\{H(\dots)\}$ (tanda tangan) | **RSA-2048** dengan skema PSS (SHA-256) | `sign` / `verify` |
| $SK_i\{\dots\}$ (enkripsi simetris) | **AES-256-CBC** (IV acak per pesan) | `senc` / `sdec` |
| $H(\dots)$ (fungsi *hash*) | **SHA-256** (dengan prefiks panjang antar-bagian) | `H` |

Pesan dikirim melalui TCP dalam format JSON (field biner di-*hex*-kan) dengan prefiks panjang 4 byte (*big-endian*).

---

## Prasyarat

- **Python 3.8** atau lebih baru.
- Pustaka **`cryptography`**. Pasang dengan:

```bash
pip install cryptography
```

---

## Cara Menjalankan

Setiap entitas dijalankan pada **terminal yang terpisah**. Urutan menjalankan penting: **AS → N2 → N1 → (penyerang)**.

### Skenario Normal (Autentikasi Berhasil)

**Terminal 1 — Authentication Server:**
```bash
python3 as_server.py
```

**Terminal 2 — Perangkat N2 (perelai):**
```bash
python3 n2_device.py
```

**Terminal 3 — Perangkat N1:**
```bash
python3 n1_device.py
```

Pada terminal N1, tekan **ENTER** untuk memodelkan aksi menempelkan perangkat N1 ke pembaca N2. Setiap penempelan, N1 melakukan **registrasi ulang** untuk memperoleh kredensial baru ($K_1$ dan $Rn_1$ yang segar), lalu melakukan autentikasi. Jika berhasil, N1 akan menampilkan:

```
OK   N1   AUTHENTICATION SUCCESS — N1 verified end-to-end with AS
```

Anda dapat menekan ENTER berkali-kali; setiap penempelan sah selalu diterima karena membawa nilai acak yang segar.

### Skenario Serangan Replay

Biarkan AS, N2, dan N1 tetap berjalan, lalu:

1. Pada terminal N1, tekan **ENTER** sekali untuk melakukan satu sesi autentikasi sah. Saat ini N1 menulis pesan autentikasinya ke `capture.bin` (memodelkan penyerang yang menyadap saluran).

2. **Terminal 4 — Perangkat penyerang:**
```bash
python3 attacker_device.py
```

Tekan **ENTER** untuk menempelkan perangkat palsu. Penyerang membaca `capture.bin` dan **memutar ulang** pesan $(AQS1, AQH1)$ milik N1 yang identik ke N2 → AS. AS mendeteksinya sebagai pesan yang telah diproses dan **menolaknya**:

```
WARN ATTACKER  ATTACK FAILED — rejected: replay detected (this N1 tap was already used)
INFO ATTACKER  Protection works: the replayed tap was not accepted by AS.
```

---

## Mekanisme Keamanan yang Didemonstrasikan

1. **Deteksi *replay* melalui penanda *hash* bagian-dalam.** AS menyimpan himpunan `seen_inner` berisi *hash* $H(IDN_1, Rn_1, H(RnA_1))$ dari setiap sesi N1 yang telah diproses. Karena setiap penempelan sah melakukan registrasi ulang dengan $Rn_1$ baru, *hash* ini selalu segar; sebaliknya pesan yang diputar ulang membawa *hash* lama sehingga langsung ditolak. *Hash* bagian-dalam N1 dipilih sebagai penanda (bukan $AQH2$) karena registrasi ulang N2 pada setiap sentuhan membuat $AQH2$ selalu berubah.

2. **Integritas berlapis.** AS menghitung ulang $AQH2 = H(IDN_2, Rn_2, H(RnA_2), AQH1)$ dan membandingkannya dengan nilai yang diterima untuk memastikan rantai pesan N1→N2 tidak diubah.

3. **Penegakan masa berlaku (*survival period*).** Kredensial yang tersimpan di AS memiliki batas waktu (`SP_DURATION`, bawaan 1 jam); permintaan dengan kredensial kedaluwarsa ditolak (`sp_expired_n1` / `sp_expired_n2`).

4. **Validasi kesegaran *timestamp* (TS1).** N2 memvalidasi bahwa selisih waktu balasan AS berada dalam toleransi (`TS_TOLERANCE`, bawaan 30 detik), menolak balasan basi (`ts1_stale`).

5. **Autentikasi asal pesan.** Perangkat memverifikasi tanda tangan AS (`APE1`, `APE2`) menggunakan kunci publik AS sebelum menerima balasan.

> **Catatan:** Poin 3 dan 4 (mekanisme berbasis waktu nyata) merupakan aspek yang **tidak dapat dimodelkan pada ProVerif** karena ketiadaan notasi waktu, sehingga simulasi ini melengkapi analisis formal.

---

## Membaca Log

Setiap entitas mencetak log berwarna ke konsol dan menuliskannya dalam format **JSONL** ke berkas `log_<peran>.jsonl`. Format konsol:

```
HH:MM:SS.mmm  LEVEL  ROLE  [sid]  pesan  reason=<kode>
```

- **LEVEL:** `INFO`, `STEP`, `SEND`, `RECV`, `OK`, `WARN`, `ERROR`.
- **sid:** ID sesi 4 heksadesimal untuk mengorelasikan satu penempelan lintas-terminal (AS, N1, N2).
- **reason:** kode alasan ringkas dan konsisten pada penolakan (mis. `replay_detected`, `sp_expired_n1`, `ts1_stale`).

Gunakan `sid` yang sama untuk menelusuri satu transaksi utuh di ketiga terminal.

---

## Batasan Simulasi

- Seluruh entitas berjalan pada `localhost` melalui TCP socket, **bukan** perangkat NFC fisik.
- Jenis serangan yang disimulasikan dibatasi pada **serangan *replay***, sesuai ruang lingkup penelitian.
- Penyadapan dimodelkan secara sederhana melalui berkas bersama `capture.bin` yang ditulis N1 dan dibaca penyerang.
- Mode enkripsi simetris menggunakan AES-256-CBC; untuk penerapan nyata dapat dipertimbangkan mode terautentikasi seperti AES-GCM.

---

## Referensi

- Lu, X., & Liu, Y. (2021). *A secure NFC device authentication protocol.* (Protokol yang disimulasikan dalam penelitian ini.)
- Python Cryptographic Authority. *cryptography* library. [https://cryptography.io/](https://cryptography.io/)
