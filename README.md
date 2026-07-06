# Analisis Keamanan Formal dan Simulasi Protokol Autentikasi Perangkat NFC Lu & Liu

Repositori ini berisi artefak penelitian Tugas Akhir mengenai **analisis keamanan protokol autentikasi perangkat *Near Field Communication* (NFC) yang diusulkan oleh Lu & Liu**. Penelitian dilakukan melalui dua pendekatan yang saling melengkapi:

1. **Analisis formal** menggunakan **ProVerif** untuk membuktikan properti keamanan protokol secara matematis di bawah model penyerang Dolev–Yao.
2. **Simulasi** menggunakan **Python** untuk memvisualisasikan jalannya protokol dengan algoritma kriptografi nyata dan mendemonstrasikan ketahanannya terhadap serangan pengulangan (*replay attack*).

---

## Latar Belakang Singkat

Protokol Lu & Liu mengeklaim mampu menjamin kerahasiaan, autentikasi timbal balik (*mutual authentication*), serta ketahanan terhadap serangan tertentu pada proses autentikasi perangkat NFC. Penelitian ini bertujuan **membuktikan kebenaran klaim tersebut** melalui verifikasi formal, sekaligus memberikan gambaran konkret cara kerja protokol melalui simulasi.

Protokol melibatkan tiga entitas — dua perangkat NFC (**N1** dan **N2**) serta sebuah **Authentication Server (AS)** — dan terdiri atas dua fase: **pendaftaran (*registration*)** dan **autentikasi (*authentication*)**.

---

## Struktur Repositori

```
.
├── README.md                    ← dokumen ini (gambaran keseluruhan)
├── LICENSE
├── .gitignore
│
├── proverif/                    ← model formal & verifikasi
│   ├── protokol_lu_liu.pv
│   └── README.md
│
└── simulasi-python/             ← simulasi protokol
    ├── protokol.py
    ├── as_server.py
    ├── n1_device.py
    ├── n2_device.py
    ├── attacker_device.py
    └── README.md
```

---

## Dua Komponen Penelitian

### 1. Analisis Formal (ProVerif) — [`proverif/`](proverif/)

Model formal protokol Lu & Liu dalam bahasa ProVerif, mencakup pemetaan setiap persamaan protokol ke *pi calculus*, deklarasi 16 *query* keamanan, dan proses seluruh entitas yang dijalankan pada jumlah sesi tak terbatas.

**Hasil:** seluruh **16 *query* bernilai `true`** — membuktikan kerahasiaan, autentikasi timbal balik, dan ketahanan terhadap serangan *replay*.

Lihat [`proverif/README.md`](proverif/README.md) untuk penjelasan lengkap dan cara menjalankan.

### 2. Simulasi (Python) — [`simulasi-python/`](simulasi-python/)

Implementasi konkret protokol menggunakan RSA-2048, AES-256-CBC, dan SHA-256, dengan empat entitas yang berkomunikasi melalui TCP socket. Simulasi memperagakan skenario autentikasi normal serta demonstrasi penolakan serangan *replay*, sekaligus memvalidasi mekanisme berbasis waktu (*timestamp* dan *survival period*) yang tidak dapat dimodelkan pada ProVerif.

Lihat [`simulasi-python/README.md`](simulasi-python/README.md) untuk penjelasan lengkap dan cara menjalankan.

---

## Ringkasan Hasil

| Aspek | ProVerif | Simulasi Python |
| --- | --- | --- |
| Kerahasiaan (identitas, kunci, *nonce*) | Terbukti (8 *query* `true`) | — |
| Autentikasi timbal balik | Terbukti (8 *query* `true`) | Alur terverifikasi ujung-ke-ujung |
| Ketahanan serangan *replay* | Terbukti (*injective correspondence*) | Serangan ditolak (`replay_detected`) |
| Mekanisme berbasis waktu (SP, TS1) | Tidak dapat dimodelkan | Divalidasi |
| Serangan *brute force* | Tidak diuji (keterbatasan alat) | Tidak diuji |

---

## Cara Memulai

Setiap komponen memiliki petunjuk penggunaannya sendiri:

- **Verifikasi formal:** buka [`proverif/`](proverif/) — memerlukan ProVerif ≥ 2.05.
- **Menjalankan simulasi:** buka [`simulasi-python/`](simulasi-python/) — memerlukan Python 3.8+ dan pustaka `cryptography`.

---

## Batasan Penelitian

- Serangan *brute force* tidak diuji karena ProVerif tidak dapat memodelkan percobaan banyak kombinasi kunci.
- Jumlah perangkat NFC pada fase pendaftaran dibatasi dua (N1 dan N2).
- Serangan yang disimulasikan pada Python hanya serangan *replay*.

---

## Referensi

- Lu, X., & Liu, Y. (2021). *A secure NFC device authentication protocol.*
- Blanchet, B. *ProVerif: Cryptographic protocol verifier in the formal model.* [https://bblanche.gitlabpages.inria.fr/proverif/](https://bblanche.gitlabpages.inria.fr/proverif/)
- Dolev, D., & Yao, A. (1983). *On the security of public key protocols.* IEEE Transactions on Information Theory.

---

## Penulis

Raihan Fitrah Hanafi
