# Analisis Formal Protokol Autentikasi Perangkat NFC Lu & Liu menggunakan ProVerif

Repositori ini berisi model formal protokol autentikasi perangkat *Near Field Communication* (NFC) yang diusulkan oleh **Lu & Liu (2021)**, yang ditulis dalam bahasa spesifikasi **ProVerif** (`.pv`). Model ini digunakan untuk memverifikasi properti keamanan protokol secara otomatis di bawah model penyerang **Dolev–Yao**, yaitu penyerang yang menguasai penuh saluran komunikasi publik (dapat menyadap, menghapus, memodifikasi, dan menyuntikkan pesan), namun tidak dapat memecahkan primitif kriptografi tanpa kunci yang sesuai.

> Penelitian ini merupakan bagian dari Tugas Akhir mengenai analisis keamanan formal protokol autentikasi perangkat NFC.

---

## Daftar Isi

- [Ringkasan](#ringkasan)
- [Berkas dalam Repositori](#berkas-dalam-repositori)
- [Prasyarat](#prasyarat)
- [Cara Menjalankan](#cara-menjalankan)
- [Struktur Model](#struktur-model)
  - [1. Deklarasi Tipe dan Primitif Kriptografi](#1-deklarasi-tipe-dan-primitif-kriptografi)
  - [2. Deklarasi Data dan Asumsi](#2-deklarasi-data-dan-asumsi)
  - [3. Query Keamanan](#3-query-keamanan)
  - [4. Event](#4-event)
  - [5. Makro Proses (Entitas)](#5-makro-proses-entitas)
  - [6. Proses Utama](#6-proses-utama)
- [Properti Keamanan yang Diverifikasi](#properti-keamanan-yang-diverifikasi)
- [Hasil Verifikasi](#hasil-verifikasi)
- [Cara Membaca Output ProVerif](#cara-membaca-output-proverif)
- [Batasan Model](#batasan-model)
- [Referensi](#referensi)

---

## Ringkasan

Protokol Lu & Liu melibatkan tiga entitas:

| Entitas | Keterangan |
| --- | --- |
| **N1** | Perangkat NFC pertama |
| **N2** | Perangkat NFC kedua (sekaligus bertindak sebagai perelai pesan menuju AS) |
| **AS** | *Authentication Server* (server autentikasi tepercaya) |

Protokol terdiri atas **dua fase**:

1. **Fase Pendaftaran (Registration):** Setiap perangkat (N1 dan N2) mendaftarkan diri ke AS. AS menyimpan identitas, *nonce*, dan kunci simetris perangkat ke dalam basis data internal.
2. **Fase Autentikasi (Authentication):** N1 dan N2 saling mengautentikasi melalui perantaraan AS, memanfaatkan data yang telah disimpan pada fase pendaftaran.

Model ini membuktikan **kerahasiaan** nilai-nilai sensitif dan **autentikasi timbal balik** (*mutual authentication*) antar-entitas, sekaligus **ketahanan terhadap serangan pengulangan** (*replay attack*).

---

## Berkas dalam Repositori

| Berkas | Keterangan |
| --- | --- |
| `protokol_lu_liu.pv` | Model formal protokol Lu & Liu dalam bahasa ProVerif |
| `README.md` | Dokumentasi penjelasan model (berkas ini) |

---

## Prasyarat

- **ProVerif** versi 2.05 atau yang lebih baru. Unduh dari [situs resmi ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/).
- Sistem operasi Linux, macOS, atau Windows (ProVerif tersedia untuk ketiganya).

---

## Cara Menjalankan

Jalankan perintah berikut pada terminal:

```bash
proverif protokol_lu_liu.pv
```

ProVerif akan mengevaluasi seluruh *query* yang dideklarasikan dan mencetak hasilnya (`true`, `false`, atau `cannot be proved`) untuk masing-masing properti.

Untuk menyimpan output ke sebuah berkas:

```bash
proverif protokol_lu_liu.pv > hasil_verifikasi.txt
```

---

## Struktur Model

### 1. Deklarasi Tipe dan Primitif Kriptografi

Model mendeklarasikan tipe khusus (`host`, `nonce`, `key`, `skey`, `pkey`) dan primitif kriptografi berikut:

| Primitif | Fungsi | Merepresentasikan |
| --- | --- | --- |
| `pk`, `aenc` / `adec` | Enkripsi asimetris | Enkripsi dengan kunci publik AS ($E_{puk}$) |
| `sign` / `checksign` | Tanda tangan digital | Pembuktian asal pesan dari AS ($E_{prk}$) |
| `senc` / `sdec` | Enkripsi simetris | Enkripsi dengan kunci simetris perangkat ($SK_i$) |
| `H` | Fungsi *hash* satu arah | Fungsi *hash* (tanpa destruktor, sehingga tidak dapat dibalik) |

Terdapat pula tiga *type converter* (`key_to_bitstring`, `host_to_bitstring`, `nonce_to_bitstring`) untuk mengubah nilai bertipe khusus menjadi `bitstring` agar dapat diproses oleh fungsi kriptografi.

> **Catatan penting:** Fungsi `H` dideklarasikan **tanpa** persamaan reduksi (destruktor). Ini memodelkan sifat *one-way* dari fungsi *hash*: penyerang tidak dapat memulihkan input dari nilai *hash*-nya.

### 2. Deklarasi Data dan Asumsi

```proverif
free IDN1, IDN2: host [private].
table database(host, nonce, key, nonce).
not attacker(new skAS).
```

- `IDN1`, `IDN2` dideklarasikan **`private`** sehingga identitas perangkat tidak diketahui penyerang sejak awal.
- `table database(...)` memodelkan basis data internal AS yang menyimpan `(identitas, nonce perangkat, kunci simetris, nonce AS)` untuk setiap perangkat terdaftar.
- `not attacker(new skAS)` merupakan **asumsi keamanan** eksplisit: penyerang tidak menguasai *private key* milik AS. Asumsi ini wajar karena kunci privat server memang harus dirahasiakan.

### 3. Query Keamanan

Model mendeklarasikan **16 query** yang terbagi menjadi dua kategori:

**a. Kerahasiaan (8 query):**

```proverif
query attacker(IDN1).
query attacker(IDN2).
query secret K1.
query secret K2.
query secret Rn1.
query secret Rn2.
query secret RnA1.
query secret RnA2.
```

Menguji apakah penyerang dapat memperoleh identitas perangkat ($IDN_1$, $IDN_2$), kunci simetris ($K_1$, $K_2$), *nonce* perangkat ($Rn_1$, $Rn_2$), dan *nonce* AS ($RnA_1$, $RnA_2$).

**b. Autentikasi / Correspondence (8 query):**

Menggunakan *correspondence assertion* berbentuk `event(A) ==> event(B)` yang berarti "jika kejadian A terjadi, maka kejadian B pasti telah terjadi sebelumnya". Untuk setiap perangkat (N1 dan N2) pada setiap fase (pendaftaran dan autentikasi), terdapat dua bentuk:

- **Non-injective** (`event ==> event`): menjamin adanya pengiriman yang mendahului setiap penerimaan.
- **Injective** (`inj-event ==> inj-event`): menjamin hubungan **satu-ke-satu** antar-sesi, sehingga sebuah pesan tidak dapat digunakan ulang. Inilah yang membuktikan **ketahanan terhadap serangan pengulangan (*replay*)**.

### 4. Event

*Event* adalah penanda titik-titik penting dalam eksekusi protokol, digunakan sebagai dasar *query correspondence*. Contoh: `N1_reg_sends` (N1 mengirim permintaan pendaftaran), `AS_reg_accepts_N1` (AS menerima permintaan pendaftaran N1), dan seterusnya untuk kedua perangkat pada kedua fase.

### 5. Makro Proses (Entitas)

Model mendefinisikan lima makro proses yang merepresentasikan perilaku setiap entitas:

| Proses | Peran |
| --- | --- |
| `processN1` | Perilaku perangkat N1 (pendaftaran + autentikasi) |
| `processN2` | Perilaku perangkat N2 (pendaftaran + autentikasi + perelaian pesan) |
| `processAS_Registration_N1` | AS memproses pendaftaran N1 |
| `processAS_Registration_N2` | AS memproses pendaftaran N2 |
| `processAS_Authentication` | AS memproses autentikasi timbal balik N1 & N2 |

### 6. Proses Utama

```proverif
process
    new skAS: skey;
    let pkAS = pk(skAS) in
    out(c, pkAS);
    (
        (!processN1(pkAS)) |
        (!processN2(pkAS)) |
        (!processAS_Registration_N1(skAS)) |
        (!processAS_Registration_N2(skAS)) |
        (!processAS_Authentication(skAS))
    )
```

AS membangkitkan pasangan kunci, lalu mempublikasikan kunci publik `pkAS` ke saluran publik. Seluruh proses dijalankan secara paralel dan diawali operator replikasi (`!`), sehingga ProVerif menganalisis protokol pada **jumlah sesi tak terbatas**.

---

## Properti Keamanan yang Diverifikasi

| No. | Properti | Jenis Query | Jumlah |
| --- | --- | --- | --- |
| 1 | Kerahasiaan identitas perangkat ($IDN_1$, $IDN_2$) | `attacker()` | 2 |
| 2 | Kerahasiaan kunci simetris ($K_1$, $K_2$) | `secret` | 2 |
| 3 | Kerahasiaan *nonce* perangkat ($Rn_1$, $Rn_2$) | `secret` | 2 |
| 4 | Kerahasiaan *nonce* AS ($RnA_1$, $RnA_2$) | `secret` | 2 |
| 5 | Autentikasi pendaftaran (non-injective & injective) | `correspondence` | 4 |
| 6 | Autentikasi timbal balik (non-injective & injective) | `correspondence` | 4 |
| | **Total** | | **16** |

---

## Hasil Verifikasi

Seluruh **16 query bernilai `true`**, yang berarti:

- **Kerahasiaan terpenuhi** — penyerang tidak dapat memperoleh identitas, kunci simetris, maupun *nonce* apa pun.
- **Autentikasi timbal balik terpenuhi** — setiap penerimaan pesan benar-benar didahului oleh pengiriman yang sah.
- **Tahan serangan pengulangan (*replay*)** — dibuktikan oleh keberhasilan seluruh *query* berbentuk `inj-event`.

Dengan demikian, klaim keamanan yang dinyatakan Lu & Liu **terbukti terpenuhi** dalam batasan model yang dirancang.

---

## Cara Membaca Output ProVerif

Untuk setiap query, ProVerif mencetak salah satu dari:

- `RESULT ... is true` — properti **terpenuhi** (aman).
- `RESULT ... is false` — properti **dilanggar**; ProVerif akan menampilkan jejak serangan (*attack trace*).
- `RESULT ... cannot be proved` — ProVerif tidak dapat menyimpulkan (bukan berarti tidak aman).

Baris `secrecy assumption verified: fact unreachable attacker(skAS[])` mengonfirmasi bahwa asumsi kerahasiaan *private key* AS berlaku sepanjang analisis.

---

## Batasan Model

- **Serangan *brute force* tidak diuji.** ProVerif bekerja pada model simbolik dengan asumsi kriptografi sempurna, sehingga tidak dapat memodelkan penyerang yang mencoba banyak kombinasi kunci.
- **Jumlah perangkat pada fase pendaftaran dibatasi dua** (N1 dan N2), sesuai ruang lingkup penelitian.
- **Aspek berbasis waktu** (seperti *timestamp* `TS1` dan *survival period* `SP`) hanya dimodelkan secara simbolik; validasi kesegaran berbasis waktu nyata dilakukan pada simulasi terpisah menggunakan Python.

---

## Referensi

- Lu, X., & Liu, Y. (2021). *A secure NFC device authentication protocol.* (Protokol yang dianalisis dalam penelitian ini.)
- Blanchet, B. *ProVerif: Cryptographic protocol verifier in the formal model.* [https://bblanche.gitlabpages.inria.fr/proverif/](https://bblanche.gitlabpages.inria.fr/proverif/)
- Dolev, D., & Yao, A. (1983). *On the security of public key protocols.* IEEE Transactions on Information Theory.
