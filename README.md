# SigCheck – Windows File Signature & Hash Checker

Tool berbasis Python untuk memeriksa digital signature, publisher, metadata, dan hash file pada Windows menggunakan Authenticode serta CIRCL Hashlookup API.

## Features

- **Authenticode Verification** – Memeriksa keaslian digital signature menggunakan Windows PowerShell.
- **Publisher Verification** – Membandingkan publisher dengan daftar publisher tepercaya.
- **Certificate Information** – Menampilkan informasi sertifikat, issuer, thumbprint, masa berlaku, dan timestamp.
- **Certificate Chain Diagnostics** – Memeriksa diagnostik rantai sertifikat.
- **File Hashing** – Menghitung MD5, SHA-1, dan SHA-256.
- **Online Hash Lookup** – Mengecek SHA-256 melalui CIRCL Hashlookup API.
- **File Metadata** – Menampilkan informasi perusahaan, deskripsi, versi, ukuran, dan nama produk.
- **Process Scanning** – Memeriksa modul yang digunakan oleh proses berdasarkan PID.
- **Kernel Driver Scanning** – Memeriksa driver Windows yang sedang dimuat.
- **JSON Report** – Menyimpan hasil pemeriksaan dalam format JSON.

## Requirements

- Windows 10 / Windows 11
- Python 3.x
- Windows PowerShell
- Koneksi internet untuk CIRCL Hashlookup API

### Python Dependencies

Install dependency berikut untuk menggunakan fitur process scanning:

```bash
py -m pip install psutil
```

## Installation

Clone repository:

```bash
git clone https://github.com/pradiptanararayaa/digitalsign-checker
```

Masuk ke direktori:

```bash
cd digitalsign-checker
```

Jalankan program:

```bash
py check.py
```

## Usage

### Interactive Mode

```bash
py check.py
```

Program akan menampilkan menu interaktif untuk memilih jenis pemindaian.

### Scan Single File

```bash
py check.py "C:\Users\User\Desktop\sample.dll"
```

### Scan Directory

```bash
py check.py "C:\Windows\System32"
```

### Scan Multiple Files

```bash
py check.py "C:\Path\file1.dll" "C:\Path\file2.exe"
```

### Scan Loaded Kernel Drivers

```bash
py check.py --drivers
```

### Scan Process by PID

```bash
py check.py --pid 1234
```

### JSON Output

```bash
py check.py "C:\Path\sample.dll" --json
```

### Show Only Suspicious Results

```bash
py check.py "C:\Path\folder" --only-bad
```

### Save Scan Report

```bash
py check.py "C:\Path\folder" --save report.json
```

### Custom Configuration

```bash
py check.py "C:\Path\folder" --config trust.json
```

## Detection Results

| Status | Description |
|---|---|
| `TRUSTED` | Signature valid dan publisher cocok dengan daftar tepercaya. |
| `VALID_SIGNATURE` | Signature valid, tetapi publisher belum masuk daftar tepercaya. |
| `UNSIGNED` | File tidak memiliki Authenticode signature. |
| `HASH_MISMATCH` | Hash file tidak cocok dengan signature. |
| `NOT_TRUSTED` | Windows tidak mempercayai signature. |
| `UNKNOWN` | Windows tidak dapat menentukan status signature. |
| `ERROR` | Terjadi kesalahan saat pemeriksaan. |
| `BLOCKED_CERTIFICATE` | Sertifikat ditemukan dalam blocklist. |
| `KNOWN_VULNERABLE_DRIVER` | Driver cocok dengan daftar driver rentan yang dikonfigurasi. |

## CIRCL Hashlookup API

SigCheck menggunakan CIRCL Hashlookup untuk melakukan pencocokan SHA-256 terhadap database file yang dikenal.

API endpoint:

```text
https://hashlookup.circl.lu/lookup/sha256/{sha256}
```

### Lookup Results

| Status | Description |
|---|---|
| `FOUND` | Hash ditemukan dalam database CIRCL. |
| `NOT_FOUND` | Hash tidak ditemukan dalam database. |
| `API_ERROR` | Terjadi kesalahan saat mengakses API. |

**Privacy:** File tidak diunggah ke CIRCL. Program hanya mengirimkan nilai SHA-256 untuk pencocokan.

> Hash ditemukan bukan berarti file pasti aman. Hash tidak ditemukan juga bukan berarti file merupakan malware.

## File Metadata

Informasi yang dikumpulkan meliputi:

- File Description
- Company Name
- Product Name
- File Version
- Product Version
- Original Filename
- Internal Name
- File Size
- Last Modified Time

## Configuration

Program mendukung konfigurasi opsional melalui `trust.json`.

Contoh:

```json
{
  "trusted_publishers": {
    "Example Publisher Ltd.": []
  },
  "blocklist_thumbprints": [
    "CERTIFICATE_THUMBPRINT"
  ],
  "known_vulnerable_drivers": [
    "example.sys"
  ]
}
```

Jangan memasukkan publisher ke daftar tepercaya sebelum melakukan verifikasi.

## Important Notes

- Status signature diperoleh melalui Windows Authenticode.
- Publisher yang cocok dengan allowlist tidak otomatis menjamin file aman.
- File unsigned tidak otomatis berarti malware.
- Hasil hash lookup bergantung pada database CIRCL.
- Jalankan sebagai Administrator jika membutuhkan akses pemindaian proses atau driver tertentu.
