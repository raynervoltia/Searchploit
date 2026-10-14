# Searchploit 🚀

**Exploit-DB Live Extractor & Vulnerability Intelligence Engine**

Searchploit adalah tool CLI & interactive engine untuk mengekstrak, mencari, menganalisis, dan mengunduh exploit terbaru dari database resmi **Exploit-DB** (secara live melalui RSS feed dan sinkronisasi arsip lengkap GitLab).

---

## Fitur Utama

- ⚡ **Live RSS Extractor**: Mengambil rilis exploit terbaru langsung dari server Exploit-DB secara real-time.
- 🗄️ **High-Speed SQLite Database**: Mengindeks 45.000+ exploit untuk pencarian sub-millisecond tanpa lag.
- 🎯 **Multi-Filtering**: Filter berdasarkan kategori (`webapps`, `remote`, `local`, `dos`, `papers`), platform (`php`, `python`, `linux`, `windows`, dll), atau nomor CVE.
- 👁️ **Instant Source Code Viewer (`--cat` / `-x`)**: Membaca kode exploit langsung di layar terminal.
- ⬇️ **Direct Code Downloader (`--download` / `-d`)**: Mengunduh file exploit ke folder lokal (`./downloads/`).
- 🎨 **Terminal UI & Interactive Menu**: Tampilan berwarna ANSI dengan menu interaktif ramah pengguna.
- 🪶 **Zero Dependency**: Berjalan langsung menggunakan pustaka standar Python 3 (tanpa perlu install pip library tambahan).

---

## Cara Instalasi & Menjalankan

Tidak perlu install dependency eksternal, cukup gunakan Python 3:

```bash
cd /root/searchploit
chmod +x searchploit.py
```

### 1. Mode Interaktif (Tampilan Menu)
Jalankan tanpa argumen:
```bash
python3 searchploit.py
```

### 2. Update / Inisialisasi Database
Mengunduh dan menyinkronkan 45.000+ data exploit terbaru:
```bash
python3 searchploit.py -u
```

### 3. Cek Exploit Terbaru Secara Live (RSS Feed)
Melihat rilisan teranyar yang baru saja di-publish hari ini:
```bash
python3 searchploit.py --live
```

### 4. Tampilkan N Exploit Terbaru dari Database
```bash
python3 searchploit.py -l 25
```

### 5. Pencarian Berdasarkan Keyword atau CVE
```bash
# Berdasarkan keyword
python3 searchploit.py -s "wordpress"
python3 searchploit.py -s "spring boot"

# Berdasarkan CVE ID
python3 searchploit.py --cve "CVE-2024"
```

### 6. Filter Berdasarkan Kategori & Platform
```bash
# Hanya kategori webapps
python3 searchploit.py -t webapps

# Hanya platform PHP
python3 searchploit.py -p php

# Kombinasi (Webapps + PHP)
python3 searchploit.py -t webapps -p php -l 20
```

### 7. Melihat Detail & Membaca Kode Exploit
```bash
# Tampilkan detail metadata
python3 searchploit.py -i 52692

# Baca source code langsung di terminal
python3 searchploit.py -x 52692
```

### 8. Download Kode Exploit ke Folder Lokal
```bash
python3 searchploit.py -d 52692
# File akan otomatis tersimpan di folder downloads/
```

### 9. Cek Statistik Database
```bash
python3 searchploit.py --stats
```

---

## Struktur Folder Project

```text
/root/searchploit/
├── searchploit.py      # Entrypoint CLI & Interactive menu
├── requirements.txt    # Dokumen dependensi (built-in)
├── README.md           # Petunjuk penggunaan
├── core/
│   ├── db.py           # SQLite storage & indexing engine
│   ├── extractor.py    # Live RSS parser & GitLab downloader
│   └── display.py      # Terminal UI & formatting badges
└── data/               # Cache lokal (files_exploits.csv & exploits.db)
```
