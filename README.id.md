# MirageSSH: SSH Honeypot Berbasis AI & Forensik Tarpit

<div align="center">

```
  __  __ _                    ____ ____  _   _ 
 |  \/  (_)_ __ __ _  __ _  / ___/ ___|| | | |
 | |\/| | | '__/ _` |/ _` | \___ \___ \| |_| |
 | |  | | | | | (_| | (_| |  ___) |__) |  _  |
 |_|  |_|_|_|  \__,_|\__, | |____/____/|_| |_|
                      |___/                    
```

**Honeypot SSH Adaptif Generasi Baru dengan Fake Shell Cerdas (LLM Responder), Virtual Filesystem In-Memory, Deception Tarpit, dan Telemetri Real-Time MITRE ATT&CK®.**

[![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen?style=for-the-badge&logo=githubactions&logoColor=white)](.github/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](Dockerfile)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red?style=for-the-badge&logo=target&logoColor=white)](https://attack.mitre.org/)

[English](README.md) • [Bahasa Indonesia](README.id.md)

</div>

---

## 🌟 Ringkasan Proyek

**MirageSSH** adalah server SSH palsu (honeypot) tingkat menengah-ke-atas (*medium-to-high interaction*) yang dirancang khusus untuk memikat, mencatat, dan menganalisis perilaku peretas (hacker/botnet).

Berbeda dari honeypot konvensional yang hanya memberikan jawaban statis atau error "command not found", **MirageSSH** memadukan:
1. **Virtual File System (VFS) In-Memory**: Sistem berkas Linux asli (Ubuntu 22.04 LTS) yang aman dari risiko *container escape* atau peretasan server riil.
2. **AI Dynamic Shell Responder (Google Gemini / OpenAI / Heuristik Offline)**: Menghasilkan output terminal Linux yang 100% realistis dan kontekstual untuk perintah-perintah kompleks, unduhan payload (`curl`/`wget`), script exploit, maupun pencarian celah sistem (*privilege escalation*).
3. **Sticky Tarpit Throttling**: Memberikan jeda waktu buatan (*latency deception*) pada perintah agresif agar penyerang betah berlama-lama, menguras sumber daya mereka, dan memberi waktu bagi tim analis keamanan (SOC) untuk melacak pergerakan mereka.
4. **Perekaman Sesi Asciinema v2 (`.cast`)**: Menyimpan rekaman ketikan peretas frame-demi-frame sehingga dapat diputar ulang layaknya menonton video di terminal maupun browser.
5. **Jebakan Honeytoken**: Berkas umpan sensitif (`.env`, `id_rsa`, `shadow`, database dump) yang jika dibuka oleh penyerang akan langsung membunyikan alarm insiden darurat ke Discord/Telegram.
6. **Web SOC Dashboard Real-Time**: Dasbor pemantauan bergaya Cyberpunk/SOC gelap dengan metrik interaktif, peta negara asal, dan integrasi kerangka kerja **MITRE ATT&CK®**.

---

## ⚔️ Perbandingan: Mengapa MirageSSH?

| Fitur | MirageSSH | Cowrie Biasa | Docker/VM Asli |
|---|---|---|---|
| **Keamanan Isolasi** | **100% Sandbox In-Memory** (Bebas risiko breakout) | Sedang | ⚠️ Berisiko Tinggi (Bisa dijadikan sarang malware/DDoS) |
| **Realisme Output** | **Sangat Nyata (AI LLM + Local Engine)** | Statis/Kaku | 100% (OS Nyata) |
| **Perintah Kompleks/Aneh** | **Dijawab meyakinkan oleh AI** | "command not found" (Membocorkan honeypot) | Dieksekusi nyata |
| **Putar Ulang Sesi** | **Format Asciinema v2 (`.cast`) + Web Player** | Format kustom | Perlu auditd / ttylog |
| **Jebakan Honeytoken** | **Bawaan (.env, id_rsa, db_dump, AWS)** | Perlu setting manual | Perlu setting manual |
| **Klasifikasi MITRE ATT&CK** | **Otomatis & Real-time (T1033, T1082, dll.)** | Tidak ada | Butuh SIEM eksternal |
| **SOC Dashboard Web** | **Bawaan (FastAPI + Dark Theme + Chart.js)** | Butuh ELK Stack | Butuh Grafana/Splunk |
| **Bisa Offline** | **Ya, ada fallback heuristik cerdas tanpa API key** | N/A | N/A |

---

## 🚀 Fitur Unggulan

### 1. 🧠 Mesin Eksekusi Hibrida (Fast-Path + AI Responder)
- Perintah umum sehari-hari (`ls`, `cd`, `cat`, `whoami`, `id`, `uname`, `ps`, `top`, `uptime`, `ip a`, `ping`, `echo > file`) dieksekusi secara instan (< 1 milidetik) oleh mesin internal.
- Perintah yang tidak dikenal, script panjang, exploit, atau percobaan instalasi paket secara otomatis diteruskan ke Google Gemini API untuk menghasilkan keluaran terminal yang meyakinkan tanpa membocorkan identitas AI.
- Jika API key tidak diisi atau kuota habis, sistem secara otomatis beralih ke mesin heuristik offline.

### 2. 🪤 Umpan Honeytoken (Tripwire Kredensial Palsu)
Dilengkapi dengan berkas-berkas umpan menarik (*juicy targets*):
- `/home/ubuntu/.env`: Kunci AWS palsu, Stripe secret key, dan password database produksi.
- `/home/ubuntu/.aws/credentials`: Kredensial AWS CLI palsu.
- `/root/.ssh/id_rsa`: Jebakan kunci privat SSH root.
- `/etc/shadow`: Hash kata sandi palsu untuk memancing serangan *cracking*.
- `/var/backups/prod_database.sql`: Cadangan database PostgreSQL berisi data kartu kredit samaran.

*Setiap akses baca atau ubah pada berkas ini langsung memicu notifikasi peringatan KRITIS.*

### 3. ⏳ Tarpit Deception (Jebakan Lengket)
- Memperlambat respons terminal secara dinamis (0.2 detik hingga 2.5 detik) ketika penyerang menjalankan perintah pemindaian agresif seperti `nmap`, pencarian berkas SUID, atau *dumping shadow*.
- Trik ini membuat botnet atau hacker manual tertahan berlama-lama tanpa curiga, memaksimalkan data intelijen ancaman yang terkumpul.

### 4. 🎯 Pemetaan Otomatis Kerangka Kerja MITRE ATT&CK®
Setiap perintah dikategorikan langsung ke dalam taktik dan teknik MITRE:
- **T1033**: System Owner/User Discovery (`whoami`, `id`)
- **T1082**: System Information Discovery (`uname -a`, `cat /proc/version`)
- **T1016**: System Network Configuration Discovery (`ip a`, `netstat`)
- **T1087**: Account Discovery (`cat /etc/passwd`)
- **T1003**: OS Credential Dumping (`cat /etc/shadow`)
- **T1552**: Unsecured Credentials in Files (`.env`, `id_rsa`)
- **T1105**: Ingress Tool Transfer (`curl`, `wget`)
- **T1059**: Command & Scripting Interpreter (Reverse shell, bash dropper)

### 5. 📼 Rekaman Terminal Asciinema v2 (`.cast`)
Setiap ketikan dan respons terminal disimpan lengkap dengan stempel waktu milidetik. Anda dapat memutar ulang aksi peretas di terminal:
```bash
asciinema play data/recordings/<session_id>.cast
```

### 6. 📊 Web SOC Dashboard Real-Time
Akses melalui peramban web di port `8080`:
- Pemantauan sesi aktif secara langsung.
- Peta sebaran negara asal penyerang beserta nama ISP/ASN.
- Grafik batang frekuensi teknik MITRE ATT&CK.
- Modal forensik interaktif untuk menginspeksi perintah dan respons terminal peretas.

---

## ⚡ Panduan Instalasi & Menjalankan

### Opsi 1: Menjalankan dengan Docker Compose (Sangat Direkomendasikan)

1. **Clone repository:**
   ```bash
   git clone https://github.com/yourusername/miragessh.git
   cd miragessh
   ```

2. **Salin berkas konfigurasi lingkungan:**
   ```bash
   cp .env.example .env
   # Masukkan GEMINI_API_KEY atau DISCORD_WEBHOOK_URL jika ingin menggunakan AI Gemini & notifikasi
   ```

3. **Jalankan dengan 1 perintah:**
   ```bash
   docker compose up -d
   ```

4. **Buka Dasbor SOC:**
   Kunjungi browser di `http://localhost:8080`

---

### Opsi 2: Menjalankan Langsung dengan Python

1. **Clone dan masuk ke direktori:**
   ```bash
   git clone https://github.com/yourusername/miragessh.git
   cd miragessh
   ```

2. **Buat dan aktifkan Virtual Environment:**
   ```bash
   python -m venv venv
   # Linux / macOS:
   source venv/bin/activate
   # Windows:
   .\venv\Scripts\activate
   ```

3. **Pasang pustaka dependensi:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Jalankan MirageSSH:**
   ```bash
   python -m miragessh
   ```

---

## 🧪 Uji Coba: Simulasi Serangan Peretas Otomatis

MirageSSH menyertakan skrip simulasi serangan bawaan untuk mendemonstrasikan perilaku peretas secara langsung:

```bash
python scripts/demo_attack.py 127.0.0.1 2222
```

Skrip ini akan login ke honeypot, melakukan *reconnaissance*, mencari berkas SUID, membuka berkas `.env` (memicu Honeytoken), mencoba mengunduh malware dengan `curl`, lalu memutuskan sambungan. Anda bisa melihat dasbor web terupdate secara langsung!

---

## 📂 Struktur Direktori Proyek

```
miragessh/
├── .github/workflows/ci.yml      # Otomasi pengujian CI GitHub Actions
├── config/
│   ├── default_config.yaml       # Konfigurasi utama honeypot
│   └── vfs_manifest.json         # Struktur berkas virtual Linux & Honeytoken
├── data/
│   ├── logs/                     # Berkas log JSONL & log audit teks
│   ├── recordings/               # Rekaman sesi Asciinema (.cast)
│   └── host_keys/                # Kunci host SSH (dibuat otomatis)
├── src/
│   └── miragessh/
│       ├── __init__.py
│       ├── __main__.py           # Entry point: python -m miragessh
│       ├── cli.py                # Banner dan parser argumen terminal
│       ├── server/               # Daemon server SSH Paramiko & Tarpit
│       ├── shell/                # Virtual File System (VFS) & perintah Linux lokal
│       ├── ai/                   # Integrasi Gemini, OpenAI, & Mock heuristik
│       ├── telemetry/            # MITRE ATT&CK, Asciinema, Honeytoken, GeoIP
│       └── web/                  # Backend FastAPI & template dasbor SOC
├── scripts/
│   ├── demo_attack.py            # Skrip otomatis simulasi serangan hacker
│   └── generate_keys.py          # Generator kunci RSA mandiri
├── tests/                        # Pengujian unit otomatis Pytest (100% Lulus)
├── Dockerfile                    # Container produksi multi-stage
├── docker-compose.yml            # Orkes penyebaran 1 perintah
├── requirements.txt              # Daftar pustaka Python
├── pyproject.toml                # Standar paket Python modern
└── LICENSE                       # Lisensi MIT
```

---

## 🔒 Etika & Penafian Keamanan

> [!CAUTION]
> **Hanya untuk Riset Pertahanan Siber Legal**: MirageSSH dirancang untuk tujuan edukasi, riset forensik, dan pemantauan intelijen ancaman pada jaringan yang Anda miliki secara sah atau telah memiliki izin tertulis. Jangan pernah menggunakan honeypot untuk tujuan menjebak secara ilegal tanpa otorisasi organisasi yang tepat.

---

## 📄 Lisensi

Proyek ini dilisensikan di bawah lisensi resmi [MIT License](LICENSE).
