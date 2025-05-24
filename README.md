# 🔎 EnhancedPortScanner

A powerful and modern **TCP/UDP Hybrid Port Scanner** with a light-themed GUI, automatic local IP detection, scan profiles, geolocation lookup, vulnerability warnings, and exportable reports.

Built in Python with `Tkinter`, this tool makes network scanning **user-friendly, educational, and effective** for aspiring cybersecurity professionals.

---

## 🚀 Features

- **Hybrid Scanning**: Supports TCP, UDP, and Both protocols.
- **Scan Profiles**:
  - `Quick`: Common vulnerable ports.
  - `Web`: HTTP/S and common web ports.
  - `Full`: Ports 1–1024.
  - `Custom`: Define your own port range.
- **Geolocation & ISP Lookup**: Shows country, ISP, and AS info for target IP.
- **Vulnerability Warnings**: Flags high-risk ports (RDP, SMB, Telnet, etc.).
- **Progress Bar & Threading**: Fast scans with multithreaded architecture.
- **Dark-Themed GUI**: Built with `ttk` for a modern user interface.
- **Export Options**: Save results as `.CSV` or `.JSON`.
- **Responsive UI**: Scrollable interface works on small and fullscreen windows.

---

## 🛠 Technologies Used

- `Python 3.11+`
- `Tkinter (ttk)` – GUI framework
- `Socket`, `Threading`, `Queue` – Core networking & threading
- `Requests` – IP geolocation API
- `CSV`, `JSON` – Report export formats

---


## 📦 How to Run

1. Clone the repo:

   ```bash
   git clone https://github.com/JoshuaHarlee/EnhancedPortScanner.git
   cd EnhancedPortScanner
