# Warden EDR 🛡️🦀

A lightweight, high-performance **Endpoint Detection and Response (EDR)** agent and **Process Memory Anomaly Hunter** engineered in **Rust** for Linux systems.

Provides real-time process memory inspection (`/proc`), anomalous executable mapping detection (`rwx` regions without disk backing), hidden process hunting, and cryptographic File Integrity Monitoring (FIM).

---

## 🏛️ Architecture & Threat Matrix

```text
Linux Kernel Subsystems (/proc, vfs, inotify)
          │
          ├──► [ Memory Region Scanner ] ── (Detects unbacked RWX mappings & shellcode injection)
          │
          ├──► [ Process Hierarchy Hunter ] ── (Detects orphaned & masquerading daemon anomalies)
          │
          └──► [ SHA-256 FIM Engine ]   ──► Cryptographic baseline check on /etc, /bin, cron
                     │
                     ▼
          [ Security Alert Dispatcher ] (Structured JSON & Syslog IOC telemetry)
```

---

## 🌟 Key Capabilities

- **Shellcode & In-Memory Injection Detection**: Traverses `/proc/[pid]/maps` looking for suspicious memory pages marked `rwx` that lack backing binary file descriptors (classic signature of reflective DLL / ELF loaders and staged shellcode).
- **Process Masquerading & Parent-Child Anomalies**: Audits `/proc/[pid]/stat` and `cmdline` to flag binary name spoofing and suspicious parentage (e.g. web server spawning `/bin/sh`).
- **Cryptographic File Integrity Monitoring (FIM)**: Generates SHA-256 baseline hashes across critical system directories (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/cron*`) to detect unauthorized modifications and persistence implants.
- **Minimal System Overhead**: Written in idiomatic Rust with zero runtime dependencies and predictable memory constraints.

---

## 📂 Project Structure

```text
warden-edr/
├── Cargo.toml             # Configuration & crates
├── src/
│   ├── lib.rs             # Public exports
│   ├── process.rs         # /proc memory maps parser & injection detector
│   ├── fim.rs             # SHA-256 File Integrity Monitoring engine
│   ├── alert.rs           # Security alerts & threat severity models
│   ├── engine.rs          # Core EDR audit coordinator
│   └── main.rs            # CLI tool
└── README.md
```

---

## 🚀 Quickstart

### Inspect Active Processes for Memory Injection:
```bash
cargo run --release -- scan-processes
```

### Build & Audit System File Integrity Baseline:
```bash
cargo run --release -- fim-create --path /etc/passwd --output baseline.json
cargo run --release -- fim-verify --baseline baseline.json
```

---

## 📜 License
MIT License • Engineered by [Lazarus Ebi](https://github.com/0xlazorr)
