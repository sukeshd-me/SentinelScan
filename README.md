# SentinelScan — File Safety & Malware Analysis Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)
[![Architecture](https://img.shields.io/badge/Architecture-Zero--Execution-purple.svg)](#zero-execution-architecture)
[![Testing](https://img.shields.io/badge/Tests-16%2F16%20Passed-success.svg)](#running-automated-tests)
[![Security](https://img.shields.io/badge/Security-5--Min%20Shredding-red.svg)](#automated-file-shredding--hygiene)

**SentinelScan** is a high-performance, open-source static file safety and malware analysis platform. Engineered from the ground up on a **Zero-Execution Architecture**, SentinelScan dissects, inspects, and evaluates suspicious files without running untrusted code on the host system.

From PE/ELF binaries and Microsoft Office documents to PDFs, Android APKs, archives, and multi-syntax scripts, SentinelScan extracts critical telemetry, calculates cryptographic fingerprints, detects heuristic anomalies, calculates Shannon entropy, tests for evasion techniques, and calculates a deterministic 0–100 threat score.

---

## Table of Contents

- [Key Capabilities & What It Can Do](#key-capabilities--what-it-can-do)
- [Zero-Execution Architecture](#zero-execution-architecture)
- [Analyzer Pipeline Breakdown](#analyzer-pipeline-breakdown)
  - [PE32 / PE32+ (Windows Portable Executables)](#1-pe32--pe32-windows-portable-executables)
  - [ELF (Linux Executables)](#2-elf-linux-executables)
  - [PDF Documents](#3-pdf-documents)
  - [Office Documents (OpenXML & OLE)](#4-office-documents-openxml--ole)
  - [Archives & Compressed Files](#5-archives--compressed-files)
  - [Android APKs](#6-android-apks)
  - [Scripts & Web Markup](#7-scripts--web-markup)
  - [Antivirus Engine (ClamAV Streaming)](#8-antivirus-engine-clamav-streaming)
- [Deterministic Scoring Engine & Threat Matrix](#deterministic-scoring-engine--threat-matrix)
- [Automated File Shredding & Hygiene](#automated-file-shredding--hygiene)
- [Large File Resiliency (Chunked Transfer up to 1GB)](#large-file-resiliency-chunked-transfer-up-to-1gb)
- [Quickstart & Installation](#quickstart--installation)
- [Environment Configuration](#environment-configuration)
- [Running Automated Tests](#running-automated-tests)
- [Connecting ClamAV (Optional)](#connecting-clamav-optional)
- [REST API Reference](#rest-api-reference)
- [Safe Built-in Test Samples](#safe-built-in-test-samples)
- [Security & Access Control](#security--access-control)
- [License](#license)

---

## Key Capabilities & What It Can Do

SentinelScan delivers enterprise-grade static analysis directly in the browser or via automated REST APIs:

- 🛡️ **Zero-Execution Threat Inspection**: Analyzes binary headers, document objects, stream trees, and macro bytecodes safely without sandboxing or virtualization execution overhead.
- ⚡ **Multi-Format Static Dissection**:
  - **Executables**: PE32/PE32+ (EXE, DLL, SYS) and ELF32/ELF64.
  - **Documents**: PDF, Microsoft Word (`.docx`, `.docm`), Excel (`.xlsx`, `.xlsm`), PowerPoint (`.pptx`).
  - **Mobile**: Android Application Packages (`.apk`).
  - **Archives**: ZIP, JAR, WAR with zip-bomb and directory-traversal protection.
  - **Scripts**: PowerShell (`.ps1`), Bash (`.sh`), Windows Script Host (`.vbs`, `.bat`, `.cmd`), SVG images (`.svg`).
- 📊 **Deterministic Scoring (0–100)**: Transparent, mathematical risk evaluation providing four standardized verdicts: `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, and `CRITICAL_RISK`.
- 🧬 **Shannon Entropy & Packing Detection**: Calculates mathematical byte randomness across sections to identify encrypted payloads, obfuscated layers, or commercial packers (e.g., UPX).
- 🚫 **Exploit Primitive Detection**:
  - `W^X` memory violation warnings (simultaneous writable and executable sections).
  - Dangerous PDF actions (`/Launch`, `/JavaScript`, `/EmbeddedFiles`, `/OpenAction`).
  - Office DDE formulas, external template injection, and embedded VBA macro projects.
  - Zip Slip path traversal sequences (`../`, absolute path attacks).
  - Android high-risk permission mapping (SMS, Audio, Device Admin, Overlay).
  - Dangerous script triggers (`IEX`, reverse shells, hidden execution styles, download cradles).
- 🧹 **Zero-Trust File Hygiene**: Automatic background worker securely overwrites (`0x00`) and unlinks uploaded files within 5 minutes of analysis, eliminating storage bloat and data-leak risks.
- 📦 **1GB Chunked Ingestion**: Resilient file upload protocol supporting streaming chunks up to 1GB with SHA-256 integrity verification.
- 📑 **Comprehensive Reporting**: Export findings as structured JSON payloads or print-ready GitHub-flavored Markdown executive briefs.
- 🧪 **Built-in Benign Test Generators**: One-click synthetic sample creation for safe training, demonstration, and continuous pipeline verification.

---

## Zero-Execution Architecture

Traditional sandboxes execute untrusted binaries inside virtual machines, exposing the host to VM escape exploits, sandbox evasion logic (e.g., sleep calls, cursor detection), and high computational latency.

SentinelScan adopts a **Zero-Execution Strategy**:
1. Files are treated strictly as **inert byte buffers and binary streams**.
2. Magic headers, structured formats, and token sequences are parsed using pure Node.js binary readers.
3. No child process (`exec`, `spawn`, `fork`) is ever invoked on the target file.
4. Parsers apply strict bounds checks, recursion depth caps, and timeout guards to prevent parser-DoS attacks.

```
                  ┌─────────────────────────────────────────┐
                  │          SentinelScan Client            │
                  │   (Cyber Defense Web UI / REST API)     │
                  └────────────────────┬────────────────────┘
                                       │ Multipart / Chunked (up to 1GB)
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │       Ingestion & Storage Guard         │
                  │  - Unique UUID v4 File Isolation        │
                  │  - Client-Token Authorization (IDOR)    │
                  │  - 5-Minute Shredding Timer Enqueued    │
                  └────────────────────┬────────────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                │        Multi-Engine Static Pipeline         │
                ▼                                             ▼
   ┌───────────────────────────┐                ┌───────────────────────────┐
   │ Cryptographic & Telemetry │                │ Static Content Analyzers  │
   │  - SHA-256, SHA-1, MD5    │                │  - PE32/PE64 (Headers/Sec)│
   │  - Magic Byte Validation  │                │  - ELF32/ELF64 (Headers)  │
   │  - Ext Mismatch Detection │                │  - PDF (Objects & Actions)│
   │  - Shannon Byte Entropy   │                │  - Office (Macros/DDE/XML)│
   └────────────┬──────────────┘                │  - Archive (Bomb/ZipSlip) │
                │                               │  - APK (Manifest & Perms) │
                │                               │  - Script (Ast & Regex)   │
                │                               └─────────────┬─────────────┘
                │                                             │
                │         ┌─────────────────────────┐         │
                └────────►│ Deterministic Risk Core │◄────────┘
                          │   (Score 0–100 Matrix)  │
                          └────────────┬────────────┘
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │   Verdict & Telemetry   │
                          │ - JSON Report & Markdown│
                          │ - SQLite WAL Record     │
                          │ - Secure Shred Protocol │
                          └─────────────────────────┘
```

---

## Analyzer Pipeline Breakdown

### 1. PE32 / PE32+ (Windows Portable Executables)
- **Header Parsing**: Reads DOS Header (`MZ`), PE signature (`PE\0\0`), File Header, and Optional Header (PE32 vs PE32+ 64-bit).
- **Section Table & Characteristics**:
  - Analyzes section names (`.text`, `.data`, `.rdata`, `.rsrc`, `.reloc`, etc.) and detects suspicious or abnormal names.
  - Computes **Shannon Entropy** ($H = -\sum p_i \log_2 p_i$) per section. Sections exceeding $H \ge 7.2$ are flagged as packed or encrypted.
  - Detects **`W^X` Memory Violations**: Flags sections with simultaneous `IMAGE_SCN_MEM_WRITE` (`0x80000000`) and `IMAGE_SCN_MEM_EXECUTE` (`0x20000000`) flags.
- **Import Table (IAT) Analysis**: Flags imports commonly leveraged by loaders, injecters, and ransomware (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `InternetOpen`, `URLDownloadToFile`).
- **Authenticode Check**: Inspects Certificate Table entry in data directories to verify digital signature presence.

### 2. ELF (Linux Executables)
- **Header Inspection**: Reads ELF magic (`0x7F 'E' 'L' 'F'`), architecture (32-bit vs 64-bit), endianness, and machine type (x86, x86-64, ARM, AArch64).
- **Program Headers & RWX Segments**:
  - Traverses `PT_LOAD` segments.
  - Flags segments with combined Read (`0x4`), Write (`0x2`), and Execute (`0x1`) permissions (`PF_R | PF_W | PF_X`).
- **Section Analysis**: Parses `.text`, `.dynsym`, `.plt`, `.got` and flags stripped symbol tables or non-standard section layouts.

### 3. PDF Documents
- **Structural Tree Inspection**: Parses PDF header version, indirect objects, and cross-reference streams.
- **Malicious Action Detection**:
  - `/JavaScript` and `/JS`: Embedded scripts designed for Acrobat reader exploitation.
  - `/Launch`: Shell commands executed upon viewing.
  - `/EmbeddedFiles`: Hidden secondary files or malicious stages nested inside the document.
  - `/OpenAction` & `/AA` (Additional Actions): Auto-trigger events firing without user confirmation.

### 4. Office Documents (OpenXML & OLE)
- **Format Differentiation**: Distinguishes between modern OpenXML archives (`.docx`, `.xlsx`, `.pptx`) and legacy Compound File Binary / OLE formats.
- **Macro & Payload Discovery**:
  - Locates `word/vbaProject.bin`, `xl/vbaProject.bin`, and extracts embedded VBA modules.
  - Detects auto-executing macros (`AutoOpen`, `Workbook_Open`, `Document_Open`).
- **Remote Template Injection**: Inspects `_rels/*.rels` for external target relationships (`TargetMode="External"` downloading dotm/templates over HTTP/HTTPS).
- **DDE (Dynamic Data Exchange)**: Identifies dangerous Excel formula injection patterns (`=cmd|' /C ...'`).

### 5. Archives & Compressed Files
- **Zip Bomb / Decompression Bomb Protection**:
  - Inspects Central Directory Headers without decompressing the payload.
  - Calculates the total uncompressed size vs. compressed size. Expansion ratios exceeding **100:1** or payloads exceeding configured thresholds trigger immediate critical risk flags.
- **Zip Slip Vulnerability Detection**:
  - Audits relative path sequences within every entry header.
  - Identifies path traversal sequences (`../`, `..\`) and root paths intended to overwrite system files outside the target directory.

### 6. Android APKs
- **Zip-level Architecture**: Scans the APK package for `AndroidManifest.xml`, `classes.dex`, and native `.so` libraries.
- **Permission Matrix**: Decodes permissions and identifies dangerous Android entitlements:
  - `android.permission.SEND_SMS` & `RECEIVE_SMS` (Toll fraud / OTP theft).
  - `android.permission.RECORD_AUDIO` & `CAMERA` (Surveillance / spyware).
  - `android.permission.SYSTEM_ALERT_WINDOW` (Overlay phishing attacks).
  - `android.permission.BIND_DEVICE_ADMIN` (Ransomware / persistence).
  - `android.permission.INSTALL_PACKAGES` (Silent dropper capability).

### 7. Scripts & Web Markup
- **PowerShell (`.ps1`)**:
  - Detects execution bypasses (`-ExecutionPolicy Bypass`, `-NoProfile`).
  - Identifies encoded commands (`-EncodedCommand`, `-enc`, base64 blocks).
  - Detects memory download cradles (`DownloadString`, `DownloadData`, `IEX`, `Invoke-Expression`).
- **Bash / Linux Shell (`.sh`)**:
  - Detects interactive reverse shells (`/dev/tcp/...`, `nc -e`, `mkfifo /tmp/`).
  - Detects destructive disk commands (`rm -rf /`, `mkfs`).
- **Windows Script Host (`.vbs`, `.bat`, `.cmd`)**:
  - Identifies `WScript.Shell`, `Shell.Application`, and hidden execution modes (`vbHide`, `WindowStyle = 0`).
- **Scalable Vector Graphics (`.svg`)**:
  - Detects embedded `<script>` tags, `onload`, and `onerror` handlers commonly used in XSS and client-side credential skimming attacks.

### 8. Antivirus Engine (ClamAV Streaming)
- **Native TCP Protocol**: Streams file bytes directly to a ClamAV daemon (`clamd`) using the standard `zINSTREAM\0` protocol over TCP socket.
- **Graceful Offline Fallback**: If ClamAV is not reachable or not running, SentinelScan gracefully marks the engine as `OFFLINE_BYPASSED` and continues full static analysis without interruptions.

---

## Deterministic Scoring Engine & Threat Matrix

Rather than utilizing an unexplainable "black box" machine learning model, SentinelScan calculates scores deterministically through transparent, weighted security heuristics.

### Base Score Allocation

Every identified threat factor contributes a weighted score penalty:

| Finding Type | Severity | Points Added | Rationale |
| :--- | :--- | :--- | :--- |
| **Known Malware Signature (ClamAV)** | Critical | +90 | Confirmed virus or trojan signature match |
| **W^X Memory Violation** | Critical | +45 | Code injection / shellcode execution primitive |
| **High Shannon Entropy (> 7.2)** | High | +30 | Strong indicator of commercial packer or encrypted payload |
| **Zip Bomb Ratio (> 100:1)** | Critical | +80 | Resource exhaustion / DoS attack |
| **Zip Slip Traversal (`../`)** | Critical | +75 | Arbitrary file overwrite attack |
| **PDF AutoAction (`/Launch`)** | High | +50 | Arbitrary system process launch |
| **Office Remote Template Injection** | High | +45 | External malware stage fetching |
| **Office VBA AutoOpen Macros** | Medium / High| +35 | Common social engineering dropper vector |
| **PowerShell Download Cradle (`IEX`)** | High | +40 | Memory-only payload execution |
| **Bash Reverse Shell (`/dev/tcp`)** | Critical | +60 | Remote access trojan / interactive backdoor |
| **Extension vs Magic Mismatch** | Medium | +30 | Camouflage attempt to bypass basic filters |
| **Android Spyware Permission Combo** | High | +40 | Suspicious permission cluster (SMS + Audio + Overlay) |

### Verdict Classifications

$$\text{Final Score} = \min\left(100, \sum \text{Weights} \right)$$

| Score Range | Verdict | UI Indicator | Action Recommendation |
| :--- | :--- | :--- | :--- |
| **0 – 15** | `CLEAN` | 🟢 Emerald | File exhibits standard structures; no threats detected. |
| **16 – 44** | `SUSPICIOUS` | 🟡 Amber | Contains unusual structures or benign macros; review before opening. |
| **45 – 74** | `MALICIOUS` | 🟠 Orange | Multiple high-risk indicators detected; do not execute. |
| **75 – 100** | `CRITICAL_RISK` | 🔴 Crimson | Active exploit primitives or confirmed virus signature; quarantine immediately. |

---

## Automated File Shredding & Hygiene

To guarantee complete data privacy and prevent malware hoarding:

1. Files uploaded to the local temp store are scheduled for automated deletion.
2. A background worker runs every 60 seconds and evaluates files exceeding the retention window (default: **300 seconds / 5 minutes**).
3. **Secure Shred Protocol**:
   - Files are opened in read/write mode.
   - The entire file size is overwritten with zeroed byte buffers (`0x00`).
   - The file handle is flushed to disk via `fs.fdatasync`.
   - The file is unlinked (`fs.unlinkSync`).
4. System event telemetry records the secure shredding action in the SQLite event log for auditable compliance.

---

## Large File Resiliency (Chunked Transfer up to 1GB)

For files too large for standard single-request HTTP forms (up to 1,024 MB):

1. **Initialization (`/api/upload/init`)**: Client requests an upload session with target filename, total size, and chunk count. SentinelScan generates an isolated session ID.
2. **Chunk Transmission (`/api/upload/chunk`)**: The client slices the file into chunks (recommended: 10 MB per chunk) and sends each chunk along with its index and slice SHA-256.
3. **Completion & Assembly (`/api/upload/complete`)**: Once all slices are delivered, the server streams the parts together into the final payload, verifies total SHA-256, and immediately queues analysis.

---

## Quickstart & Installation

### Prerequisites
- **Node.js**: Version 20.0.0 or higher
- **npm**: Version 9.0.0 or higher
- **Git**

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/sukeshd007/SentinelScan.git
cd SentinelScan

# 2. Install dependencies
npm install

# 3. Create your environment configuration
cp .env.example .env

# 4. Start the application
npm start
```

Once started, navigate to `http://localhost:3000` in your web browser.

### Development Mode (with hot reloading)

```bash
npm run dev
```

---

## Environment Configuration

SentinelScan works out of the box with sensible zero-configuration defaults. You can customize runtime settings via `.env`:

```ini
# Application Port
PORT=3000

# File Retention & Shredding (in seconds)
FILE_RETENTION_SECONDS=300

# Maximum Upload Limits (in bytes)
MAX_FILE_SIZE_BYTES=1073741824       # 1 GB
DIRECT_UPLOAD_LIMIT_BYTES=52428800    # 50 MB

# Rate Limiting
RATE_LIMIT_WINDOW_MS=60000            # 1 minute
RATE_LIMIT_MAX_REQUESTS=120           # 120 requests per minute

# ClamAV Configuration (Optional)
CLAMAV_HOST=127.0.0.1
CLAMAV_PORT=3310
CLAMAV_TIMEOUT_MS=10000

# Storage Path
UPLOAD_DIR=temp/uploads
```

---

## Running Automated Tests

SentinelScan includes a comprehensive suite of unit and integration tests covering all analyzers, chunking protocols, risk scoring calculations, and report generation.

```bash
# Run all test suites
npm test
```

### Test Suite Coverage
- `tests/analyzers.test.js`: Validates PE, ELF, PDF, Office, Zip Bomb, Zip Slip, Script, and APK analyzers against mock and real structures.
- `tests/risk_engine.test.js`: Tests score accumulation, boundary clamping, and verdict mapping.
- `tests/storage.test.js`: Verifies chunk assembly, SHA-256 validation, and 5-minute zero-fill file shredding.
- `tests/api.test.js`: End-to-end integration tests for single upload, status polling, report export, and test sample generation.

---

## Connecting ClamAV (Optional)

SentinelScan includes native support for ClamAV's daemon via TCP streaming. If ClamAV is offline, SentinelScan continues without errors.

### Option A: Using Docker (Quickest)

```bash
docker run -d \
  --name clamav \
  -p 3310:3310 \
  clamav/clamav:latest
```

### Option B: Native Linux Service

```bash
sudo apt update && sudo apt install -y clamav-daemon
sudo systemctl enable --now clamav-daemon
```

Configure `CLAMAV_HOST=127.0.0.1` and `CLAMAV_PORT=3310` in your `.env` file and restart SentinelScan.

---

## REST API Reference

SentinelScan provides a clean, predictable REST API for integration into CI/CD pipelines, SOAR playbooks, and custom security scripts.

### 1. Direct File Upload & Analysis
```http
POST /api/scan
Content-Type: multipart/form-data
```
**Request:**
- Form Field: `file` (Binary file)
- Header (Optional): `X-Client-Token: <token>` (Prevents IDOR access)

**Response (`200 OK`):**
```json
{
  "success": true,
  "scanId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "COMPLETED",
  "fileName": "sample_binary.exe",
  "fileSize": 45056,
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "magicType": "application/x-dosexec",
  "threatScore": 85,
  "verdict": "CRITICAL_RISK",
  "findingsCount": 3,
  "analyzedAt": "2026-09-04T12:00:00.000Z"
}
```

---

### 2. Chunked Upload Protocol (For Files > 50 MB)

#### Step A: Initialize Session
```http
POST /api/upload/init
Content-Type: application/json

{
  "fileName": "large_disk_image.iso",
  "fileSize": 450000000,
  "totalChunks": 45,
  "clientToken": "user-session-token"
}
```

#### Step B: Upload Chunk
```http
POST /api/upload/chunk
Content-Type: multipart/form-data

Form fields:
  - uploadId: "<uploadId>"
  - chunkIndex: 0
  - chunk: (binary chunk data)
```

#### Step C: Finalize & Queue Scan
```http
POST /api/upload/complete
Content-Type: application/json

{
  "uploadId": "<uploadId>",
  "expectedSha256": "optional-hash-verification"
}
```

---

### 3. Retrieve Scan Results
```http
GET /api/scan/:id
Header: X-Client-Token: <token>
```
Returns comprehensive analysis details including:
- Cryptographic hashes (SHA-256, SHA-1, MD5)
- Magic bytes analysis and file extension matching
- Shannon entropy calculations
- Deep format-specific telemetry
- List of categorized findings with risk ratings and technical descriptions
- ClamAV scan results

---

### 4. Download Executive Report
```http
GET /api/report/:id?format=markdown
GET /api/report/:id?format=json
```
- `format=markdown`: Returns a complete, GitHub-flavored Markdown document suitable for sharing or saving into incident tickets.
- `format=json`: Returns raw structured report telemetry.

---

### 5. Generate Safe Test Samples
```http
POST /api/test/generate
Content-Type: application/json

{
  "type": "pe_packed" | "pdf_js" | "office_macro" | "zip_bomb" | "zip_slip" | "ps1_cradle" | "clean_text"
}
```
Generates synthetic, non-destructive test files in memory for verification and evaluation.

---

### 6. Service Health
```http
GET /api/health
```
```json
{
  "status": "HEALTHY",
  "uptime": 1420,
  "database": "CONNECTED",
  "clamav": "ONLINE",
  "timestamp": "2026-09-04T12:00:00.000Z"
}
```

---

## Safe Built-in Test Samples

The SentinelScan Web UI includes a **Sample Testing Suite** allowing security teams, educators, and evaluators to test all analyzers immediately without needing real malware:

- **EICAR Standard Test Antivirus String**: Safe benign string that triggers AV signature detection.
- **Synthesized PE with High Entropy**: Mock Windows executable with randomized byte sections simulating a packed trojan.
- **PDF with JavaScript & AutoLaunch**: PDF container with non-destructive `/JavaScript` and `/OpenAction` streams.
- **Office Document with Simulated VBA**: Word container holding `vbaProject.bin` with `AutoOpen` hooks.
- **Simulated Zip Bomb**: Multi-layer archive demonstrating 150:1 compression ratio detection.
- **Zip Slip Traversal Sample**: Archive containing a traversal filename (`../../etc/passwd`).
- **PowerShell Download Cradle**: Script with `-ExecutionPolicy Bypass` and `IEX (New-Object Net.WebClient).DownloadString`.

---

## Security & Access Control

- **Zero Untrusted Execution**: Uploaded files are never executed.
- **In-Memory Buffer Caps**: Stream-based hashing prevents buffer-overflow exploits.
- **IDOR Prevention**: Every scan is tagged with a client session token; users cannot view scans created by other sessions unless authorized.
- **Sanitized Headers**: Express configured with `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and strict CORS policies.
- **Zero-Fill Unlinking**: Automatic shredder prevents lingering binaries on disk.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
