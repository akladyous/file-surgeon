# 🪄 FileSurgeon

> Deep file carving, MIME-aware extraction, and forensic artifact recovery for disk images, memory dumps, and raw binary streams.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Forensics](https://img.shields.io/badge/domain-Digital%20Forensics-critical)](.)
[![Powered by Magika](https://img.shields.io/badge/detection-Google%20Magika-orange)](https://github.com/google/magika)

> ⚠️ **For authorized use only.** This tool is intended for digital forensics professionals, incident responders, and security researchers operating on data
> they have explicit legal authorization to analyze. Misuse may violate computer fraud and data privacy laws.

---

## What is File Carving?

When files are deleted, a filesystem removes the directory entry — but the raw bytes often remain on disk. **File carving** is the process of recovering those
files without relying on filesystem metadata. Instead, it works by:

1. Scanning raw bytes for known **file signatures** (magic bytes / file headers)
2. Identifying the end of each file (footer bytes, or predicted size)
3. Extracting the carved bytes and reconstructing the original file

FileSurgeon extends classical carving with **MIME-aware validation** — every carved candidate is re-identified using deep learning (Magika) to reject false
positives before writing to disk. This dramatically improves carve quality on fragmented or corrupted media.

---

## Use Cases

- **Incident Response** — recover deleted malware, scripts, or documents from a compromised host image
- **CTF Challenges** — extract hidden files embedded inside other files (steganography, polyglots)
- **Disk Forensics** — recover evidence from formatted or partially overwritten drives
- **Memory Forensics** — extract artifacts from raw RAM dumps (PE headers, ZIP blobs, JPEG thumbnails)
- **Network Forensics** — carve files out of raw PCAP streams
- **Research** — study how files fragment across storage media

---

## Features

- **Signature-based carving** — extensible header/footer dictionary covering 40+ file types
- **MIME validation layer** — Magika re-identifies every carved candidate to eliminate false positives
- **Stream-friendly** — works on raw binary files of any size using a sliding-window reader (no full load into RAM)
- **Fragmentation handling** — configurable gap tolerance for carved files that span non-contiguous sectors
- **Entropy analysis** — flags high-entropy regions as likely encrypted or compressed content
- **Sector-aligned scanning** — optional 512-byte sector alignment for disk image fidelity
- **Report generation** — structured JSON report per carve session (offset, size, MIME, confidence, SHA-256)
- **Pluggable signatures** — add new file types via a simple YAML signature file, no code changes
- **CLI + importable API** — use interactively or embed in your own forensics pipeline

---

## Requirements

- Python 3.9+
- [Magika](https://github.com/google/magika) — `pip install magika`
- [tqdm](https://github.com/tqdm/tqdm) — progress bars
- [PyYAML](https://pyyaml.org/) — signature loading
- [pycryptodome](https://pycryptodome.readthedocs.io/) _(optional)_ — entropy scoring

---

## Installation

```bash
git clone https://github.com/your-org/filesurgeon.git
cd filesurgeon
pip install -r requirements.txt
```

`requirements.txt`:

```
magika>=0.5.0
tqdm>=4.0
pyyaml>=6.0
pycryptodome>=3.0   # optional, for entropy analysis
```

---

## Quick Start

```bash
# Carve everything from a raw disk image
python filesurgeon.py --input disk.img --output ./carved/

# Carve only specific types from a memory dump
python filesurgeon.py --input memdump.raw --output ./carved/ --types pdf,png,elf,zip

# Carve with MIME validation (rejects false positives)
python filesurgeon.py --input capture.bin --output ./carved/ --validate

# Carve + entropy scan (flag encrypted/packed regions)
python filesurgeon.py --input disk.img --output ./carved/ --validate --entropy

# Write a JSON report alongside carved files
python filesurgeon.py --input disk.img --output ./carved/ --validate --report report.json
```

---

## CLI Reference

```
--input  PATH         Raw binary stream, disk image, or memory dump to carve
--output DIR          Directory to write carved files into (created if absent)
--types  LIST         Comma-separated file types to target (default: all)
                      e.g. --types pdf,jpeg,zip,elf,sqlite,docx
--signatures FILE     Custom YAML signature file (default: signatures/default.yaml)
--validate            Re-identify carved candidates with Magika before saving
--entropy             Compute Shannon entropy on each carved region
--sector-align        Snap scan offsets to 512-byte sector boundaries
--gap-tolerance N     Max byte gap to bridge when carving fragmented files (default: 0)
--min-size N          Discard carved files smaller than N bytes (default: 512)
--max-size N          Discard carved files larger than N bytes (default: 500MB)
--report FILE         Write JSON session report to FILE
--log-level LEVEL     DEBUG / INFO / WARNING / ERROR (default: INFO)
--workers N           Parallel carving workers (default: 1)
```

---

## Supported File Types (Built-in Signatures)

| Category        | Types                                                    |
| --------------- | -------------------------------------------------------- |
| **Documents**   | PDF, DOCX, XLSX, PPTX, ODT, RTF                          |
| **Images**      | JPEG, PNG, GIF, BMP, TIFF, WebP, ICO, PSD                |
| **Archives**    | ZIP, RAR, 7z, GZIP, BZIP2, TAR, XZ                       |
| **Executables** | ELF (Linux), PE (Windows), Mach-O (macOS), DEX (Android) |
| **Databases**   | SQLite, LevelDB                                          |
| **Media**       | MP4, AVI, MKV, MP3, WAV, FLAC, OGG                       |
| **Scripts**     | Python bytecode (.pyc), Java .class                      |
| **Crypto**      | PGP/GPG keys, X.509 PEM certs, PKCS12                    |
| **Network**     | PCAP, PCAPng                                             |
| **Disk Images** | ISO 9660, VMDK, VHD                                      |

Add your own in `signatures/custom.yaml` — see [Custom Signatures](#custom-signatures).

---

## Python API

### Carve a binary stream

```python
from filesurgeon import carve_stream, CarveOptions

with open("disk.img", "rb") as f:
    options = CarveOptions(
        validate=True,
        entropy=True,
        min_size=1024,
        target_types={"pdf", "elf", "zip"},
    )
    results = carve_stream(f, output_dir="./carved", options=options)

for r in results:
    print(f"[{r.mime_type}] offset={r.offset:#010x} size={r.size} sha256={r.sha256}")
```

### Process results programmatically

```python
from filesurgeon import carve_stream, CarveStatus

results = carve_stream(stream, output_dir="./carved")

recovered   = [r for r in results if r.status == CarveStatus.SAVED]
rejected    = [r for r in results if r.status == CarveStatus.REJECTED]   # MIME mismatch
encrypted   = [r for r in results if r.entropy and r.entropy > 7.5]      # high entropy

print(f"Recovered: {len(recovered)}  Rejected: {len(rejected)}  High-entropy: {len(encrypted)}")
```

### The `CarveResult` dataclass

| Field           | Type            | Description                                    |
| --------------- | --------------- | ---------------------------------------------- |
| `offset`        | `int`           | Byte offset of the header in the source stream |
| `size`          | `int`           | Carved size in bytes                           |
| `output_path`   | `str \| None`   | Path where the file was written                |
| `expected_type` | `str`           | Type inferred from header signature            |
| `mime_type`     | `str \| None`   | MIME type from Magika validation               |
| `label`         | `str \| None`   | Magika short label                             |
| `sha256`        | `str`           | SHA-256 of the carved bytes                    |
| `entropy`       | `float \| None` | Shannon entropy (0–8), None if not computed    |
| `status`        | `CarveStatus`   | `saved`, `rejected`, `skipped`, `error`        |

---

## Custom Signatures

Extend detection by creating a YAML file following this schema:

```yaml
# signatures/custom.yaml

signatures:
    - name: lnk # short label / output file extension
      header: "4C 00 00 00 01 14 02 00" # hex magic bytes (spaces optional)
      header_offset: 0 # byte offset where header appears
      footer: null # hex footer bytes, or null
      max_size: 10485760 # max file size in bytes (10 MB)
      mime_type: "application/x-ms-shortcut"

    - name: evtx
      header: "45 6C 66 46 69 6C 65 00"
      header_offset: 0
      footer: null
      max_size: 536870912 # 512 MB
      mime_type: "application/x-ms-evtx"
```

Load it at runtime:

```bash
python filesurgeon.py --input disk.img --output ./carved/ --signatures signatures/custom.yaml
```

---

## Session Report Format

When `--report report.json` is passed, FileSurgeon writes a structured JSON report:

```json
{
    "session": {
        "input": "disk.img",
        "input_size_bytes": 8589934592,
        "started_at": "2025-02-22T14:30:00Z",
        "finished_at": "2025-02-22T14:47:23Z",
        "options": { "validate": true, "entropy": true, "sector_align": false }
    },
    "summary": {
        "total_candidates": 812,
        "saved": 749,
        "rejected": 48,
        "errors": 15
    },
    "carved_files": [
        {
            "offset": "0x00A3F200",
            "size": 245891,
            "expected_type": "pdf",
            "mime_type": "application/pdf",
            "label": "pdf",
            "sha256": "e3b0c44298fc1c149afb...",
            "entropy": 6.82,
            "status": "saved",
            "output_path": "carved/0x00A3F200_pdf.pdf"
        }
    ]
}
```

---

## Architecture

```
filesurgeon/
├── filesurgeon.py          # CLI entry-point + public API (carve_stream, carve_file)
├── core/
│   ├── scanner.py          # Sliding-window byte scanner
│   ├── signatures.py       # Signature registry + YAML loader
│   ├── validator.py        # Magika MIME validation layer
│   ├── entropy.py          # Shannon entropy computation
│   └── report.py           # JSON session report builder
├── signatures/
│   └── default.yaml        # Built-in signature database
├── tests/
│   ├── test_carver.py
│   ├── test_validator.py
│   └── fixtures/           # Binary test blobs
└── README.md
```

---

## Forensic Workflow Example

A typical disk forensics workflow integrating FileSurgeon:

```bash
# 1. Acquire a forensic image (outside scope of this tool)
dd if=/dev/sdb of=evidence.img bs=4M status=progress

# 2. Carve all files, validate, compute entropy, generate report
python filesurgeon.py \
  --input evidence.img \
  --output ./case_001/carved/ \
  --validate \
  --entropy \
  --report ./case_001/carve_report.json \
  --log-level INFO

# 3. Filter high-entropy carved files (possible encrypted payloads)
jq '[.carved_files[] | select(.entropy > 7.5)]' ./case_001/carve_report.json

# 4. Hash-verify a carved file against a known IOC list
sha256sum ./case_001/carved/*.elf

# 5. Import the JSON report into your SIEM or case management system
python ingest_report.py ./case_001/carve_report.json
```

---

## Limitations & Known Constraints

- **Fragmented files** — heavily fragmented files may carve incorrectly; adjust `--gap-tolerance` to recover more at the cost of false positives
- **Encrypted volumes** — cannot carve through full-disk encryption (BitLocker, LUKS); decrypt the volume first
- **Proprietary formats** — formats without public magic byte documentation require manual signature authoring
- **Memory dumps** — ASLR and memory page shuffling mean carved executables from RAM may not be directly runnable
- **Performance** — single-threaded mode processes ~200–400 MB/s on modern hardware; use `--workers` to parallelize

---

## Legal & Ethical Notice

This tool must only be used on data you own or have explicit written authorization to analyze. Unauthorized forensic analysis of systems or storage media may
violate:

- The Computer Fraud and Abuse Act (CFAA) — United States
- The Computer Misuse Act — United Kingdom
- GDPR Article 5 — European Union
- Equivalent legislation in your jurisdiction

The authors assume no liability for misuse.

---

## Related Tools

| Tool                                                              | Role                                           |
| ----------------------------------------------------------------- | ---------------------------------------------- |
| [Autopsy](https://www.autopsy.com/)                               | Full forensics GUI platform                    |
| [Bulk Extractor](https://github.com/simsong/bulk_extractor)       | High-performance feature extraction            |
| [Scalpel](https://github.com/sleuthkit/scalpel)                   | Classic signature-based carver                 |
| [Volatility](https://github.com/volatilityfoundation/volatility3) | Memory forensics framework                     |
| [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit)          | Filesystem-layer forensics                     |
| [mime-scanner](https://github.com/your-org/mime-scanner)          | The MIME detection library this tool builds on |

---

## License

MIT — see [LICENSE](LICENSE).

Forensics professionals: see also the [SANS Digital Forensics](https://www.sans.org/digital-forensics-incident-response/) and [SWGDE](https://www.swgde.org/)
guidelines for evidence handling best practices.
