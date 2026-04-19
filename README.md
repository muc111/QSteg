# QSteg v17.0 – Quantum-Resistant Steganography

Hide encrypted data inside PNG, MP4, and PDF files.  
One password shows a harmless decoy. The real password unlocks the actual secret.

**Hybrid post-quantum encryption** – AES-256-GCM + ML-KEM-1024 + ML-DSA-65.  
**AI-assisted development** – portions of this codebase were developed with Claude (Anthropic). Disclosed transparently per project policy.

---

## What's new in v17.0

| Area | v16.7 | v17.0 |
|---|---|---|
| PQC fallback | Silent simulation if OpenSSL < 3.6 | **Hard failure** – no simulation ever |
| Key combination | Raw `sha3_256(pw_key ‖ ss)` | **HKDF RFC 5869** (HMAC-SHA-256) |
| Key separation | Single derived key | **AES key (0-31B) + PRNG seed (32-63B)** |
| Pixel selection | Sequential scan | **PRNG-keyed Fisher-Yates permutation** |
| Error correction | XOR parity (1 byte/8) | **Reed-Solomon RS(255,223)** |
| Social media | Warning only | **Robust mode** – 5% density, stronger RS |
| Dual-layer format | Plaintext `###NSA-DUALv16###` separator | **No separator**, filler padding, masked seed |
| MP4 / PDF | Unlabelled data inject | **Clearly labelled container embedding** |
| Security theater | "NSA", "DoD 5220.22-M" labels | **Removed** |
| Tests | 12 | **17** (+ PQC failure, RS recovery, entropy) |

---

## Features

- **Dual passwords** – decoy layer + hidden layer  
- **AES-256-GCM** – always available, fast  
- **HKDF key derivation** – RFC 5869, separated encryption key + PRNG seed  
- **PRNG pixel embedding** – keyed Fisher-Yates permutation, non-sequential  
- **Reed-Solomon ECC** – survives up to 16 byte-errors per 255-byte block  
- **Robust mode** – designed for social-media channels (WhatsApp, Instagram)  
- **Hybrid PQC** – ML-KEM-1024 + ML-DSA-65 via OpenSSL ≥ 3.6 (hard fail if unavailable)  
- **Improved deniability** – no plaintext structural separator between layers  
- **18 automated tests** – `python qsteg.py --test`

---

## Why QSteg?

Most stego tools just tuck data into LSBs and call it a day. QSteg aims for:

- **Quantum survival** – PQC hybrid mode (real OpenSSL, no simulation)
- **Plausible deniability** – forensic tools cannot trivially detect dual payloads
- **Lossy channel survival** – Reed-Solomon + robust mode for social media
- **Honest engineering** – no misleading security labels, accurate error messages

---

## Installation

### 1. Clone and install Python deps

```bash
git clone https://github.com/muc111/QSteg.git
cd QSteg
pip install -r requirements.txt
```

### 2. Install OpenSSL 3.6+ (required for PQC mode only)

**Ubuntu/Debian (build from source – repos are often behind)**
```bash
sudo apt update && sudo apt install build-essential checkinstall zlib1g-dev
wget https://www.openssl.org/source/openssl-3.6.0.tar.gz
tar -xzf openssl-3.6.0.tar.gz && cd openssl-3.6.0
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
make -j$(nproc) && sudo make install
echo 'export PATH="/usr/local/ssl/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

**macOS**
```bash
brew install openssl@3
# Follow brew output to add to PATH
```

**Termux (Android)**
```bash
pkg update && pkg upgrade && pkg install openssl-tool
```

**Verify**
```bash
openssl version -a   # must show 3.6.x
python -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

> ℹ️ If OpenSSL ≥ 3.6 is not available, QSteg will **refuse to start PQC operations** rather than silently downgrade. Use `SecurityLevel.FAST` (AES-256 only) on older systems.

---

## Quick Start

```bash
python qsteg.py
```

Pick **1. Encode data**, choose a carrier, set passwords, done.

### Workflow

1. Run the tool → select **Encode data**
2. Choose a PNG carrier (PNG recommended for true steganography)
3. Choose security level: **FAST** (AES-256) or **STANDARD** (AES+PQC)
4. Enable **robust mode** if the image may be re-uploaded to social media
5. Enter your secret message
6. Set a decoy password (reveals fake content) and a master password (reveals real data)
7. Two output files are created: the stego image + a `.qss` sidecar (PRNG seed)
8. Decode with either password

> **Important:** Keep the `.qss` sidecar file alongside the stego file. Without it, decoding is not possible. Store it securely.

---

## Why Two Passwords?

If someone forces you to unlock the file, give them the decoy password. They'll see a plausible document (corporate memo, research paper) and assume that's all there is. The real data stays hidden unless you use the master password.

In v17.0, the dual-layer structure has **no plaintext separator**, making it harder for forensic tools to detect the dual-payload structure.

---

## MP4 and PDF: Container Embedding, Not Steganography

MP4 and PDF modes inject a clearly-framed data blob into the file byte-stream. **This is not steganography** – a format-aware forensic examiner will detect the embedded data. These modes are provided for convenience, not covert communication.

For covert use, always choose a **PNG carrier**.

---

## Robust Mode (Social Media)

Enable robust mode when the carrier image may pass through a lossy channel (WhatsApp, Instagram, Telegram, etc.):

- Payload density reduced to **~5%** of capacity (vs 65% standard)
- Reed-Solomon uses **64 parity bytes** per block (vs 32 standard)
- Warns if carrier width < 1024px

Trade-off: requires a substantially larger carrier image.

---

## Known Issues

- **WhatsApp / social media** – platforms recompress images, destroying LSB data. Use **robust mode** for better survival rates, or send as a document attachment.
- **PQC overhead** – hybrid mode adds ~3.5 KB to each container. Tiny images may not have enough capacity.
- **PRNG seed (`.qss`) must travel with the stego file** – if the sidecar is lost, the stego file cannot be decoded.

---

## Tests

```bash
python qsteg.py --test
```

18 tests covering:

| # | Test |
|---|---|
| 01 | AES-256-GCM roundtrip |
| 02 | HKDF key derivation |
| 03 | Hybrid PQC encryption (skips gracefully if OpenSSL < 3.6) |
| 04 | Dual-layer container (no separator) |
| 05 | Reed-Solomon encode/decode |
| 06 | RS error recovery (10 corrupted bytes) |
| 07 | PRNG pixel permutation |
| 08 | PNG PRNG-steganography roundtrip |
| 09 | MP4 container embedding |
| 10 | PDF container embedding |
| 11 | Capacity calculation |
| 12 | Security utilities |
| 13 | Wrong password → clean failure |
| 14 | RS bit-flip per block recovery |
| 15 | Corrupted container → graceful failure |
| 16 | PQC key corruption → no silent downgrade |
| 17 | Entropy similarity (steganalysis resistance) |
| 18 | File hiding (1 KB) in PNG |

---

## License

MIT – use it, modify it, share it. Don't blame me if you forget your password.

---

## Contributing

PRs and issues welcome. Especially interested in:

- Testing on different OpenSSL 3.6+ builds
- WAV/FLAC steganography support
- DCT-domain embedding for JPEG resilience
- Improved WhatsApp robustness testing
