
# QSteg v16.7 – Quantum-Resistant Steganography

Hide encrypted data inside PNG, MP4, and PDF files.  
One password shows a harmless decoy. The real password unlocks the actual secret.

**Hybrid post-quantum encryption** – AES-256-GCM + ML-KEM-768 + ML-DSA-65.

---

## Why QSteg?

Most stego tools just tuck data into LSBs and call it a day. I wanted something that:

- Survives a quantum computer in 10 years (PQC hybrid mode)
- Gives you plausible deniability (dual-layer containers)
- Actually works on Linux, macOS, and Termux without fuss

If you just need basic AES stego, it does that too.

---

## Features

- **Dual passwords** – decoy layer + hidden layer
- **AES-256-GCM** – fast, standard, always available
- **Hybrid PQC mode** – ML-KEM-768 (Kyber) + ML-DSA-65 (Dilithium) via OpenSSL 3.6+
- **LSB-2 embedding** for PNGs (with built-in ECC)
- **MP4 and PDF support** – data gets appended as metadata
- **12 automated tests** – `python qsteg.py --test`
- **Secure memory handling** – constant-time compares, DoD wipe

---

## Installation

### 1. Clone and install Python deps

```bash
git clone https://github.com/muc111/QSteg.git
cd QSteg
pip install -r requirements.txt
```

2. Install OpenSSL 3.6+ (required for PQC)

Ubuntu/Debian (build from source – repos are often behind)

```bash
sudo apt update && sudo apt install build-essential checkinstall zlib1g-dev
wget https://www.openssl.org/source/openssl-3.6.0.tar.gz
tar -xzf openssl-3.6.0.tar.gz
cd openssl-3.6.0
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
make -j$(nproc)
sudo make install
echo 'export PATH="/usr/local/ssl/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

macOS

```bash
brew install openssl@3
# follow the brew instructions to add it to PATH
```

Termux (Android)

```bash
pkg update && pkg upgrade
pkg install openssl-tool
```

Verify

```bash
openssl version -a   # should say 3.6.x
python -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

---

Quick Start

```bash
python qsteg.py
```

Pick 1. Encode data, choose a carrier file, set passwords, done.

Example workflow:

1. Run the tool, select "Encode data"
2. Choose a PNG/MP4/PDF
3. Select security level (STANDARD = AES+PQC)
4. Enter your secret message
5. Set a decoy password (shows fake content) and a master password (reveals real data)
6. Decode later with either password

---

Why Two Passwords?

If someone forces you to unlock the file, give them the decoy password. They'll see a plausible document (corporate memo, research paper, etc.) and assume that's all there is. The real data stays hidden unless you use the master password.

---

Known Issues

· WhatsApp / social media – These platforms recompress images, which destroys LSB data. Send stego files as documents instead and they'll survive intact.
· PQC overhead – Hybrid mode adds ~3.5KB to each container. Tiny images may not have enough capacity.

---

Tests

Run the built-in test suite:

```bash
python qsteg.py --test
```

All 12 tests should pass.

---

License

MIT – use it, modify it, share it. Just don't blame me if you forget your password.

---

Contributing

PRs and issues welcome. I'm especially interested in:

· Testing on different OpenSSL builds
· Adding WAV/FLAC support
· Improving WhatsApp robustness (Reed-Solomon)

---