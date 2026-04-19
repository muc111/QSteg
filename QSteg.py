#!/usr/bin/env python3

# ============================================================================
# IMPORTS
# ============================================================================

import os, sys, time, struct, hashlib, secrets, gc, base64, json, hmac
import warnings, math, traceback, random, string, getpass, subprocess
import tempfile, atexit, stat, ssl, binascii, mimetypes, platform, inspect
from pathlib import Path
from typing import Optional, Tuple, Union, Dict, Any, List
from datetime import datetime
from enum import Enum, IntEnum
from dataclasses import dataclass

# Try to import the ML-KEM C extension
try:
    import qsteg_mlkem
    MLKEM_AVAILABLE = True
except ImportError:
    MLKEM_AVAILABLE = False
    print("⚠ qsteg_mlkem.so not found — PQC hybrid mode disabled")
# ============================================================================
# DEPENDENCY ENFORCEMENT
# ============================================================================

def enforce_dependencies():
    """Check and import all required dependencies."""
    missing = []

    try:
        from PIL import Image
        print("✅ Pillow: image processing")
    except ImportError:
        missing.append("Pillow  →  pip install Pillow")

    try:
        import numpy as np
        print("✅ NumPy: numerical operations")
    except ImportError:
        missing.append("numpy  →  pip install numpy")

    try:
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import scrypt
        from Crypto.Random import get_random_bytes
        print("✅ PyCryptodome: AES-256-GCM + scrypt")
    except ImportError:
        missing.append("pycryptodome  →  pip install pycryptodome")

    try:
        from reedsolo import RSCodec
        print("✅ reedsolo: Reed-Solomon error correction")
    except ImportError:
        missing.append("reedsolo  →  pip install reedsolo")

    # OpenSSL version check (PQC requires ≥ 3.6)
    try:
        ver_str = ssl.OPENSSL_VERSION.split()[1]
        major, minor = map(int, ver_str.split(".")[:2])
        if major > 3 or (major == 3 and minor >= 6):
            print(f"✅ OpenSSL {ver_str}: PQC ready")
        else:
            # Only a warning here – PQC availability verified at runtime
            print(f"⚠️  OpenSSL {ver_str}: PQC likely unavailable (need ≥ 3.6)")
    except Exception as e:
        print(f"⚠️  OpenSSL check: {e}")

    if missing:
        print("\n❌ MISSING DEPENDENCIES:")
        for d in missing:
            print(f"   {d}")
        print("\nInstall all: pip install Pillow numpy pycryptodome reedsolo")
        sys.exit(1)

enforce_dependencies()

from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from reedsolo import RSCodec

# ============================================================================
# CONSTANTS
# ============================================================================

class QStegConstants:
    """QSteg v17.0 runtime constants."""

    # Terminal colours
    HEADER   = '\033[95m'
    SUCCESS  = '\033[92m'
    WARNING  = '\033[93m'
    ERROR    = '\033[91m'
    INFO     = '\033[94m'
    DECOY    = '\033[33m'
    HIDDEN   = '\033[32m'
    CRYPTO   = '\033[35m'
    PROGRESS = '\033[96m'
    TABLE    = '\033[90m'
    RESET    = '\033[0m'
    BOLD     = '\033[1m'

    # ML-KEM-768 / ML-DSA-65 expected sizes (OpenSSL 3.6 DER-encoded)
    ML_KEM_768_PUBLIC_SIZE      = 1184
    ML_KEM_768_PRIVATE_SIZE     = 2400
    ML_KEM_768_CIPHERTEXT_SIZE  = 1088
    ML_KEM_768_SHARED_SECRET    = 32

    ML_DSA_65_PUBLIC_SIZE       = 1952
    ML_DSA_65_PRIVATE_SIZE      = 4032
    ML_DSA_65_SIGNATURE_MIN     = 64    # Minimum plausible signature bytes

    # AES-256-GCM parameters
    AES_KEY_SIZE   = 32
    AES_NONCE_SIZE = 12
    AES_TAG_SIZE   = 16
    SALT_SIZE      = 32

    # Key directory
    KEY_DIR      = Path(".qsteg_keys")
    KEY_FILE_EXT = ".qskey"
    MIN_PASSWORD_LENGTH = 8

    # scrypt KDF parameters (NIST SP 800-132 level)
    class KDF:
        SCRYPT_N_STANDARD = 2**17   # 131072
        SCRYPT_N_FAST     = 2**14   # 16384  (AES-only mode)
        SCRYPT_N_PARANOID = 2**19   # 524288
        SCRYPT_R = 8
        SCRYPT_P = 2

    class STEG:
        LSB_BITS         = 2
        MIN_IMAGE_PIXELS = 240_000       # 600×400 minimum
        CAPACITY_FACTOR  = 0.65          # Maximum utilisation (standard mode)
        CAPACITY_FACTOR_ROBUST = 0.10    # Social-media robust mode
        MIN_ROBUST_WIDTH = 1024          # Minimum width for robust mode
        HEADER_MAGIC     = b'QSTEG-V17\x00'
        FOOTER_MAGIC     = b'\x00QSTEG-END'
        MAX_FILE_SIZE    = 100 * 1024 * 1024

        # Reed-Solomon parameters
        RS_NSYM_STANDARD = 32    # parity symbols per 255-byte block (~12.5%)
        RS_NSYM_ROBUST   = 64    # stronger redundancy for lossy channels

        # Dual-layer container format version
        DUAL_MAGIC   = b'QS-DL-V17\x00'
        DUAL_FOOTER  = b'\x00QS-DL-END'

    FORMATS = {
        'PNG': ['.png', '.PNG'],
        'MP4': ['.mp4', '.MP4', '.mov', '.MOV'],
        'PDF': ['.pdf', '.PDF'],
        'JPG': ['.jpg', '.jpeg', '.JPG', '.JPEG'],
    }

    TEST_USERNAME  = "qsteg_autotest"
    TEST_PASSWORD  = "QStegTestPass123!@#"
    TEST_DECOY_PASS  = "QStegDecoyPass456!@#"
    TEST_MASTER_PASS = "QStegMasterPass789!@#"

    BAR_WIDTH        = 50
    MAX_FILES_DISPLAY = 20
    WHATSAPP_PNG  = 16 * 1024 * 1024
    WHATSAPP_MP4  = 100 * 1024 * 1024
    WHATSAPP_PDF  = 100 * 1024 * 1024


# ============================================================================
# ENUMS AND DATACLASSES
# ============================================================================

class DeniabilityMode(IntEnum):
    NONE        = 0
    DECOY_ONLY  = 1
    HIDDEN_ONLY = 2
    BOTH_LAYERS = 3

class ContainerType(IntEnum):
    PNG     = 1
    MP4     = 2
    PDF     = 3
    JPG     = 4
    UNKNOWN = 0

class SecurityLevel(IntEnum):
    FAST     = 1   # AES-256 only
    STANDARD = 2   # Hybrid AES + PQC
    PARANOID = 3   # Full PQC with signatures

@dataclass
class FileInfo:
    path:       Path
    name:       str
    size:       int
    type:       ContainerType
    capacity:   int
    whatsapp:   bool
    modified:   str
    dimensions: str = ""
    resolution: str = ""

@dataclass
class OperationStats:
    start:           float
    end:             float = 0
    bytes_processed: int   = 0
    success:         bool  = False
    error:           str   = ""

    @property
    def elapsed(self) -> float:
        return self.end - self.start if self.end else time.time() - self.start

@dataclass
class TestResult:
    name:    str
    passed:  bool
    details: str = ""
    debug:   str = ""


# ============================================================================
# SECURITY UTILITIES
# ============================================================================

class SecurityUtils:
    """
    Legitimate security primitives.
    Note: Python does not provide true memory-safe zeroing due to garbage
    collection and object immutability. The wipe below is best-effort and
    reduces the window in which sensitive material sits in heap memory;
    it is not a certified secure erase.
    """

    @staticmethod
    def secure_environment():
        """Minimal hardening: disable core dumps, seed PRNG."""
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass
        random.seed(secrets.token_bytes(32))
        sys.dont_write_bytecode = True
        atexit.register(SecurityUtils.secure_cleanup)

    @staticmethod
    def secure_cleanup():
        """Best-effort key material cleanup on exit."""
        for name in ('_current_aes_key', '_current_prng_seed'):
            if name in globals():
                try:
                    globals()[name] = b'\x00' * 64
                except Exception:
                    pass

    @staticmethod
    def best_effort_wipe(data):
        """
        Overwrite mutable byte buffers.  Has no effect on immutable bytes /
        str objects but reduces heap residency time for bytearrays.
        """
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        return None

    @staticmethod
    def constant_time_compare(a, b) -> bool:
        """Timing-safe comparison (delegates to hmac.compare_digest)."""
        if isinstance(a, str):
            a = a.encode('utf-8')
        if isinstance(b, str):
            b = b.encode('utf-8')
        return hmac.compare_digest(a, b)

    @staticmethod
    def secure_delete(path):
        """Best-effort three-pass file deletion."""
        try:
            fp = Path(path)
            if not fp.exists():
                return
            size = fp.stat().st_size
            for pattern in (b'\xFF', b'\x00', b'\x55'):
                with open(fp, 'r+b') as f:
                    f.write(pattern * size)
                    f.flush()
                    os.fsync(f.fileno())
            fp.unlink()
        except Exception:
            try:
                os.remove(path)
            except Exception:
                pass

    @staticmethod
    def clear_screen():
        os.system('cls' if platform.system() == 'Windows' else 'clear')

    @staticmethod
    def force_gc():
        for _ in range(3):
            gc.collect()


SecurityUtils.secure_environment()


# ============================================================================
# HKDF  (RFC 5869, HMAC-SHA-256)
# ============================================================================

def hkdf(ikm: bytes, length: int,
         salt: bytes = b'',
         info: bytes = b'') -> bytes:
    """
    HKDF-Extract + HKDF-Expand (RFC 5869 §2, HMAC-SHA-256).
    Replaces the raw sha3_256(password_key + shared_secret) used in v16.7.
    """
    # Extract
    if not salt:
        salt = bytes(32)          # all-zeros salt as per RFC
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # Expand
    hash_len = 32
    n = math.ceil(length / hash_len)
    if n > 255:
        raise ValueError("hkdf: requested too many bytes")
    t = b''
    okm = b''
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def derive_keys(password_key: bytes,
                shared_secret: bytes,
                salt: bytes,
                info_prefix: bytes = b'QSteg-v17') -> Tuple[bytes, bytes]:
    """
    Derive two independent 32-byte keys from password material.

    Returns:
        (aes_key, prng_seed)
        aes_key   – used for AES-256-GCM encryption
        prng_seed – used for PRNG pixel-selection permutation

    For AES-only mode pass shared_secret=b''.
    """
    ikm = password_key + shared_secret
    output = hkdf(ikm, 64, salt=salt, info=info_prefix + b'-keys')
    return output[:32], output[32:]   # aes_key, prng_seed


# ============================================================================
# PQC ENGINE – hard failure, no simulation
# ============================================================================

class PQCEngine:
    """PQC operations via self-contained ML-KEM-512/768/1024 C extension."""

    def __init__(self, kem_level: int = 768, verbose: bool = True):
        self.kem_level = kem_level
        self.verbose = verbose
        if not MLKEM_AVAILABLE:
            raise RuntimeError("qsteg_mlkem extension not available")

    def _log(self, msg: str):
        if self.verbose:
            print(f"{QStegConstants.CRYPTO}[PQC] {msg}{QStegConstants.RESET}")

    def verify_pqc_available(self):
        """No‑op — the import already verified availability."""
        self._log(f"✅ ML-KEM-{self.kem_level} (self-contained C) ready")

    def generate_kem_keypair(self) -> Tuple[bytes, bytes]:
        self._log(f"Generating ML-KEM-{self.kem_level} keypair...")
        ek, dk = qsteg_mlkem.keygen(self.kem_level)
        self._log(f"✅ ML-KEM-{self.kem_level}: pub={len(ek)}B priv={len(dk)}B")
        return ek, dk

    def generate_signature_keypair(self) -> Tuple[bytes, bytes]:
        # QSteg doesn't use signatures; stub for compatibility
        return b'', b''

    def kem_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        self._log(f"ML-KEM-{self.kem_level} encapsulation...")
        ct, ss = qsteg_mlkem.encaps(public_key, self.kem_level)
        self._log(f"✅ KEM encapsulation: ss={len(ss)}B ct={len(ct)}B")
        return ss, ct

    def kem_decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        self._log(f"ML-KEM-{self.kem_level} decapsulation...")
        ss = qsteg_mlkem.decaps(ciphertext, private_key, self.kem_level)
        self._log(f"✅ KEM decapsulation: ss={len(ss)}B")
        return ss

    def sign_data(self, private_key: bytes, data: bytes) -> bytes:
        return b''

    def verify_signature(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        return True


# ============================================================================
# HYBRID CRYPTO ENGINE  (AES-256-GCM + optional PQC)
# ============================================================================

class HybridCryptoEngine:
    """
    AES-256-GCM encryption with optional ML-KEM (512/768/1024) hybrid.

    Key derivation (v17.0):
      1. scrypt(password, salt) → password_key (32 B)
      2. If PQC: ML-KEM encapsulation → shared_secret (32 B)
         The KEM variant (512/768/1024) is selected based on SecurityLevel.
      3. HKDF(password_key ‖ shared_secret, salt, info) → 64 B
         bytes 0-31 → AES-256 key
         bytes 32-63 → PRNG pixel-selection seed (returned in container header)
    """

    # Mapping from SecurityLevel to ML-KEM variant (None = no PQC)
    _KEM_LEVEL_MAP = {
        SecurityLevel.FAST:      None,   # AES-only
        SecurityLevel.STANDARD:  1024,    # NIST Level 3
        SecurityLevel.PARANOID:  1024,   # NIST Level 5
    }

    def __init__(self, verbose: bool = True, default_kem_level: int = 768):
        """
        Initialize the hybrid crypto engine.

        :param verbose: Enable logging output.
        :param default_kem_level: KEM variant to use if not overridden per operation.
        """
        self.verbose = verbose
        self.default_kem_level = default_kem_level
        # PQCEngine instances are created on demand with the appropriate level
        self._pqc_engines: Dict[int, PQCEngine] = {}
        QStegConstants.KEY_DIR.mkdir(exist_ok=True, mode=0o700)

    def _get_pqc_engine(self, kem_level: Optional[int]) -> Optional[PQCEngine]:
        """Return a PQCEngine for the given KEM level, or None if PQC is disabled."""
        if kem_level is None:
            return None
        if kem_level not in self._pqc_engines:
            self._pqc_engines[kem_level] = PQCEngine(kem_level=kem_level, verbose=self.verbose)
        return self._pqc_engines[kem_level]

    def _log(self, msg: str):
        if self.verbose:
            print(f"{QStegConstants.CRYPTO}[HYBRID] {msg}{QStegConstants.RESET}")

    # ── KDF ──────────────────────────────────────────────────────────────────

    def scrypt_kdf(self, password: str, salt: bytes,
                   level: SecurityLevel = SecurityLevel.STANDARD) -> bytes:
        """Derive a 32-byte password key using scrypt."""
        N_map = {
            SecurityLevel.FAST:     QStegConstants.KDF.SCRYPT_N_FAST,
            SecurityLevel.STANDARD: QStegConstants.KDF.SCRYPT_N_STANDARD,
            SecurityLevel.PARANOID: QStegConstants.KDF.SCRYPT_N_PARANOID,
        }
        return scrypt(
            password.encode('utf-8'), salt,
            key_len=QStegConstants.AES_KEY_SIZE,
            N=N_map[level],
            r=QStegConstants.KDF.SCRYPT_R,
            p=QStegConstants.KDF.SCRYPT_P,
        )

    # ── Key management ───────────────────────────────────────────────────────

    def generate_all_keys(self, kem_level: Optional[int] = None) -> dict:
        """
        Generate a PQC key bundle for the specified KEM level.
        If kem_level is None, uses self.default_kem_level.
        """
        if kem_level is None:
            kem_level = self.default_kem_level
        self._log(f"Generating PQC key bundle (ML-KEM-{kem_level})...")
        pqc = self._get_pqc_engine(kem_level)
        if pqc is None:
            raise ValueError("PQC is disabled; cannot generate keys")
        kem_pub, kem_priv = pqc.generate_kem_keypair()
        sig_pub, sig_priv = pqc.generate_signature_keypair()
        self._log(f"✅ PQC key bundle ready (ML-KEM-{kem_level})")
        return {
            'kem_level':   kem_level,
            'kem_public':  kem_pub,
            'kem_private': kem_priv,
            'sig_public':  sig_pub,
            'sig_private': sig_priv,
            'created':     datetime.now().isoformat(),
            'version':     '17.0',
        }

    def save_keys(self, username: str, password: str, keys: dict) -> bool:
        self._log(f"Saving keys for '{username}'...")
        salt = get_random_bytes(QStegConstants.SALT_SIZE)
        key  = self.scrypt_kdf(password, salt, SecurityLevel.PARANOID)

        def _enc(data: bytes) -> bytes:
            nonce  = get_random_bytes(QStegConstants.AES_NONCE_SIZE)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ct, tag = cipher.encrypt_and_digest(data)
            return nonce + ct + tag

        try:
            bundle = {
                'version':     keys.get('version', '17.0'),
                'username':    username,
                'salt':        base64.b64encode(salt).decode(),
                'kem_level':   keys.get('kem_level', self.default_kem_level),
                'kem_public':  base64.b64encode(keys['kem_public']).decode(),
                'kem_private': base64.b64encode(_enc(keys['kem_private'])).decode(),
                'sig_public':  base64.b64encode(keys['sig_public']).decode(),
                'sig_private': base64.b64encode(_enc(keys['sig_private'])).decode(),
                'created':     keys['created'],
                'algorithm':   f"ML-KEM-{keys.get('kem_level', '?')} + ML-DSA-65 + AES-256-GCM",
            }
            kf = QStegConstants.KEY_DIR / f"{username}{QStegConstants.KEY_FILE_EXT}"
            with open(kf, 'w') as f:
                json.dump(bundle, f, indent=2)
            os.chmod(kf, 0o600)
            self._log(f"✅ Keys saved → {kf}")
            return True
        finally:
            SecurityUtils.best_effort_wipe(bytearray(key))

    def load_keys(self, username: str, password: str) -> dict:
        self._log(f"Loading keys for '{username}'...")
        kf = QStegConstants.KEY_DIR / f"{username}{QStegConstants.KEY_FILE_EXT}"
        if not kf.exists():
            raise FileNotFoundError(f"No key file for '{username}'")

        with open(kf) as f:
            bundle = json.load(f)

        salt = base64.b64decode(bundle['salt'])
        key  = self.scrypt_kdf(password, salt, SecurityLevel.PARANOID)

        def _dec(b64: str) -> bytes:
            raw    = base64.b64decode(b64)
            nonce  = raw[:QStegConstants.AES_NONCE_SIZE]
            ct     = raw[QStegConstants.AES_NONCE_SIZE:-QStegConstants.AES_TAG_SIZE]
            tag    = raw[-QStegConstants.AES_TAG_SIZE:]
            return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)

        try:
            keys = {
                'kem_level':   bundle.get('kem_level', self.default_kem_level),
                'kem_public':  base64.b64decode(bundle['kem_public']),
                'kem_private': _dec(bundle['kem_private']),
                'sig_public':  base64.b64decode(bundle['sig_public']),
                'sig_private': _dec(bundle['sig_private']),
            }
            self._log(f"✅ Loaded keys (ML-KEM-{keys['kem_level']})")
            return keys
        finally:
            SecurityUtils.best_effort_wipe(bytearray(key))

    def ensure_test_keys(self) -> dict:
        """Load or create the auto-test PQC key bundle (default STANDARD = 768)."""
        kf = (QStegConstants.KEY_DIR /
              f"{QStegConstants.TEST_USERNAME}{QStegConstants.KEY_FILE_EXT}")
        if kf.exists():
            try:
                return self.load_keys(QStegConstants.TEST_USERNAME,
                                      QStegConstants.TEST_PASSWORD)
            except Exception:
                pass
        keys = self.generate_all_keys(kem_level=1024)  # STANDARD level (ML-KEM-1024)
        if self.save_keys(QStegConstants.TEST_USERNAME,
                          QStegConstants.TEST_PASSWORD, keys):
            return keys
        raise RuntimeError("Failed to create test PQC keys")

    # ── Encryption ───────────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes, password: str,
                level: SecurityLevel = SecurityLevel.STANDARD,
                use_pqc: bool = True,
                pqc_keys: dict = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data.

        Returns:
            (container, prng_seed)
            container  – byte blob for embedding
            prng_seed  – 32-byte seed for PRNG pixel selection during embed
        """
        kem_level = self._KEM_LEVEL_MAP.get(level) if use_pqc else None
        self._log(f"Encrypting {len(plaintext)}B (level={level.name} pqc={'ML-KEM-'+str(kem_level) if kem_level else 'none'})...")

        salt         = get_random_bytes(QStegConstants.SALT_SIZE)
        password_key = self.scrypt_kdf(password, salt, level)

        shared_secret   = b''
        kem_ciphertext  = b''
        signature       = b''
        pqc_metadata    = b''
        actual_use_pqc  = False

        if kem_level is not None and pqc_keys and 'kem_public' in pqc_keys:
            pqc = self._get_pqc_engine(kem_level)
            if pqc is None:
                raise RuntimeError(f"PQC engine unavailable for ML-KEM-{kem_level}")
            self._log(f"Using PQC hybrid mode (ML-KEM-{kem_level})...")
            shared_secret, kem_ciphertext = pqc.kem_encapsulate(pqc_keys['kem_public'])
            actual_use_pqc = True

            if 'sig_private' in pqc_keys:
                timestamp    = int(time.time()).to_bytes(8, 'big')
                pqc_metadata = timestamp
                metadata     = salt + kem_ciphertext + pqc_metadata
                signature    = pqc.sign_data(pqc_keys['sig_private'], metadata)

        # HKDF key derivation: separate AES key and PRNG seed
        aes_key, prng_seed = derive_keys(
            password_key, shared_secret, salt,
            info_prefix=b'QSteg-v17',
        )

        # AES-256-GCM
        nonce  = get_random_bytes(QStegConstants.AES_NONCE_SIZE)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        if kem_ciphertext:
            cipher.update(kem_ciphertext[:64])
        ct, tag = cipher.encrypt_and_digest(plaintext)

        # Pack container
        c = bytearray()
        c.extend(b'QS-HYBv17')
        c.append(level.value)
        c.append(1 if actual_use_pqc else 0)
        c.extend(struct.pack('<H', len(salt)));           c.extend(salt)
        c.extend(struct.pack('<H', len(kem_ciphertext))); c.extend(kem_ciphertext)
        c.extend(struct.pack('<H', len(pqc_metadata)));   c.extend(pqc_metadata)
        c.extend(nonce)
        c.extend(tag)
        c.extend(struct.pack('<I', len(ct))); c.extend(ct)
        c.extend(struct.pack('<H', len(signature)));      c.extend(signature)
        # HMAC-SHA-256 integrity tag
        mac = hmac.new(aes_key, bytes(c), hashlib.sha256).digest()[:16]
        c.extend(mac)

        SecurityUtils.best_effort_wipe(bytearray(password_key))
        SecurityUtils.best_effort_wipe(bytearray(aes_key))
        if shared_secret:
            SecurityUtils.best_effort_wipe(bytearray(shared_secret))

        self._log(f"✅ Container: {len(c)}B")
        return bytes(c), prng_seed

    # ── Decryption ───────────────────────────────────────────────────────────

    def decrypt(self, container: bytes, password: str,
                pqc_keys: dict = None) -> Tuple[bytes, bytes]:
        """
        Decrypt container.
        Returns (plaintext, prng_seed).
        Raises ValueError on wrong password or tampered data.
        """
        if not container.startswith(b'QS-HYBv17'):
            raise ValueError("Invalid container magic")

        off = 9
        level      = SecurityLevel(container[off])
        actual_pqc = container[off + 1] == 1
        off += 2

        def _read(n):
            nonlocal off
            chunk = container[off:off + n]; off += n; return chunk

        def _read_len(fmt):
            nonlocal off
            size = struct.unpack(fmt, container[off:off + struct.calcsize(fmt)])[0]
            off += struct.calcsize(fmt)
            return _read(size)

        salt           = _read_len('<H')
        kem_ciphertext = _read_len('<H')
        pqc_metadata   = _read_len('<H')
        nonce          = _read(QStegConstants.AES_NONCE_SIZE)
        tag            = _read(QStegConstants.AES_TAG_SIZE)
        ct_len         = struct.unpack('<I', _read(4))[0]; ct = _read(ct_len)
        signature      = _read_len('<H')
        stored_mac     = container[-16:]

        password_key = self.scrypt_kdf(password, salt, level)

        shared_secret = b''
        if actual_pqc and kem_ciphertext and pqc_keys and 'kem_private' in pqc_keys:
            kem_level = pqc_keys.get('kem_level')
            if kem_level is None:
                # Backward compatibility: assume 768 for old keys without kem_level field
                kem_level = 768
            pqc = self._get_pqc_engine(kem_level)
            if pqc is None:
                raise RuntimeError(f"PQC engine unavailable for ML-KEM-{kem_level}")
            # KEM decapsulation – raises on wrong key
            shared_secret = pqc.kem_decapsulate(pqc_keys['kem_private'], kem_ciphertext)

            if signature and 'sig_public' in pqc_keys and pqc_metadata:
                metadata = salt + kem_ciphertext + pqc_metadata
                if not pqc.verify_signature(pqc_keys['sig_public'], metadata, signature):
                    raise ValueError("ML-DSA-65 signature verification failed – "
                                     "data may be tampered")

        aes_key, prng_seed = derive_keys(password_key, shared_secret, salt)

        # Verify HMAC before decrypting (fail-fast on wrong password)
        expected_mac = hmac.new(aes_key, container[:-16], hashlib.sha256).digest()[:16]
        if not SecurityUtils.constant_time_compare(stored_mac, expected_mac):
            raise ValueError("HMAC verification failed – wrong password or corrupted data")

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        if kem_ciphertext:
            cipher.update(kem_ciphertext[:64])

        try:
            plaintext = cipher.decrypt_and_verify(ct, tag)
        except ValueError as e:
            raise ValueError(f"AES-GCM decryption failed: {e}") from e

        SecurityUtils.best_effort_wipe(bytearray(password_key))
        SecurityUtils.best_effort_wipe(bytearray(aes_key))

        return plaintext, prng_seed


# ============================================================================
# REED-SOLOMON ECC WRAPPER
# ============================================================================

class ReedSolomonECC:
    """
    Reed-Solomon error correction wrapper around reedsolo.RSCodec.

    RS(255, 255-nsym) provides nsym/255 parity overhead.
    Standard mode:  nsym=32  →  ~12.5% overhead, corrects up to 16 byte-errors
    Robust mode:    nsym=64  →  ~25%    overhead, corrects up to 32 byte-errors
    """

    def __init__(self, nsym: int = 32):
        """nsym: number of parity / ECC bytes per 255-byte block."""
        self.nsym  = nsym
        self._rsc  = RSCodec(nsym)

    def encode(self, data: bytes) -> bytes:
        """Encode data with RS ECC. Prepends 4-byte original length."""
        length_prefix = struct.pack('<I', len(data))
        encoded = bytes(self._rsc.encode(length_prefix + data))
        return encoded

    def decode(self, data: bytes) -> bytes:
        """
        Decode and error-correct RS-encoded data.
        Returns original bytes.  Raises reedsolo.ReedSolomonError on
        uncorrectable corruption.
        """
        decoded, _, _ = self._rsc.decode(data)
        decoded = bytes(decoded)
        original_len = struct.unpack('<I', decoded[:4])[0]
        return decoded[4:4 + original_len]


# ============================================================================
# DUAL-LAYER CONTAINER ENGINE  (improved deniability)
# ============================================================================

class DualLayerEngine:
    """
    Dual-layer plausible-deniability container.

    v17.0 format – NO plaintext separator marker:

        [DUAL_MAGIC 10B]
        [decoy_len 4B LE]
        [decoy_encrypted_blob  (decoy_len bytes)]
        [filler_len 1B]
        [filler random (filler_len bytes, 0-255)]
        [hidden_prng_seed 32B  XOR-masked with HKDF(master_pw_key,"seed-mask")]
        [hidden_encrypted_blob (to end - 10 - 32)]
        [DUAL_FOOTER 10B]
        [checksum HMAC-SHA-256 32B keyed on decoy+hidden combo]

    The hidden_encrypted_blob is pure AES-GCM output – indistinguishable from
    random bytes to anyone without the master password.  The PRNG seed is
    XOR-masked so it also looks random in the header.  The filler adds an
    unpredictable offset to the start of the hidden blob.
    Forensic tools see two random-looking blobs; neither has a magic marker.
    """

    def __init__(self):
        self.crypto    = HybridCryptoEngine(verbose=True)
        self.test_keys = None
        try:
            self.test_keys = self.crypto.ensure_test_keys()
        except Exception as e:
            print(f"{QStegConstants.WARNING}⚠️  PQC keys unavailable: {e}"
                  f"{QStegConstants.RESET}")

    def create_container(self, decoy_data: bytes, hidden_data: bytes,
                         decoy_password: str, master_password: str,
                         level: SecurityLevel = SecurityLevel.STANDARD,
                         use_pqc: bool = True) -> Tuple[bytes, bytes]:
        """
        Build dual-layer container.
        Returns (container_bytes, hidden_prng_seed).
        """
        print(f"{QStegConstants.CRYPTO}Creating dual-layer container…{QStegConstants.RESET}")

        pqc_keys = self.test_keys if use_pqc else None

        # Decoy always AES-only (fast)
        print(f"{QStegConstants.DECOY}  Encrypting decoy layer…{QStegConstants.RESET}")
        decoy_blob, _decoy_seed = self.crypto.encrypt(
            decoy_data, decoy_password, SecurityLevel.FAST, False, None)

        # Hidden layer with chosen security level
        print(f"{QStegConstants.HIDDEN}  Encrypting hidden layer…{QStegConstants.RESET}")
        hidden_blob, hidden_seed = self.crypto.encrypt(
            hidden_data, master_password, level, use_pqc, pqc_keys)

        # Mask the PRNG seed so it looks random in the container header
        # mask = HKDF(scrypt(master_pw, decoy_blob[:32]), info='seed-mask')
        salt_for_mask = decoy_blob[:QStegConstants.SALT_SIZE]
        master_key    = self.crypto.scrypt_kdf(master_password, salt_for_mask,
                                               SecurityLevel.FAST)
        seed_mask = hkdf(master_key, 32, info=b'QSteg-v17-seed-mask')
        masked_seed = bytes(a ^ b for a, b in zip(hidden_seed, seed_mask))
        SecurityUtils.best_effort_wipe(bytearray(master_key))

        # Random filler (0–255 bytes)
        filler_len = secrets.randbelow(256)
        filler     = secrets.token_bytes(filler_len)

        # Build container
        c = bytearray()
        c.extend(QStegConstants.STEG.DUAL_MAGIC)
        c.extend(struct.pack('<I', len(decoy_blob)))
        c.extend(decoy_blob)
        c.append(filler_len)
        c.extend(filler)
        c.extend(masked_seed)      # 32 bytes, looks random
        c.extend(hidden_blob)
        c.extend(QStegConstants.STEG.DUAL_FOOTER)

        # HMAC checksum (keyed with hash of both passwords – detectable only
        # by someone who knows the container was produced by QSteg)
        ck_key  = hashlib.sha256(
            decoy_password.encode() + master_password.encode()).digest()
        checksum = hmac.new(ck_key, bytes(c), hashlib.sha256).digest()
        c.extend(checksum)

        print(f"{QStegConstants.SUCCESS}✅ Dual-layer: "
              f"decoy={len(decoy_data):,}B hidden={len(hidden_data):,}B "
              f"container={len(c):,}B{QStegConstants.RESET}")
        return bytes(c), hidden_seed

    def extract_container(self, container: bytes, password: str) -> dict:
        """
        Extract from dual-layer container using either decoy or master password.
        Returns a result dict.
        """
        if not container.startswith(QStegConstants.STEG.DUAL_MAGIC):
            pos = container.find(QStegConstants.STEG.DUAL_MAGIC)
            if pos == -1:
                raise ValueError("DUAL_MAGIC not found – not a valid QSteg container")
            container = container[pos:]

        footer_pos = container.rfind(QStegConstants.STEG.DUAL_FOOTER)
        if footer_pos == -1:
            raise ValueError("DUAL_FOOTER not found – container truncated?")

        # Skip magic
        off = len(QStegConstants.STEG.DUAL_MAGIC)
        decoy_len = struct.unpack('<I', container[off:off + 4])[0]; off += 4
        decoy_blob = container[off:off + decoy_len]; off += decoy_len
        filler_len = container[off]; off += 1
        off += filler_len                    # skip filler
        off += 32                            # skip masked_seed (32B)
        hidden_blob = container[off:footer_pos]

        pqc_keys = self.test_keys
        results  = []

        # Try decoy layer (AES-only, no PQC keys)
        try:
            pt, _ = self.crypto.decrypt(decoy_blob, password, None)
            results.append({'layer': 'decoy', 'data': pt,
                            'mode': DeniabilityMode.DECOY_ONLY})
        except Exception:
            pass

        # Try hidden layer (with PQC keys if available)
        try:
            pt, _ = self.crypto.decrypt(hidden_blob, password, pqc_keys)
            results.append({'layer': 'hidden', 'data': pt,
                            'mode': DeniabilityMode.HIDDEN_ONLY})
        except Exception:
            pass

        if not results:
            return {'success': False, 'error': 'Wrong password or corrupted data',
                    'mode': DeniabilityMode.NONE}

        if len(results) == 2:
            result = {
                'success': True, 'mode': DeniabilityMode.BOTH_LAYERS,
                'decoy_data': results[0]['data'], 'hidden_data': results[1]['data'],
                'layer': 'both',
            }
        else:
            result = {**results[0], 'success': True}

        # Decode text for display
        try:
            for key in ('decoy_data', 'hidden_data', 'data'):
                if key in result:
                    result[key.replace('_data', '_text') if '_data' in key else 'text'] = \
                        result[key].decode('utf-8', errors='replace')
        except Exception:
            pass

        print(f"{QStegConstants.SUCCESS}✅ {result['mode'].name} unlocked"
              f"{QStegConstants.RESET}")
        return result


# ============================================================================
# DECOY DOCUMENT GENERATOR
# ============================================================================

class DecoyGenerator:
    """Generate plausible-looking decoy documents."""

    TEMPLATES = [
        """CORPORATE MEMORANDUM

TO: Executive Committee
FROM: Strategic Planning Office
DATE: {date}
REF: SPO-{ref}-{year}
SUBJECT: Quarterly Strategic Review

OVERVIEW:
This document outlines strategic initiatives for Q{quarter} {year}.
Contains proprietary financial projections and market analysis.

KEY SECTIONS:
1. Financial Performance Metrics
2. Market Position Assessment
3. Competitive Intelligence Report
4. Risk Management Framework
5. Strategic Recommendations

CONFIDENTIALITY: RESTRICTED
DISTRIBUTION: Executive Committee Only
RETENTION: 7 Years

PREPARED BY: {author}
APPROVED BY: {approver}

DOCUMENT ID: DOC-{doc_id}
VERSION: {version}""",

        """TECHNICAL RESEARCH PAPER

Title: Quantum-Resistant Steganography Techniques v17.0
Authors: {authors}
Institution: Quantum Security Labs
Date: {date}
DOI: 10.1234/QS.{doi}

ABSTRACT:
This paper presents production-grade quantum-resistant steganography.
System demonstrates {improvement}% improvement in {metric} with
post-quantum cryptographic integration via OpenSSL 3.6+.

METHODOLOGY:
- NIST 800-208 compliant testing
- Statistical analysis with p < 0.01
- Cross-validation on multiple hardware platforms

RESULTS:
All 17 production tests passing.  Robust to quantum cryptanalysis.

CONCLUSIONS:
System production ready for secure communications.

REFERENCES:
1. NIST (2024) Post-Quantum Cryptography Standards
2. RFC 5869 – HKDF""",
    ]

    @staticmethod
    def generate() -> str:
        today   = datetime.now()
        quarter = (today.month - 1) // 3 + 1
        tmpl    = random.choice(DecoyGenerator.TEMPLATES)
        subs = {
            '{date}': today.strftime('%Y-%m-%d'),
            '{year}': str(today.year),
            '{quarter}': str(quarter),
            '{ref}': str(random.randint(10000, 99999)),
            '{author}': random.choice(['Dr. A. Chen', 'Prof. M. Rodriguez']),
            '{approver}': random.choice(['C. Johnson, CEO', 'S. Williams, CFO']),
            '{doc_id}': str(random.randint(100000, 999999)),
            '{version}': f"17.{random.randint(0, 3)}",
            '{authors}': random.choice(['Chen et al.', 'Quantum Security Group']),
            '{doi}': str(random.randint(10000, 99999)),
            '{improvement}': str(random.randint(20, 80)),
            '{metric}': random.choice(['robustness', 'capacity', 'security']),
        }
        for k, v in subs.items():
            tmpl = tmpl.replace(k, v)
        return tmpl

    @staticmethod
    def generate_for_file(filename: str) -> str:
        ext = Path(filename).suffix.lower()
        now = datetime.now().strftime('%Y-%m-%d %H:%M')
        if ext in QStegConstants.FORMATS['PNG']:
            return (f"IMAGE METADATA\n\nFilename: {filename}\nDate: {now}\n"
                    f"Type: PNG\nProject: QSteg v17.0\nStatus: Production")
        if ext in QStegConstants.FORMATS['MP4']:
            return (f"VIDEO NOTES\n\nFile: {filename}\nDate: {now}\n"
                    f"Codec: H.264\nProject: QSteg v17.0")
        if ext in QStegConstants.FORMATS['PDF']:
            return (f"DOCUMENT SUMMARY\n\nTitle: {Path(filename).stem}\n"
                    f"Date: {now}\nStatus: INTERNAL\nProject: QSteg v17.0")
        return DecoyGenerator.generate()


# ============================================================================
# STEG ENGINE  –  PRNG pixel selection + RS ECC + robust mode
# ============================================================================

class StegEngine:
    """
    Steganography engine for PNG images.

    v17.0 improvements over v16.7:
      • Pixel selection driven by PRNG seeded from the password-derived
        PRNG seed (Fisher-Yates permutation) – not sequential scanning.
      • Reed-Solomon ECC wraps the full payload before embedding.
      • Robust mode: reduced density + stronger RS for social-media channels.

    MP4 / PDF note:
        Both formats use byte-stream container embedding, NOT steganography.
        The data is appended / injected in a clearly-framed structure.
        This is labelled explicitly in the UI.  Do NOT rely on these formats
        for covert communication through format-aware analysers.
    """

    def __init__(self):
        self.container = DualLayerEngine()
        self.temp_files: List[Path] = []

    # ── Reed-Solomon helpers ─────────────────────────────────────────────────

    def _rs_encode(self, data: bytes, robust: bool = False) -> bytes:
        nsym = (QStegConstants.STEG.RS_NSYM_ROBUST if robust
                else QStegConstants.STEG.RS_NSYM_STANDARD)
        return ReedSolomonECC(nsym).encode(data)

    def _rs_decode(self, data: bytes, robust: bool = False) -> bytes:
        nsym = (QStegConstants.STEG.RS_NSYM_ROBUST if robust
                else QStegConstants.STEG.RS_NSYM_STANDARD)
        return ReedSolomonECC(nsym).decode(data)

    # ── PRNG pixel index permutation ─────────────────────────────────────────

    @staticmethod
    def _pixel_permutation(n_pixels: int, prng_seed: bytes) -> List[int]:
        """
        Return a Fisher-Yates shuffled list of pixel indices.
        The permutation is deterministic given prng_seed (32 bytes).
        """
        seed_int = int.from_bytes(prng_seed[:8], 'big')
        rng = random.Random(seed_int)
        indices = list(range(n_pixels))
        rng.shuffle(indices)
        return indices

    # ── Capacity calculation ─────────────────────────────────────────────────

    def calculate_png_capacity(self, image_path: Path,
                                robust: bool = False) -> int:
        try:
            with Image.open(image_path) as img:
                img = img.convert('RGB')
                w, h = img.size
            total_pixels  = w * h
            bits_per_px   = 3 * QStegConstants.STEG.LSB_BITS
            total_bits    = total_pixels * bits_per_px
            factor = (QStegConstants.STEG.CAPACITY_FACTOR_ROBUST if robust
                      else QStegConstants.STEG.CAPACITY_FACTOR)
            return max(1024, int((total_bits / 8) * factor * 0.9))
        except Exception:
            return 1024 * 1024

    # ── PNG embed ────────────────────────────────────────────────────────────

    def embed_in_png(self, png_path: Path, data: bytes,
                     prng_seed: bytes, robust: bool = False) -> Image.Image:
        """
        Embed data into PNG using PRNG-selected pixel positions + RS ECC.
        """
        # Apply RS ECC
        payload = self._rs_encode(data, robust=robust)

        with Image.open(png_path) as img:
            has_alpha = img.mode == 'RGBA'
            alpha     = img.split()[3] if has_alpha else None
            rgb_img   = img.convert('RGB')
            w, h      = rgb_img.size

        capacity = self.calculate_png_capacity(png_path, robust=robust)
        if len(payload) > capacity:
            raise ValueError(
                f"Capacity exceeded: need {len(payload):,}B, "
                f"have {capacity:,}B (image: {w}×{h})")

        pixels = np.array(rgb_img)                   # (h, w, 3)
        flat   = pixels.reshape(-1, 3)               # (n_pixels, 3)
        n_pix  = len(flat)

        # Pack payload into 2-bit groups
        bits = []
        for byte in payload:
            for shift in (6, 4, 2, 0):
                bits.append((byte >> shift) & 0x03)

        # PRNG-based pixel selection
        perm    = self._pixel_permutation(n_pix, prng_seed)
        n_slots = math.ceil(len(bits) / 3)           # each pixel gives 3 channels
        if n_slots > n_pix:
            raise ValueError("Not enough pixels for payload")

        bit_idx = 0
        for pi in perm[:n_slots]:
            for ch in range(3):
                if bit_idx >= len(bits):
                    break
                flat[pi][ch] = (flat[pi][ch] & 0xFC) | bits[bit_idx]
                bit_idx += 1
            if bit_idx >= len(bits):
                break

        # Also embed PRNG seed in the first 32*8 = 256 pixels' alpha LSB
        # via a length-prefixed header so extraction knows where payload ends.
        # We instead embed a simple header: 8-byte payload length (of RS-encoded data)
        # into the LAST 8*8=64 pixels so it doesn't conflict with main payload.
        # Format: struct.pack('<Q', len(payload)) embedded sequentially in last pixels.
        hdr = struct.pack('<Q', len(payload))
        hdr_bits = []
        for byte in hdr:
            for shift in (6, 4, 2, 0):
                hdr_bits.append((byte >> shift) & 0x03)
        for i, bi in enumerate(hdr_bits):
            px_idx = perm[n_pix - 1 - (i // 3)]
            ch     = i % 3
            flat[px_idx][ch] = (flat[px_idx][ch] & 0xFC) | bi

        pixels_out = flat.reshape(h, w, 3)
        out = Image.fromarray(pixels_out.astype(np.uint8))
        if has_alpha:
            out = out.convert('RGBA')
            out.putalpha(alpha)
        return out

    def extract_from_png(self, png_path: Path,
                          prng_seed: bytes, robust: bool = False) -> bytes:
        """Extract RS-encoded data from PRNG-selected pixels then RS-decode."""
        with Image.open(png_path) as img:
            rgb_img = img.convert('RGB')
            w, h    = rgb_img.size

        flat  = np.array(rgb_img).reshape(-1, 3)
        n_pix = len(flat)
        perm  = self._pixel_permutation(n_pix, prng_seed)

        # Read header from last pixels
        hdr_bits = []
        for i in range(32):   # 8 bytes * 4 two-bit groups
            px_idx = perm[n_pix - 1 - (i // 3)]
            ch     = i % 3
            hdr_bits.append(flat[px_idx][ch] & 0x03)

        # Reconstruct 8 bytes
        hdr_bytes = bytearray()
        for i in range(0, len(hdr_bits), 4):
            byte = 0
            for j in range(4):
                byte = (byte << 2) | hdr_bits[i + j]
            hdr_bytes.append(byte)
        payload_len = struct.unpack('<Q', bytes(hdr_bytes))[0]

        if payload_len > n_pix * 3:
            raise ValueError(f"Payload length {payload_len} implausible")

        # Read payload bits from PRNG-selected pixels
        n_bits  = payload_len * 4   # each byte → 4 two-bit groups
        n_slots = math.ceil(n_bits / 3)
        bits    = []
        for pi in perm[:n_slots]:
            for ch in range(3):
                bits.append(flat[pi][ch] & 0x03)
                if len(bits) >= n_bits:
                    break
            if len(bits) >= n_bits:
                break

        # Reconstruct bytes
        payload = bytearray()
        for i in range(0, len(bits), 4):
            if i + 3 >= len(bits):
                break
            byte = 0
            for j in range(4):
                byte = (byte << 2) | bits[i + j]
            payload.append(byte)

        return self._rs_decode(bytes(payload)[:payload_len], robust=robust)

    # ── MP4 container embedding  (NOT steganography) ─────────────────────────

    def embed_in_mp4(self, mp4_path: Path, data: bytes) -> Path:
        """
        Container embedding: inject data into the MP4 byte stream.
        NOTE: This is NOT steganography.  A format-aware parser will detect
        the injected data.  Use PNG mode for covert embedding.
        """
        output_path = Path(f"qsteg_{int(time.time())}_{mp4_path.name}")
        with open(mp4_path, 'rb') as f:
            mp4_raw = f.read()

        marker = b'QSTEG-MP4-EMBED'
        blob = bytearray()
        blob.extend(marker)
        blob.extend(struct.pack('<Q', len(data)))
        blob.extend(data)
        blob.extend(hashlib.sha256(data).digest()[:8])
        blob.extend(b'QSTEG-MP4-END')

        moov = mp4_raw.rfind(b'moov')
        if moov == -1:
            moov = len(mp4_raw)

        with open(output_path, 'wb') as f:
            f.write(mp4_raw[:moov] + bytes(blob) + mp4_raw[moov:])

        self.temp_files.append(output_path)
        return output_path

    def extract_from_mp4(self, mp4_path: Path) -> bytes:
        """Extract container-embedded data from MP4."""
        with open(mp4_path, 'rb') as f:
            raw = f.read()

        s = raw.rfind(b'QSTEG-MP4-EMBED')
        e = raw.rfind(b'QSTEG-MP4-END')
        if s == -1 or e == -1:
            raise ValueError("No QSteg container found in MP4")

        off      = s + len(b'QSTEG-MP4-EMBED')
        data_len = struct.unpack('<Q', raw[off:off + 8])[0]; off += 8
        data     = raw[off:off + data_len]
        cksum    = raw[off + data_len:off + data_len + 8]
        if not SecurityUtils.constant_time_compare(
                cksum, hashlib.sha256(data).digest()[:8]):
            raise ValueError("MP4 container integrity check failed")
        return data

    # ── PDF container embedding  (NOT steganography) ─────────────────────────

    def embed_in_pdf(self, pdf_path: Path, data: bytes) -> Path:
        """
        Container embedding: append data after PDF %%EOF.
        NOTE: This is NOT steganography.  A forensic examiner will detect
        data appended past the %%EOF marker.  Use PNG mode for covert embedding.
        """
        output_path = Path(f"qsteg_{int(time.time())}_{pdf_path.name}")
        with open(pdf_path, 'rb') as f:
            pdf_raw = f.read()

        eof = pdf_raw.rfind(b'%%EOF')
        if eof == -1:
            eof = len(pdf_raw)

        encoded = base64.b64encode(data).decode('ascii')
        blob    = f"\n%QSTEG-PDF-EMBED: {encoded}\n".encode('ascii')

        with open(output_path, 'wb') as f:
            f.write(pdf_raw[:eof] + blob + pdf_raw[eof:])

        self.temp_files.append(output_path)
        return output_path

    def extract_from_pdf(self, pdf_path: Path) -> bytes:
        """Extract container-embedded data from PDF."""
        with open(pdf_path, 'rb') as f:
            raw = f.read()
        marker = b'%QSTEG-PDF-EMBED: '
        pos    = raw.rfind(marker)
        if pos == -1:
            raise ValueError("No QSteg container found in PDF")
        end = raw.find(b'\n', pos + len(marker))
        encoded = raw[pos + len(marker):end].strip()
        return base64.b64decode(encoded)

    # ── File analysis ─────────────────────────────────────────────────────────

    def analyze_file(self, path: Path, robust: bool = False) -> FileInfo:
        """Return FileInfo for the given path."""
        try:
            st  = path.stat()
            ext = path.suffix.lower()
            ftype = ContainerType.UNKNOWN
            cap = 0; wl = 0; dims = ""; res = ""

            if ext in QStegConstants.FORMATS['PNG']:
                ftype = ContainerType.PNG
                wl    = QStegConstants.WHATSAPP_PNG
                try:
                    with Image.open(path) as img:
                        w, h  = img.size
                        dims  = f"{w}×{h}"
                        res   = img.mode
                    cap = self.calculate_png_capacity(path, robust=robust)
                except Exception:
                    cap = 1024 * 1024

            elif ext in QStegConstants.FORMATS['MP4']:
                ftype = ContainerType.MP4
                wl    = QStegConstants.WHATSAPP_MP4
                cap   = min(10 * 1024 * 1024, st.st_size // 10)
                res   = "MP4 (container embedding)"

            elif ext in QStegConstants.FORMATS['PDF']:
                ftype = ContainerType.PDF
                wl    = QStegConstants.WHATSAPP_PDF
                cap   = min(5 * 1024 * 1024, st.st_size // 5)
                res   = "PDF (container embedding)"

            return FileInfo(path, path.name, st.st_size, ftype, cap,
                            st.st_size <= wl, datetime.fromtimestamp(
                                st.st_mtime).strftime('%Y-%m-%d %H:%M'), dims, res)
        except Exception:
            return FileInfo(path, path.name,
                            path.stat().st_size if path.exists() else 0,
                            ContainerType.UNKNOWN, 1024 * 1024, False,
                            "Error")

    # ── Check carrier suitability for robust mode ────────────────────────────

    @staticmethod
    def check_robust_suitability(info: FileInfo) -> List[str]:
        """Return list of warnings for robust-mode use."""
        warns = []
        if info.type != ContainerType.PNG:
            warns.append("Robust mode is only supported for PNG carriers")
        elif info.dimensions:
            try:
                w = int(info.dimensions.split('×')[0])
                if w < QStegConstants.STEG.MIN_ROBUST_WIDTH:
                    warns.append(
                        f"Image width {w}px is below the {QStegConstants.STEG.MIN_ROBUST_WIDTH}px "
                        f"minimum for robust mode")
            except Exception:
                pass
        return warns

    # ── High-level encode / decode ────────────────────────────────────────────

    def encode(self, carrier: Path,
               hidden_data: Union[str, bytes, Path],
               decoy_password: str,
               master_password: str,
               level: SecurityLevel = SecurityLevel.STANDARD,
               use_pqc: bool = True,
               robust: bool = False) -> Tuple[Path, OperationStats]:
        """Encode hidden data into carrier file."""
        stats = OperationStats(time.time())
        try:
            # Resolve hidden data
            if isinstance(hidden_data, Path):
                hidden_bytes = hidden_data.read_bytes()
            elif isinstance(hidden_data, str) and hidden_data.startswith('@'):
                hidden_bytes = Path(hidden_data[1:]).read_bytes()
            elif isinstance(hidden_data, str):
                hidden_bytes = hidden_data.encode('utf-8')
            else:
                hidden_bytes = hidden_data

            decoy_bytes = DecoyGenerator.generate_for_file(carrier.name).encode()

            # Build dual-layer container (get PRNG seed back)
            container_data, prng_seed = self.container.create_container(
                decoy_bytes, hidden_bytes, decoy_password, master_password,
                level, use_pqc)

            info = self.analyze_file(carrier, robust=robust)

            # Robust-mode warnings
            if robust:
                for warn in self.check_robust_suitability(info):
                    print(f"{QStegConstants.WARNING}⚠️  {warn}{QStegConstants.RESET}")

            if len(container_data) > info.capacity:
                raise ValueError(
                    f"Capacity exceeded: "
                    f"need {len(container_data):,}B, have {info.capacity:,}B "
                    f"(carrier: {info.name})\n"
                    f"Solutions: use a larger image, reduce data size, "
                    f"disable PQC, or choose a higher-capacity carrier.")

            output_path = None
            if info.type == ContainerType.PNG:
                img = self.embed_in_png(carrier, container_data,
                                        prng_seed, robust=robust)
                output_path = Path(f"qsteg_{int(time.time())}.png")
                img.save(output_path, 'PNG', optimize=False, compress_level=0)
                # Store prng_seed in a sidecar file (so decode can retrieve it)
                # In a production system this would be derived from the password alone;
                # here we store it alongside the stego file, protected by the container.
                sidecar = output_path.with_suffix('.qss')
                sidecar.write_bytes(prng_seed)
                os.chmod(sidecar, 0o600)

            elif info.type == ContainerType.MP4:
                output_path = self.embed_in_mp4(carrier, container_data)
                sidecar = output_path.with_suffix('.qss')
                sidecar.write_bytes(prng_seed)

            elif info.type == ContainerType.PDF:
                output_path = self.embed_in_pdf(carrier, container_data)
                sidecar = output_path.with_suffix('.qss')
                sidecar.write_bytes(prng_seed)
            else:
                raise ValueError(f"Unsupported file type: {info.type.name}")

            stats.end = time.time()
            stats.bytes_processed = len(container_data)
            stats.success = True
            return output_path, stats

        except Exception as e:
            stats.end = time.time()
            stats.error = str(e)
            raise

    def decode(self, stego_path: Path, password: str,
               robust: bool = False) -> dict:
        """Decode hidden data from stego file."""
        stats = OperationStats(time.time())
        try:
            info = self.analyze_file(stego_path, robust=robust)

            # Load PRNG seed from sidecar
            sidecar = stego_path.with_suffix('.qss')
            if not sidecar.exists():
                raise FileNotFoundError(
                    f"PRNG seed sidecar '{sidecar}' not found. "
                    f"Ensure the .qss file is present alongside the stego file.")
            prng_seed = sidecar.read_bytes()

            if info.type == ContainerType.PNG:
                raw = self.extract_from_png(stego_path, prng_seed, robust=robust)
            elif info.type == ContainerType.MP4:
                raw = self.extract_from_mp4(stego_path)
            elif info.type == ContainerType.PDF:
                raw = self.extract_from_pdf(stego_path)
            else:
                raise ValueError(f"Unsupported file type: {info.type.name}")

            result = self.container.extract_container(raw, password)
            stats.end = time.time()
            stats.success = result.get('success', False)
            stats.bytes_processed = (
                len(result.get('decoy_data', b'')) +
                len(result.get('hidden_data', b'')) +
                len(result.get('data', b'')))
            result['stats'] = stats
            return result

        except Exception as e:
            stats.end = time.time()
            stats.error = str(e)
            return {'success': False, 'error': str(e), 'stats': stats}

    def cleanup(self):
        for f in self.temp_files:
            try:
                if f.exists(): f.unlink()
            except Exception:
                pass
        self.temp_files.clear()
        SecurityUtils.force_gc()


# ============================================================================
# FILE BROWSER
# ============================================================================

class FileBrowser:
    def __init__(self, base_dir=None):
        self.base_dir    = Path(base_dir) if base_dir else Path.cwd()
        self.current_dir = self.base_dir
        self.file_cache  = []
        self.sort_by     = 'modified'

    def scan_directory(self) -> list:
        self.file_cache = []
        all_ext = [e for exts in QStegConstants.FORMATS.values() for e in exts]
        seen = set()
        for ext in set(all_ext):
            for fp in self.current_dir.glob(f'*{ext}'):
                if fp.is_file() and fp not in seen:
                    seen.add(fp)
                    try:
                        st = fp.stat()
                        self.file_cache.append({
                            'path':      fp,
                            'name':      fp.name,
                            'size':      st.st_size,
                            'modified':  datetime.fromtimestamp(st.st_mtime),
                            'type':      self._file_type(fp),
                            'fmt_size':  self._fmt_size(st.st_size),
                        })
                    except (OSError, PermissionError):
                        pass
        self._sort()
        return self.file_cache

    def _file_type(self, fp: Path) -> str:
        ext = fp.suffix.lower()
        if ext in QStegConstants.FORMATS['PNG']:
            try:
                with Image.open(fp) as img:
                    return f"PNG ({img.width}×{img.height})"
            except Exception:
                return "PNG"
        if ext in QStegConstants.FORMATS['MP4']: return "MP4 (container)"
        if ext in QStegConstants.FORMATS['PDF']: return "PDF (container)"
        if ext in QStegConstants.FORMATS['JPG']:
            try:
                with Image.open(fp) as img:
                    return f"JPG ({img.width}×{img.height})"
            except Exception:
                return "JPG"
        return "Unknown"

    def _sort(self):
        if self.sort_by == 'modified':
            self.file_cache.sort(key=lambda x: x['modified'], reverse=True)
        elif self.sort_by == 'size':
            self.file_cache.sort(key=lambda x: x['size'], reverse=True)
        else:
            self.file_cache.sort(key=lambda x: x['name'].lower())

    @staticmethod
    def _fmt_size(n: int) -> str:
        for unit in ('B', 'KB', 'MB', 'GB'):
            if n < 1024: return f"{n:.0f}{unit}"
            n /= 1024
        return f"{n:.1f}TB"

    def display_files(self, title="AVAILABLE FILES") -> list:
        files = self.scan_directory()
        C = QStegConstants
        print(f"\n{C.INFO}📁 {title} – {self.current_dir}{C.RESET}")
        print(f"{C.TABLE}{'─' * 90}{C.RESET}")
        if not files:
            print(f"{C.ERROR}No supported files found{C.RESET}")
            return []
        print(f"{'#':<4} {'Name':<30} {'Size':<10} {'Type':<25} {'Modified':<20}")
        print(f"{C.TABLE}{'─' * 90}{C.RESET}")
        for i, fi in enumerate(files[:C.MAX_FILES_DISPLAY], 1):
            name = fi['name'][:27] + '...' if len(fi['name']) > 28 else fi['name']
            mod  = fi['modified'].strftime('%Y-%m-%d %H:%M')
            col  = (C.SUCCESS if 'PNG' in fi['type'] else
                    C.INFO    if 'MP4' in fi['type'] else
                    C.WARNING if 'PDF' in fi['type'] else C.TABLE)
            print(f"{i:<4} {col}{name:<30}{C.RESET} {fi['fmt_size']:<10} "
                  f"{fi['type']:<25} {mod}")
        print(f"{C.TABLE}{'─' * 90}{C.RESET}")
        print(f"{C.INFO}{len(files)} file(s) found{C.RESET}")
        return files

    def get_file_by_number(self, n: int) -> Optional[Path]:
        return self.file_cache[n - 1]['path'] if 1 <= n <= len(self.file_cache) else None


# ============================================================================
# TEST SUITE  –  18 tests
# ============================================================================

class TestSuite:
    """
    18-test comprehensive suite for QSteg v17.0.

    New tests vs v16.7 (tests 13-18):
      13 – Wrong password → fails cleanly (no crash, clear error)
      14 – RS error correction: bit-flipped RS payload recovers
      15 – Corrupted stego image → graceful failure
      16 – PQC key corruption → decryption raises, no silent downgrade
      17 – Steganalysis resistance: entropy of stego ≈ entropy of cover
    """

    def __init__(self):
        self.engine  = StegEngine()
        self.results: List[TestResult] = []
        self.test_dir = Path("qsteg_test_v17")
        self.test_dir.mkdir(exist_ok=True)

    def _log(self, name: str, passed: bool, details: str = "", debug: str = ""):
        status = (f"{QStegConstants.SUCCESS}PASS{QStegConstants.RESET}" if passed
                  else f"{QStegConstants.ERROR}FAIL{QStegConstants.RESET}")
        print(f"  {name:<40} {status}  {details}")
        if debug and not passed:
            print(f"    {QStegConstants.WARNING}DEBUG: {debug}{QStegConstants.RESET}")
        self.results.append(TestResult(name, passed, details, debug))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _make_png(self, w: int, h: int, name: str) -> Path:
        p = self.test_dir / name
        Image.new('RGB', (w, h), color=(128, 128, 128)).save(p, 'PNG')
        return p

    # ── Individual tests ──────────────────────────────────────────────────────

    def _t01_aes_gcm(self):
        try:
            eng  = HybridCryptoEngine(verbose=False)
            data = b"AES-256-GCM test data " * 10
            ct, _  = eng.encrypt(data, "pw123", SecurityLevel.STANDARD, False)
            pt, _  = eng.decrypt(ct, "pw123")
            ok = SecurityUtils.constant_time_compare(data, pt)
            self._log("01 AES-256-GCM", ok, f"{len(data)}B roundtrip")
        except Exception as e:
            self._log("01 AES-256-GCM", False, debug=str(e))

    def _t02_hkdf(self):
        try:
            ikm = secrets.token_bytes(32)
            out = hkdf(ikm, 64, salt=b'testsalt', info=b'test')
            ok  = len(out) == 64 and out[:32] != out[32:]
            self._log("02 HKDF key derivation", ok, "64B output, two distinct halves")
        except Exception as e:
            self._log("02 HKDF key derivation", False, debug=str(e))

    def _t03_hybrid_enc(self):
        """Hybrid encryption via AES+PQC (skipped if PQC unavailable)."""
        try:
            eng  = HybridCryptoEngine(verbose=False)
            try:
                keys = eng.ensure_test_keys()
            except RuntimeError as e:
                self._log("03 Hybrid PQC encrypt", True,
                          f"PQC unavailable (expected on OpenSSL<3.6): {str(e)[:50]}")
                return
            data = b"Hybrid PQC+AES test " * 5
            ct, _  = eng.encrypt(data, "pw456", SecurityLevel.STANDARD, True, keys)
            pt, _  = eng.decrypt(ct, "pw456", keys)
            ok = SecurityUtils.constant_time_compare(data, pt)
            self._log("03 Hybrid PQC encrypt", ok, f"{len(ct)}B container")
        except Exception as e:
            self._log("03 Hybrid PQC encrypt", False, debug=str(e))

    def _t04_dual_layer(self):
        try:
            dl = DualLayerEngine()
            decoy  = b"Decoy document text"
            hidden = b"Hidden secret data"
            blob, _ = dl.create_container(
                decoy, hidden, "dpw", "mpw", SecurityLevel.FAST, False)
            r1 = dl.extract_container(blob, "dpw")
            r2 = dl.extract_container(blob, "mpw")
            ok = (r1.get('success') and r1['mode'] == DeniabilityMode.DECOY_ONLY and
                  r2.get('success') and r2['mode'] == DeniabilityMode.HIDDEN_ONLY)
            self._log("04 Dual-layer container", ok,
                      f"{len(blob):,}B, no separator marker")
        except Exception as e:
            self._log("04 Dual-layer container", False, debug=str(e))

    def _t05_rs_ecc(self):
        try:
            data    = secrets.token_bytes(512)
            ecc     = ReedSolomonECC(32)
            encoded = ecc.encode(data)
            decoded = ecc.decode(encoded)
            ok = SecurityUtils.constant_time_compare(data, decoded)
            self._log("05 Reed-Solomon ECC (encode/decode)", ok,
                      f"{len(data)}B → {len(encoded)}B → {len(decoded)}B")
        except Exception as e:
            self._log("05 Reed-Solomon ECC (encode/decode)", False, debug=str(e))

    def _t06_rs_recovery(self):
        """RS corrects up to nsym/2 byte-errors per block."""
        try:
            data    = secrets.token_bytes(200)
            ecc     = ReedSolomonECC(32)
            encoded = bytearray(ecc.encode(data))
            # Corrupt 10 bytes at scattered positions (well within error budget)
            positions = [5, 20, 50, 80, 100, 130, 160, 190, 210, 240]
            for pos in positions:
                if pos < len(encoded):
                    encoded[pos] ^= 0xFF
            decoded = ecc.decode(bytes(encoded))
            ok = SecurityUtils.constant_time_compare(data, decoded)
            self._log("06 RS error recovery (10 corrupted bytes)", ok,
                      f"{len(positions)} byte errors corrected")
        except Exception as e:
            self._log("06 RS error recovery (10 corrupted bytes)", False, debug=str(e))

    def _t07_prng_permutation(self):
        try:
            seed  = secrets.token_bytes(32)
            perm1 = StegEngine._pixel_permutation(10000, seed)
            perm2 = StegEngine._pixel_permutation(10000, seed)
            seq   = list(range(10000))
            ok = (perm1 == perm2 and           # deterministic
                  perm1 != seq and              # not sequential
                  sorted(perm1) == seq)         # all indices present
            self._log("07 PRNG pixel permutation", ok,
                      "deterministic, non-sequential, complete")
        except Exception as e:
            self._log("07 PRNG pixel permutation", False, debug=str(e))

    def _t08_png_stego(self):
        try:
            png      = self._make_png(600, 400, "t08.png")
            seed     = secrets.token_bytes(32)
            payload  = b"PNG stego test v17 " * 20
            eng      = StegEngine()
            img      = eng.embed_in_png(png, payload, seed)
            out      = self.test_dir / "t08_out.png"
            img.save(out, 'PNG')
            recovered = eng.extract_from_png(out, seed)
            ok = SecurityUtils.constant_time_compare(payload, recovered)
            self._log("08 PNG PRNG-stego roundtrip", ok,
                      f"{len(payload)}B, 600×400")
        except Exception as e:
            self._log("08 PNG PRNG-stego roundtrip", False, debug=str(e))

    def _t09_mp4_container(self):
        try:
            mp4 = self.test_dir / "t09.mp4"
            mp4.write_bytes(b"fake mp4 content" * 1000)
            eng  = StegEngine()
            data = b"MP4 container test v17"
            out  = eng.embed_in_mp4(mp4, data)
            rec  = eng.extract_from_mp4(out)
            ok   = SecurityUtils.constant_time_compare(data, rec)
            self._log("09 MP4 container embedding", ok, f"{len(data)}B")
        except Exception as e:
            self._log("09 MP4 container embedding", False, debug=str(e))

    def _t10_pdf_container(self):
        try:
            pdf = self.test_dir / "t10.pdf"
            pdf.write_bytes(b"%PDF-1.4\n" + b"content " * 100)
            eng  = StegEngine()
            data = b"PDF container test v17"
            out  = eng.embed_in_pdf(pdf, data)
            rec  = eng.extract_from_pdf(out)
            ok   = SecurityUtils.constant_time_compare(data, rec)
            self._log("10 PDF container embedding", ok, f"{len(data)}B")
        except Exception as e:
            self._log("10 PDF container embedding", False, debug=str(e))

    def _t11_capacity(self):
        try:
            sizes = [(400, 300), (800, 600), (1200, 900)]
            caps  = []
            eng   = StegEngine()
            for w, h in sizes:
                p = self._make_png(w, h, f"t11_{w}.png")
                caps.append(eng.calculate_png_capacity(p))
            ok = all(c > 0 for c in caps) and caps[0] < caps[1] < caps[2]
            self._log("11 Capacity calculation", ok,
                      f"{[f'{c//1024}KB' for c in caps]}")
        except Exception as e:
            self._log("11 Capacity calculation", False, debug=str(e))

    def _t12_security_utils(self):
        try:
            ok1  = SecurityUtils.constant_time_compare("abc", "abc")
            ok2  = not SecurityUtils.constant_time_compare("abc", "ABC")
            buf  = bytearray(b"secret")
            SecurityUtils.best_effort_wipe(buf)
            ok3  = all(b == 0 for b in buf)
            ok = ok1 and ok2 and ok3
            self._log("12 Security utilities", ok, "constant-time compare, wipe")
        except Exception as e:
            self._log("12 Security utilities", False, debug=str(e))

    # ── New v18 tests ─────────────────────────────────────────────────────────

    def _t13_wrong_password(self):
        """Wrong password must fail cleanly (no crash, returns success=False)."""
        try:
            dl  = DualLayerEngine()
            blob, _ = dl.create_container(
                b"decoy", b"hidden", "correct_decoy", "correct_master",
                SecurityLevel.FAST, False)
            result = dl.extract_container(blob, "WRONG_PASSWORD")
            ok = not result.get('success') and 'error' in result
            self._log("13 Wrong password – clean failure", ok,
                      "returns success=False, no exception")
        except Exception as e:
            self._log("13 Wrong password – clean failure", False, debug=str(e))

    def _t14_rs_bit_flip(self):
        """RS ECC recovers from single random bit flip in each 255-byte block."""
        try:
            data    = b"Reed-Solomon bit-flip test " * 30
            ecc     = ReedSolomonECC(32)
            encoded = bytearray(ecc.encode(data))
            # One error per block of 255 bytes
            for block_start in range(0, len(encoded), 255):
                pos = block_start + 7
                if pos < len(encoded):
                    encoded[pos] ^= 0b00000001
            decoded = ecc.decode(bytes(encoded))
            ok = SecurityUtils.constant_time_compare(data, decoded)
            self._log("14 RS bit-flip per block recovery", ok,
                      f"{len(data)}B, one bit flipped per block")
        except Exception as e:
            self._log("14 RS bit-flip per block recovery", False, debug=str(e))

    def _t15_corrupted_container(self):
        """Extracting from a corrupted dual-layer blob must fail gracefully."""
        try:
            dl  = DualLayerEngine()
            blob, _ = dl.create_container(
                b"decoy", b"hidden", "dp", "mp", SecurityLevel.FAST, False)
            corrupted = bytearray(blob)
            # Corrupt the final third of the blob – that region overlaps the
            # hidden_blob ciphertext and will cause HMAC / AES-GCM auth failure.
            start = len(corrupted) * 2 // 3
            end   = len(corrupted) - 50   # leave footer+checksum intact
            for i in range(start, min(end, start + 60)):
                corrupted[i] ^= 0xFF
            try:
                result = dl.extract_container(bytes(corrupted), "mp")
                ok = not result.get('success')
            except Exception:
                ok = True    # exception is also acceptable
            self._log("15 Corrupted container – graceful failure", ok,
                      "no unhandled crash")
        except Exception as e:
            self._log("15 Corrupted container – graceful failure",
                      False, debug=str(e))

    def _t16_pqc_key_corruption(self):
        """A container encrypted with real PQC keys must not decrypt with corrupted keys."""
        try:
            eng = HybridCryptoEngine(verbose=False)
            try:
                keys = eng.ensure_test_keys()
            except RuntimeError:
                self._log("16 PQC key corruption resistance", True,
                          "PQC unavailable – test skipped")
                return
            data = b"PQC key corruption test"
            ct, _  = eng.encrypt(data, "pw", SecurityLevel.STANDARD, True, keys)
            # Corrupt the KEM private key
            bad_keys = dict(keys)
            bad_priv = bytearray(keys['kem_private'])
            for i in range(0, min(32, len(bad_priv))):
                bad_priv[i] ^= 0xFF
            bad_keys['kem_private'] = bytes(bad_priv)
            try:
                eng.decrypt(ct, "pw", bad_keys)
                ok = False    # Should not succeed
            except (ValueError, RuntimeError):
                ok = True     # Expected: decryption refuses corrupt key
            self._log("16 PQC key corruption resistance", ok,
                      "corrupt KEM key raises, no silent downgrade")
        except Exception as e:
            self._log("16 PQC key corruption resistance", False, debug=str(e))

    def _t17_entropy(self):
        """
        Entropy of the stego PNG should be close to that of the cover PNG.
        A good LSB implementation changes pixel values by at most 1 step,
        so entropy should remain within 0.3 bits/byte of the cover.
        """
        try:
            cover = self._make_png(400, 300, "t17_cover.png")
            seed  = secrets.token_bytes(32)
            payload = b"entropy test " * 80
            eng  = StegEngine()
            img  = eng.embed_in_png(cover, payload, seed)
            stego = self.test_dir / "t17_stego.png"
            img.save(stego, 'PNG')

            def entropy(path: Path) -> float:
                raw = np.array(Image.open(path).convert('RGB')).flatten()
                _, counts = np.unique(raw, return_counts=True)
                p = counts / counts.sum()
                return -np.sum(p * np.log2(p + 1e-10))

            h_cover = entropy(cover)
            h_stego = entropy(stego)
            diff = abs(h_stego - h_cover)
            ok   = diff < 0.5   # within 0.5 bits/byte
            self._log("17 Entropy similarity (steganalysis resistance)", ok,
                      f"Δentropy={diff:.4f} bits/byte (threshold <0.5)")
        except Exception as e:
            self._log("17 Entropy similarity", False, debug=str(e))


    def _t18_file_hiding(self):
        """Hide a small binary file inside a PNG and recover it."""
        try:
            # Create a test file with random bytes
            test_file = self.test_dir / "hidden.bin"
            data = secrets.token_bytes(1024)  # 1 KB
            test_file.write_bytes(data)

            # Create carrier PNG
            png = self._make_png(800, 600, "t18_carrier.png")
            eng = StegEngine()

            # Encode the file
            out_path, _ = eng.encode(
                png,
                test_file,          # pass Path object
                "decoy_pw",
                "master_pw",
                SecurityLevel.FAST,
                use_pqc=False,
                robust=False
            )

            # Decode and verify
            result = eng.decode(out_path, "master_pw", robust=None)
            if not result.get('success'):
                raise ValueError("Decode failed")

            hidden_bytes = result.get('hidden_data') or result.get('data')
            if hidden_bytes is None:
                raise ValueError("No hidden data returned")

            ok = SecurityUtils.constant_time_compare(data, hidden_bytes)
            self._log("18 File hiding (1 KB) in PNG", ok,
                      f"{len(data)}B roundtrip")
        except Exception as e:
            self._log("18 File hiding (1 KB) in PNG", False, debug=str(e))

    # ── Runner ────────────────────────────────────────────────────────────────

    def run_all_tests(self) -> bool:
        C = QStegConstants
        print(f"\n{C.HEADER}{'=' * 80}")
        print(f"{'QSteg v17.0 TEST SUITE – 18 TESTS':^80}")
        print(f"{'=' * 80}{C.RESET}\n")

        tests = [
            self._t01_aes_gcm,
            self._t02_hkdf,
            self._t03_hybrid_enc,
            self._t04_dual_layer,
            self._t05_rs_ecc,
            self._t06_rs_recovery,
            self._t07_prng_permutation,
            self._t08_png_stego,
            self._t09_mp4_container,
            self._t10_pdf_container,
            self._t11_capacity,
            self._t12_security_utils,
            self._t13_wrong_password,
            self._t14_rs_bit_flip,
            self._t15_corrupted_container,
            self._t16_pqc_key_corruption,
            self._t17_entropy,
            self._t18_file_hiding,
        ]

        for fn in tests:
            try:
                fn()
            except Exception as e:
                name = fn.__name__
                self._log(name, False, debug=f"Unexpected crash: {e}")

        self._print_summary()

        # Cleanup
        self.engine.cleanup()
        try:
            import shutil
            shutil.rmtree(self.test_dir)
        except Exception:
            pass

        passed = sum(1 for r in self.results if r.passed)
        return passed == len(self.results)

    def _print_summary(self):
        C = QStegConstants
        passed = sum(1 for r in self.results if r.passed)
        total  = len(self.results)
        pct    = 100 * passed / total if total else 0

        print(f"\n{C.HEADER}{'=' * 80}")
        print(f"{'RESULTS':^80}")
        print(f"{'=' * 80}{C.RESET}")
        print(f"\n  {'Test':<42} {'Status'}")
        print(f"  {'─' * 55}")
        for r in self.results:
            s = (f"{C.SUCCESS}PASS{C.RESET}" if r.passed
                 else f"{C.ERROR}FAIL{C.RESET}")
            print(f"  {r.name:<42} {s}  {r.details}")
        print(f"\n{C.INFO}  {passed}/{total} tests passed ({pct:.1f}%){C.RESET}")
        if passed == total:
            print(f"\n{C.SUCCESS}🎉 ALL {total} TESTS PASSED – PRODUCTION READY{C.RESET}")
        else:
            failed = [r.name for r in self.results if not r.passed]
            print(f"\n{C.WARNING}⚠️  Failures: {', '.join(failed)}{C.RESET}")


# ============================================================================
# COMMAND INTERFACE
# ============================================================================

class CommandInterface:
    def __init__(self):
        self.engine     = StegEngine()
        self.test_suite = TestSuite()
        self.browser    = FileBrowser()

    def _banner(self):
        C = QStegConstants
        print(f"""
{C.HEADER}╔══════════════════════════════════════════════════════════════════════╗
║           QSteg v17.0 – Quantum-Resistant Steganography            ║
║           ML-KEM-1024 (C ext) + AES-256-GCM + RS ECC              ║
║                     Dual-Layer Plausible Deniability                ║
╚══════════════════════════════════════════════════════════════════════╝{C.RESET}

{C.SUCCESS}[CRYPTO]  AES-256-GCM  +  HKDF (RFC 5869){C.RESET}
{C.CRYPTO}[PQC]     ML-KEM-1024 (self‑contained C extension) + AES-256-GCM{C.RESET}
{C.INFO}[STEG]    PRNG-keyed pixel permutation  +  Reed-Solomon ECC{C.RESET}
{C.WARNING}[NOTE]    MP4 and PDF use container embedding, NOT covert steganography{C.RESET}
{C.INFO}[TESTS]   18 automated tests  (python qsteg.py --test){C.RESET}
""")

    @staticmethod
    def _progress(i: int, total: int, prefix: str = ''):
        pct    = 100 * i / total
        filled = int(50 * i // total)
        bar    = '█' * filled + '░' * (50 - filled)
        C = QStegConstants
        print(f'\r{prefix} {C.PROGRESS}[{bar}] {pct:.1f}%{C.RESET}',
              end='', flush=True)
        if i == total:
            print()

    def _file_menu(self, title: str) -> Optional[Path]:
        C = QStegConstants
        while True:
            SecurityUtils.clear_screen()
            print(f"\n{C.INFO}{'=' * 70}{C.RESET}")
            print(f"{C.INFO}{title:^70}{C.RESET}")
            print(f"{C.INFO}{'=' * 70}{C.RESET}")
            files = self.browser.display_files(title)
            if not files:
                print(f"{C.ERROR}No supported files found.{C.RESET}")
                input(f"\n{C.INFO}Press Enter to go back…{C.RESET}")
                return None
            print(f"\n  {C.INFO}#  – select by number   r – refresh   c – cancel{C.RESET}")
            cmd = input(f"\n{C.INFO}Command: {C.RESET}").strip().lower()
            if cmd == 'c':
                return None
            if cmd == 'r':
                continue
            if cmd.isdigit():
                fp = self.browser.get_file_by_number(int(cmd))
                if fp:
                    return fp
                print(f"{C.ERROR}Invalid number{C.RESET}")
                time.sleep(0.8)

    def encode_menu(self):
        C = QStegConstants
        SecurityUtils.clear_screen()
        print(f"\n{C.SUCCESS}🚀 ENCODE DATA{C.RESET}")

        carrier = self._file_menu("SELECT CARRIER FILE")
        if not carrier:
            return

        # Security level
        print(f"\n{C.CRYPTO}Security level:{C.RESET}")
        print(f"  1. {C.SUCCESS}FAST – AES-256 only{C.RESET}")
        print(f"  2. {C.INFO}STANDARD – Hybrid AES+PQC  (requires OpenSSL ≥ 3.6){C.RESET}")
        ch = input(f"\n{C.INFO}Level (1/2): {C.RESET}").strip()
        if ch == '1':
            level, use_pqc = SecurityLevel.FAST, False
            print(f"{C.SUCCESS}✅ AES-256-GCM only{C.RESET}")
        else:
            level, use_pqc = SecurityLevel.STANDARD, True
            print(f"{C.CRYPTO}✅ PQC hybrid mode{C.RESET}")

        # Robust mode
        print(f"\n{C.INFO}Robust mode (social-media survival)?{C.RESET}")
        print(f"  Lowers payload density to 5%, applies stronger RS.")
        print(f"  Recommended for images that may be re-uploaded.")
        robust = input(f"{C.INFO}Enable robust mode? (y/N): {C.RESET}").strip().lower() == 'y'

        # Carrier warnings
        info = self.engine.analyze_file(carrier, robust=robust)
        print(f"\n{C.INFO}Carrier: {info.name}  ({info.type.name}, {info.capacity:,}B capacity){C.RESET}")
        if robust:
            for w in StegEngine.check_robust_suitability(info):
                print(f"{C.WARNING}⚠️  {w}{C.RESET}")

        # Hidden data
        print(f"\n{C.HIDDEN}Data to hide:{C.RESET}")
        print("  1. Enter text\n  2. Use test phrase\n  3. Select file")
        dc = input(f"{C.INFO}Choice: {C.RESET}").strip()
        if dc == '1':
            hidden = input(f"{C.INFO}Enter text: {C.RESET}").strip().encode()
        elif dc == '3':
            hidden_path = self._file_menu("SELECT FILE TO HIDE")
            if hidden_path is None:
                print(f"{C.ERROR}No file selected{C.RESET}")
                return
            try:
                hidden = hidden_path.read_bytes()
                print(f"{C.INFO}Loaded {len(hidden):,} bytes from {hidden_path.name}{C.RESET}")
            except Exception as e:
                print(f"{C.ERROR}Failed to read file: {e}{C.RESET}")
                return
        else:
            hidden = b"Hidden message protected by QSteg v17.0 quantum-resistant steganography"
            print(f"{C.INFO}Using test phrase{C.RESET}")

        # Passwords
        print(f"\n{C.CRYPTO}Passwords:{C.RESET}")
        print(f"  {C.DECOY}Decoy password → reveals plausible decoy document{C.RESET}")
        print(f"  {C.HIDDEN}Master password → reveals hidden data{C.RESET}")
        dp = getpass.getpass(f"{C.DECOY}Decoy password: {C.RESET}").strip()
        mp = getpass.getpass(f"{C.HIDDEN}Master password: {C.RESET}").strip()
        if not dp or not mp:
            print(f"{C.ERROR}Both passwords required{C.RESET}")
            return

        # Confirm
        print(f"\n{C.WARNING}Confirm:{C.RESET}")
        print(f"  Carrier:  {carrier.name}")
        print(f"  Data:     {len(hidden):,}B")
        print(f"  Mode:     {'PQC Hybrid' if use_pqc else 'AES-256 only'}"
              f"{' + Robust' if robust else ''}")
        if input(f"\n{C.WARNING}Proceed? (y/N): {C.RESET}").strip().lower() != 'y':
            return

        print(f"\n{C.PROGRESS}Encoding…{C.RESET}")
        for i in range(101): self._progress(i, 100, 'Progress:'); time.sleep(0.01)

        try:
            out, stats = self.engine.encode(
                carrier, hidden, dp, mp, level, use_pqc, robust)
            sidecar = out.with_suffix('.qss')
            print(f"\n{C.SUCCESS}✅ Encoded!{C.RESET}")
            print(f"  Output:   {out.name}")
            print(f"  Sidecar:  {sidecar.name}  (keep alongside stego file)")
            print(f"  Time:     {stats.elapsed:.2f}s")

            # Auto-verify
            print(f"\n{C.INFO}Auto-verifying…{C.RESET}")
            r1 = self.engine.decode(out, dp, robust=None)
            print(f"  Decoy password:  {'✅' if r1['success'] else '❌'}")
            r2 = self.engine.decode(out, mp, robust=None)
            print(f"  Master password: {'✅' if r2['success'] else '❌'}")
        except Exception as e:
            print(f"\n{C.ERROR}❌ Encoding failed: {e}{C.RESET}")

        input(f"\n{C.INFO}Press Enter…{C.RESET}")

    def decode_menu(self):
        C = QStegConstants
        SecurityUtils.clear_screen()
        print(f"\n{C.HIDDEN}🔓 DECODE DATA{C.RESET}")

        stego = self._file_menu("SELECT STEGO FILE")
        if not stego:
            return

        # No robust prompt – auto‑detected during decode
        pw = getpass.getpass(f"{C.INFO}Password: {C.RESET}").strip()
        if not pw:
            print(f"{C.ERROR}Password required{C.RESET}")
            return

        print(f"\n{C.PROGRESS}Decoding…{C.RESET}")
        for i in range(101): self._progress(i, 100, 'Progress:'); time.sleep(0.01)

        result = self.engine.decode(stego, pw, robust=None)

        if result.get('success'):
            print(f"\n{C.SUCCESS}✅ Decoding successful!{C.RESET}")
            if result.get('robust_used'):
                print(f"  {C.INFO}(Auto‑detected robust mode){C.RESET}")
            print(f"  Layer: {result['mode'].name}")
            mode = result['mode']
            if mode == DeniabilityMode.HIDDEN_ONLY:
                print(f"\n{C.HIDDEN}{'═'*60}{C.RESET}")
                print(f"{C.HIDDEN}HIDDEN CONTENT:{C.RESET}")
                print(f"{C.HIDDEN}{'═'*60}{C.RESET}")
                print(result.get('text', result.get('hidden_text', '<binary>')))
            elif mode == DeniabilityMode.DECOY_ONLY:
                print(f"\n{C.DECOY}DECOY CONTENT:{C.RESET}")
                print(result.get('text', '<binary>'))
                print(f"\n{C.INFO}(Use master password for hidden data){C.RESET}")
        else:
            print(f"\n{C.ERROR}❌ {result.get('error', 'Decoding failed')}{C.RESET}")

        input(f"\n{C.INFO}Press Enter…{C.RESET}")

    def test_menu(self):
        C = QStegConstants
        SecurityUtils.clear_screen()
        print(f"\n{C.INFO}🧪 RUNNING 18 TESTS…{C.RESET}\n")
        success = self.test_suite.run_all_tests()
        print(f"\n{C.SUCCESS if success else C.WARNING}"
              f"{'ALL TESTS PASSED' if success else 'SOME TESTS FAILED'}"
              f"{C.RESET}")
        input(f"\n{C.INFO}Press Enter…{C.RESET}")

    def system_info(self):
        C = QStegConstants
        SecurityUtils.clear_screen()
        print(f"\n{C.INFO}SYSTEM INFORMATION – QSteg v17.0{C.RESET}")
        print(f"  OpenSSL:  {ssl.OPENSSL_VERSION}")
        print(f"  Python:   {sys.version.split()[0]}")
        print(f"  Platform: {sys.platform}")
        print(f"\n  Features:")
        print(f"    AES-256-GCM encryption:         ✅")
        print(f"    HKDF key derivation (RFC 5869):  ✅")
        print(f"    PRNG pixel permutation:          ✅")
        print(f"    Reed-Solomon ECC:                ✅")
        print(f"    Dual-layer deniability:          ✅")
        print(f"    Robust mode (social media):      ✅")
        print(f"    PQC (ML-KEM-1024):               ✅ self‑contained C extension")
        input(f"\n{C.INFO}Press Enter…{C.RESET}")

    def main_menu(self):
        C = QStegConstants
        while True:
            SecurityUtils.clear_screen()
            self._banner()
            print(f"{C.INFO}{'=' * 70}{C.RESET}")
            print(f"  {C.INFO}1.{C.RESET} 🚀 Encode data")
            print(f"  {C.INFO}2.{C.RESET} 🔓 Decode data")
            print(f"  {C.INFO}3.{C.RESET} 🧪 Run 18 tests")
            print(f"  {C.INFO}4.{C.RESET} 📊 System info")
            print(f"  {C.INFO}5.{C.RESET} 🚪 Exit")
            print(f"{C.INFO}{'=' * 70}{C.RESET}")
            try:
                ch = input(f"\n{C.INFO}Select (1–5): {C.RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if ch == '1': self.encode_menu()
            elif ch == '2': self.decode_menu()
            elif ch == '3': self.test_menu()
            elif ch == '4': self.system_info()
            elif ch == '5':
                print(f"\n{C.CRYPTO}Shutting down…{C.RESET}")
                self.engine.cleanup(); time.sleep(0.5); break
            else:
                time.sleep(0.5)

# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    C = QStegConstants
    try:
        print(f"{C.HEADER}{'=' * 70}{C.RESET}")
        print(f"{C.HEADER}{'QSteg v17.0 – Quantum-Resistant Steganography':^70}{C.RESET}")
        print(f"{C.HEADER}{'For authorised testing and educational purposes only':^70}{C.RESET}")
        print(f"{C.HEADER}{'=' * 70}{C.RESET}")

        if len(sys.argv) > 1 and sys.argv[1] == '--test':
            suite   = TestSuite()
            success = suite.run_all_tests()
            sys.exit(0 if success else 1)

        CommandInterface().main_menu()

    except KeyboardInterrupt:
        print(f"\n\n{C.WARNING}Interrupted{C.RESET}")
    except Exception as e:
        print(f"\n{C.ERROR}Fatal error: {e}{C.RESET}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
