/*
 * qsteg_mlkem.c – ML-KEM-512/768/1024 for QSteg
 *
 * Exports:
 *   keygen(level)      -> (ek: bytes, dk: bytes)
 *   encaps(ek, level)  -> (ct: bytes, ss: bytes)
 *   decaps(ct, dk, level) -> ss: bytes
 *
 * level must be 512, 768, or 1024.
 *
 * Build:
 *   gcc -shared -fPIC -O2 -o qsteg_mlkem.so qsteg_mlkem.c \
 *       $(python3-config --includes) $(python3-config --ldflags --embed) -lcrypto
 *
 * Dependencies: OpenSSL >= 1.1.1 (libcrypto)
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/* ============================================================================
 * ML-KEM constants and tables
 * ========================================================================== */

#define MLKEM_Q     3329
#define MLKEM_N      256
#define MLKEM_ETA1     2
#define MLKEM_ETA2     2
#define MLKEM_DU      11
#define MLKEM_DV       5

static uint16_t mlkem_zetas[128];
static uint16_t mlkem_bmzetas[128];
static uint32_t mlkem_ninv;

static uint8_t br7(uint8_t n) {
    uint8_t b = 0;
    for (int i = 0; i < 7; i++) { b = (b << 1) | (n & 1); n >>= 1; }
    return b;
}

static uint32_t modpow(uint32_t base, uint32_t exp, uint32_t mod) {
    uint64_t r = 1, b = base % mod;
    while (exp > 0) {
        if (exp & 1) r = r * b % mod;
        b = b * b % mod;
        exp >>= 1;
    }
    return (uint32_t)r;
}

static void mlkem_init_tables(void) {
    for (int i = 0; i < 128; i++) {
        mlkem_zetas[i]  = (uint16_t)modpow(17, br7(i),         MLKEM_Q);
        mlkem_bmzetas[i]= (uint16_t)modpow(17, 2*br7(i)+1,     MLKEM_Q);
    }
    mlkem_ninv = modpow(128, MLKEM_Q - 2, MLKEM_Q);
}

/* ============================================================================
 * NTT / polynomial arithmetic
 * ========================================================================== */

static void mlkem_ntt(uint16_t f[256]) {
    int kk = 1;
    for (int l = 128; l >= 2; l >>= 1) {
        for (int s = 0; s < 256; s += 2*l) {
            uint32_t z = mlkem_zetas[kk++];
            for (int j = s; j < s+l; j++) {
                uint16_t t = (uint16_t)(z * f[j+l] % MLKEM_Q);
                f[j+l] = (f[j] - t + MLKEM_Q) % MLKEM_Q;
                f[j]   = (f[j] + t) % MLKEM_Q;
            }
        }
    }
}

static void mlkem_intt(uint16_t f[256]) {
    int kk = 127;
    for (int l = 2; l <= 128; l <<= 1) {
        for (int s = 0; s < 256; s += 2*l) {
            uint32_t z = mlkem_zetas[kk--];
            for (int j = s; j < s+l; j++) {
                uint16_t t = f[j];
                f[j]   = (t + f[j+l]) % MLKEM_Q;
                f[j+l] = (uint16_t)(z * ((f[j+l] - t + MLKEM_Q) % MLKEM_Q) % MLKEM_Q);
            }
        }
    }
    for (int i = 0; i < 256; i++)
        f[i] = (uint16_t)((uint32_t)f[i] * mlkem_ninv % MLKEM_Q);
}

static void mlkem_pmul(const uint16_t a[256], const uint16_t b[256], uint16_t r[256]) {
    for (int i = 0; i < 128; i++) {
        uint64_t z  = mlkem_bmzetas[i];
        uint64_t a0 = a[2*i],   a1 = a[2*i+1];
        uint64_t b0 = b[2*i],   b1 = b[2*i+1];
        r[2*i]   = (uint16_t)((a0*b0 + z*a1*b1) % MLKEM_Q);
        r[2*i+1] = (uint16_t)((a0*b1 + a1*b0  ) % MLKEM_Q);
    }
}

static void mlkem_padd(uint16_t a[256], const uint16_t b[256]) {
    for (int i = 0; i < 256; i++)
        a[i] = (a[i] + b[i]) % MLKEM_Q;
}

/* ============================================================================
 * Matrix-vector multiplication (NTT domain)
 * ========================================================================== */

static void mlkem_mvmul(int K,
                        const uint16_t *A,      /* A[K][K][256] flat */
                        const uint16_t *v,      /* v[K][256] flat */
                        uint16_t *r)            /* r[K][256] flat */
{
    for (int i = 0; i < K; i++) {
        memset(r + i*256, 0, 256 * sizeof(uint16_t));
        for (int j = 0; j < K; j++) {
            uint16_t tmp[256];
            const uint16_t *Aij = A + (i*K + j)*256;
            const uint16_t *vj  = v + j*256;
            mlkem_pmul(Aij, vj, tmp);
            mlkem_padd(r + i*256, tmp);
        }
    }
}

/* ============================================================================
 * XOF, PRF, CBD
 * ========================================================================== */

static void mlkem_xof_sample(const uint8_t rho[32], int i, int j,
                             uint16_t out[256]) {
    uint8_t seed[34];
    memcpy(seed, rho, 32);
    seed[32] = (uint8_t)i;
    seed[33] = (uint8_t)j;

    uint8_t buf[840];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake128(), NULL);
    EVP_DigestUpdate(ctx, seed, 34);
    EVP_DigestFinalXOF(ctx, buf, 840);
    EVP_MD_CTX_free(ctx);

    int a_len = 0, idx = 0;
    while (a_len < 256 && idx + 3 <= 840) {
        uint16_t d1 = (uint16_t)(buf[idx] | ((uint16_t)(buf[idx+1] & 0x0Fu) << 8u));
        uint16_t d2 = (uint16_t)((buf[idx+1] >> 4u) | ((uint16_t)buf[idx+2] << 4u));
        idx += 3;
        if (d1 < MLKEM_Q) out[a_len++] = d1;
        if (d2 < MLKEM_Q && a_len < 256) out[a_len++] = d2;
    }
    while (a_len < 256) out[a_len++] = 0;
}

static void mlkem_prf(const uint8_t s[32], uint8_t b, uint8_t *out, size_t l) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(ctx, s, 32);
    EVP_DigestUpdate(ctx, &b, 1);
    EVP_DigestFinalXOF(ctx, out, l);
    EVP_MD_CTX_free(ctx);
}

static void mlkem_cbd(const uint8_t *b, int eta, uint16_t f[256]) {
    for (int i = 0; i < 256; i++) {
        int a_s = 0, b_s = 0;
        for (int j = 0; j < eta; j++) {
            int bi = 2*i*eta + j;
            a_s += (b[bi >> 3] >> (bi & 7)) & 1;
            bi = 2*i*eta + eta + j;
            b_s += (b[bi >> 3] >> (bi & 7)) & 1;
        }
        f[i] = (uint16_t)((a_s - b_s + MLKEM_Q) % MLKEM_Q);
    }
}

/* ============================================================================
 * (De)compression and byte encoding
 * ========================================================================== */

static inline uint16_t mlkem_compress(uint16_t x, int d) {
    return (uint16_t)(((uint32_t)(1u<<d) * x + (MLKEM_Q+1)/2) / MLKEM_Q % (1u<<d));
}

static inline uint16_t mlkem_decompress(uint16_t y, int d) {
    return (uint16_t)((MLKEM_Q * (uint32_t)y + (1u << (d-1))) >> d);
}

static void mlkem_byte_encode(const uint16_t f[256], int d, uint8_t *out) {
    int bit_pos = 0;
    int out_len = d * 256 / 8;
    memset(out, 0, out_len);
    for (int i = 0; i < 256; i++) {
        uint32_t v = f[i];
        for (int b = 0; b < d; b++) {
            if ((v >> b) & 1)
                out[bit_pos >> 3] |= (uint8_t)(1 << (bit_pos & 7));
            bit_pos++;
        }
    }
}

static void mlkem_byte_decode(const uint8_t *b, int d, uint16_t f[256]) {
    int bit_pos = 0;
    uint32_t m = (d < 12) ? (1u << d) : MLKEM_Q;
    for (int i = 0; i < 256; i++) {
        uint32_t v = 0;
        for (int bb = 0; bb < d; bb++) {
            v |= ((uint32_t)((b[bit_pos >> 3] >> (bit_pos & 7)) & 1)) << bb;
            bit_pos++;
        }
        f[i] = (uint16_t)(v % m);
    }
}

/* ============================================================================
 * Core K-PKE, KEM (parameterized by K)
 * ========================================================================== */

static int kem_ek_bytes(int K) {
    if (K == 2) return 800;
    if (K == 3) return 1184;
    return 1568; /* K == 4 */
}

static int kem_dk_bytes(int K) {
    if (K == 2) return 1632;
    if (K == 3) return 2400;
    return 3168;
}

static void mlkem_keypke(int K, const uint8_t d32[32],
                         uint8_t *ek, uint8_t *dk_pke) {
    uint8_t G[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, d32, 32);
    unsigned int glen = 64;
    EVP_DigestFinal_ex(ctx, G, &glen);
    EVP_MD_CTX_free(ctx);

    const uint8_t *rho   = G;
    const uint8_t *sigma = G + 32;

    /* Allocate flat arrays: A[K][K][256], s[K][256], e[K][256], etc. */
    int A_size = K * K * 256;
    int vec_size = K * 256;
    uint16_t *A   = OPENSSL_malloc(A_size * sizeof(uint16_t));
    uint16_t *s   = OPENSSL_malloc(vec_size * sizeof(uint16_t));
    uint16_t *e   = OPENSSL_malloc(vec_size * sizeof(uint16_t));
    uint16_t *shat= OPENSSL_malloc(vec_size * sizeof(uint16_t));
    uint16_t *ehat= OPENSSL_malloc(vec_size * sizeof(uint16_t));
    uint16_t *As  = OPENSSL_malloc(vec_size * sizeof(uint16_t));

    /* Sample A */
    for (int i = 0; i < K; i++)
        for (int j = 0; j < K; j++)
            mlkem_xof_sample(rho, i, j, A + (i*K + j)*256);

    /* Sample s, e */
    uint8_t prf_out[128];
    for (int i = 0; i < K; i++) {
        mlkem_prf(sigma, (uint8_t)i, prf_out, 128);
        mlkem_cbd(prf_out, MLKEM_ETA1, s + i*256);
        mlkem_prf(sigma, (uint8_t)(K + i), prf_out, 128);
        mlkem_cbd(prf_out, MLKEM_ETA1, e + i*256);
    }

    /* NTT(s) and NTT(e) */
    for (int i = 0; i < K; i++) {
        memcpy(shat + i*256, s + i*256, 256*2);
        mlkem_ntt(shat + i*256);
        memcpy(ehat + i*256, e + i*256, 256*2);
        mlkem_ntt(ehat + i*256);
    }

    /* that = A * shat + ehat */
    mlkem_mvmul(K, A, shat, As);
    for (int i = 0; i < K; i++)
        mlkem_padd(As + i*256, ehat + i*256);

    /* ek = ByteEncode12(that) || rho */
    for (int i = 0; i < K; i++)
        mlkem_byte_encode(As + i*256, 12, ek + i*384);
    memcpy(ek + K*384, rho, 32);

    /* dk_pke = ByteEncode12(shat) */
    for (int i = 0; i < K; i++)
        mlkem_byte_encode(shat + i*256, 12, dk_pke + i*384);

    /* Cleanse */
    OPENSSL_cleanse(s, vec_size*2);
    OPENSSL_cleanse(e, vec_size*2);
    OPENSSL_cleanse(shat, vec_size*2);
    OPENSSL_cleanse(ehat, vec_size*2);
    OPENSSL_cleanse(G, sizeof(G));
    OPENSSL_free(A);
    OPENSSL_free(s);
    OPENSSL_free(e);
    OPENSSL_free(shat);
    OPENSSL_free(ehat);
    OPENSSL_free(As);
}

static void mlkem_enc_kpke(int K, const uint8_t *ek,
                           const uint8_t m32[32],
                           const uint8_t r32[32],
                           uint8_t *ct) {
    int vec_size = K * 256;
    uint16_t *that = OPENSSL_malloc(vec_size * sizeof(uint16_t));
    for (int i = 0; i < K; i++)
        mlkem_byte_decode(ek + i*384, 12, that + i*256);
    const uint8_t *rho = ek + K*384;

    int A_size = K * K * 256;
    uint16_t *A = OPENSSL_malloc(A_size * sizeof(uint16_t));
    for (int i = 0; i < K; i++)
        for (int j = 0; j < K; j++)
            mlkem_xof_sample(rho, i, j, A + (i*K + j)*256);

    uint16_t *r_   = OPENSSL_malloc(vec_size * sizeof(uint16_t));
    uint16_t *e1   = OPENSSL_malloc(vec_size * sizeof(uint16_t));
    uint16_t *e2   = OPENSSL_malloc(256 * sizeof(uint16_t));
    uint16_t *rhat = OPENSSL_malloc(vec_size * sizeof(uint16_t));

    uint8_t prf_out[128];
    for (int i = 0; i < K; i++) {
        mlkem_prf(r32, (uint8_t)i, prf_out, 128);
        mlkem_cbd(prf_out, MLKEM_ETA1, r_ + i*256);
        mlkem_prf(r32, (uint8_t)(K + i), prf_out, 128);
        mlkem_cbd(prf_out, MLKEM_ETA2, e1 + i*256);
    }
    mlkem_prf(r32, (uint8_t)(2*K), prf_out, 128);
    mlkem_cbd(prf_out, MLKEM_ETA2, e2);

    for (int i = 0; i < K; i++) {
        memcpy(rhat + i*256, r_ + i*256, 256*2);
        mlkem_ntt(rhat + i*256);
    }

    /* A^T */
    uint16_t *AT = OPENSSL_malloc(A_size * sizeof(uint16_t));
    for (int i = 0; i < K; i++)
        for (int j = 0; j < K; j++)
            memcpy(AT + (j*K + i)*256, A + (i*K + j)*256, 256*2);

    uint16_t *Atr = OPENSSL_malloc(vec_size * sizeof(uint16_t));
    mlkem_mvmul(K, AT, rhat, Atr);

    uint16_t *u = OPENSSL_malloc(vec_size * sizeof(uint16_t));
    for (int j = 0; j < K; j++) {
        mlkem_intt(Atr + j*256);
        for (int c = 0; c < 256; c++)
            u[j*256 + c] = (Atr[j*256 + c] + e1[j*256 + c]) % MLKEM_Q;
    }

    uint16_t tv[256] = {0};
    for (int i = 0; i < K; i++) {
        uint16_t tmp[256];
        mlkem_pmul(that + i*256, rhat + i*256, tmp);
        mlkem_padd(tv, tmp);
    }
    mlkem_intt(tv);

    uint16_t mu[256];
    {
        uint16_t bits[256];
        mlkem_byte_decode(m32, 1, bits);
        for (int i = 0; i < 256; i++)
            mu[i] = mlkem_decompress(bits[i], 1);
    }

    uint16_t v[256];
    for (int i = 0; i < 256; i++)
        v[i] = (uint16_t)((tv[i] + e2[i] + mu[i]) % MLKEM_Q);

    /* c1 */
    for (int j = 0; j < K; j++) {
        uint16_t cu[256];
        for (int c = 0; c < 256; c++)
            cu[c] = mlkem_compress(u[j*256 + c], MLKEM_DU);
        mlkem_byte_encode(cu, MLKEM_DU, ct + j * (MLKEM_DU * 32));
    }
    /* c2 */
    {
        uint16_t cv[256];
        for (int i = 0; i < 256; i++)
            cv[i] = mlkem_compress(v[i], MLKEM_DV);
        mlkem_byte_encode(cv, MLKEM_DV, ct + K * (MLKEM_DU * 32));
    }

    OPENSSL_cleanse(r_, vec_size*2);
    OPENSSL_cleanse(e1, vec_size*2);
    OPENSSL_cleanse(e2, 256*2);
    OPENSSL_cleanse(rhat, vec_size*2);
    OPENSSL_free(that);
    OPENSSL_free(A);
    OPENSSL_free(r_);
    OPENSSL_free(e1);
    OPENSSL_free(e2);
    OPENSSL_free(rhat);
    OPENSSL_free(AT);
    OPENSSL_free(Atr);
    OPENSSL_free(u);
}

static void mlkem_dec_kpke(int K, const uint8_t *dk_pke,
                           const uint8_t *ct, uint8_t m32[32]) {
    int vec_size = K * 256;
    uint16_t *u = OPENSSL_malloc(vec_size * sizeof(uint16_t));
    for (int j = 0; j < K; j++) {
        uint16_t cu[256];
        mlkem_byte_decode(ct + j * (MLKEM_DU * 32), MLKEM_DU, cu);
        for (int c = 0; c < 256; c++)
            u[j*256 + c] = mlkem_decompress(cu[c], MLKEM_DU);
    }

    uint16_t v[256];
    {
        uint16_t cv[256];
        mlkem_byte_decode(ct + K * (MLKEM_DU * 32), MLKEM_DV, cv);
        for (int i = 0; i < 256; i++)
            v[i] = mlkem_decompress(cv[i], MLKEM_DV);
    }

    uint16_t *shat = OPENSSL_malloc(vec_size * sizeof(uint16_t));
    for (int i = 0; i < K; i++)
        mlkem_byte_decode(dk_pke + i*384, 12, shat + i*256);

    uint16_t su[256] = {0};
    for (int i = 0; i < K; i++) {
        uint16_t untt[256];
        memcpy(untt, u + i*256, 256*2);
        mlkem_ntt(untt);
        uint16_t tmp[256];
        mlkem_pmul(shat + i*256, untt, tmp);
        mlkem_padd(su, tmp);
    }
    mlkem_intt(su);

    uint16_t w[256];
    for (int i = 0; i < 256; i++)
        w[i] = (uint16_t)((v[i] - su[i] + MLKEM_Q) % MLKEM_Q);

    uint16_t cw[256];
    for (int i = 0; i < 256; i++)
        cw[i] = mlkem_compress(w[i], 1);
    mlkem_byte_encode(cw, 1, m32);

    OPENSSL_cleanse(shat, vec_size*2);
    OPENSSL_free(u);
    OPENSSL_free(shat);
}

static void mlkem_keygen(int K, uint8_t *ek, uint8_t *dk) {
    int ek_len = kem_ek_bytes(K);
    int dk_len = kem_dk_bytes(K);
    uint8_t z[32], d[32];
    RAND_bytes(z, 32);
    RAND_bytes(d, 32);

    int dk_pke_len = K * 384;
    uint8_t *dk_pke = OPENSSL_malloc(dk_pke_len);
    mlkem_keypke(K, d, ek, dk_pke);

    uint8_t H[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, ek, ek_len);
    unsigned int hlen = 32;
    EVP_DigestFinal_ex(ctx, H, &hlen);
    EVP_MD_CTX_free(ctx);

    memcpy(dk,               dk_pke, dk_pke_len);
    memcpy(dk + dk_pke_len,  ek,     ek_len);
    memcpy(dk + dk_pke_len + ek_len, H, 32);
    memcpy(dk + dk_pke_len + ek_len + 32, z, 32);

    OPENSSL_cleanse(d, 32);
    OPENSSL_cleanse(z, 32);
    OPENSSL_cleanse(dk_pke, dk_pke_len);
    OPENSSL_free(dk_pke);
}

static void mlkem_encaps(int K, const uint8_t *ek,
                         uint8_t *ct, uint8_t *ss) {
    int ek_len = kem_ek_bytes(K);
    uint8_t m[32];
    RAND_bytes(m, 32);

    uint8_t H[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, ek, ek_len);
    unsigned int hl = 32;
    EVP_DigestFinal_ex(ctx, H, &hl);
    EVP_MD_CTX_free(ctx);

    uint8_t G[64];
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, m, 32);
    EVP_DigestUpdate(ctx, H, 32);
    unsigned int gl = 64;
    EVP_DigestFinal_ex(ctx, G, &gl);
    EVP_MD_CTX_free(ctx);

    const uint8_t *Kss = G;
    const uint8_t *r   = G + 32;

    mlkem_enc_kpke(K, ek, m, r, ct);
    memcpy(ss, Kss, 32);

    OPENSSL_cleanse(m, 32);
    OPENSSL_cleanse(G, 64);
}

static void mlkem_decaps(int K, const uint8_t *ct, const uint8_t *dk,
                         uint8_t *ss) {
    int ek_len = kem_ek_bytes(K);
    int dk_pke_len = K * 384;
    const uint8_t *dk_pke = dk;
    const uint8_t *ek     = dk + dk_pke_len;
    const uint8_t *H      = dk + dk_pke_len + ek_len;
    const uint8_t *z      = dk + dk_pke_len + ek_len + 32;

    uint8_t m_p[32];
    mlkem_dec_kpke(K, dk_pke, ct, m_p);

    uint8_t G[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, m_p, 32);
    EVP_DigestUpdate(ctx, H, 32);
    unsigned int gl = 64;
    EVP_DigestFinal_ex(ctx, G, &gl);
    EVP_MD_CTX_free(ctx);

    const uint8_t *Kp = G;
    const uint8_t *rp = G + 32;

    int ct_len = ek_len;
    uint8_t *cp = OPENSSL_malloc(ct_len);
    mlkem_enc_kpke(K, ek, m_p, rp, cp);

    uint8_t diff = 0;
    for (int i = 0; i < ct_len; i++)
        diff |= ct[i] ^ cp[i];

    uint8_t reject[32];
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(ctx, z, 32);
    EVP_DigestUpdate(ctx, ct, ct_len);
    EVP_DigestFinalXOF(ctx, reject, 32);
    EVP_MD_CTX_free(ctx);

    uint8_t mask = (uint8_t)(-(int8_t)(diff == 0));
    for (int i = 0; i < 32; i++)
        ss[i] = (Kp[i] & mask) | (reject[i] & ~mask);

    OPENSSL_cleanse(m_p, 32);
    OPENSSL_cleanse(G, 64);
    OPENSSL_cleanse(cp, ct_len);
    OPENSSL_free(cp);
    OPENSSL_cleanse(reject, 32);
}

/* ============================================================================
 * Python bindings
 * ========================================================================== */

static PyObject *py_keygen(PyObject *self, PyObject *args) {
    (void)self;
    int level;
    if (!PyArg_ParseTuple(args, "i", &level)) return NULL;
    if (level != 512 && level != 768 && level != 1024) {
        PyErr_SetString(PyExc_ValueError, "level must be 512, 768, or 1024");
        return NULL;
    }
    int K = (level == 512) ? 2 : (level == 768) ? 3 : 4;
    int ek_len = kem_ek_bytes(K);
    int dk_len = kem_dk_bytes(K);
    uint8_t *ek = OPENSSL_malloc(ek_len);
    uint8_t *dk = OPENSSL_malloc(dk_len);
    mlkem_keygen(K, ek, dk);
    PyObject *ek_obj = PyBytes_FromStringAndSize((char *)ek, ek_len);
    PyObject *dk_obj = PyBytes_FromStringAndSize((char *)dk, dk_len);
    OPENSSL_free(ek);
    OPENSSL_cleanse(dk, dk_len);
    OPENSSL_free(dk);
    if (!ek_obj || !dk_obj) {
        Py_XDECREF(ek_obj); Py_XDECREF(dk_obj);
        return NULL;
    }
    return PyTuple_Pack(2, ek_obj, dk_obj);
}

static PyObject *py_encaps(PyObject *self, PyObject *args) {
    (void)self;
    const uint8_t *ek;
    Py_ssize_t ek_len;
    int level;
    if (!PyArg_ParseTuple(args, "y#i", &ek, &ek_len, &level)) return NULL;
    if (level != 512 && level != 768 && level != 1024) {
        PyErr_SetString(PyExc_ValueError, "level must be 512, 768, or 1024");
        return NULL;
    }
    int K = (level == 512) ? 2 : (level == 768) ? 3 : 4;
    int exp_ek_len = kem_ek_bytes(K);
    if (ek_len != exp_ek_len) {
        PyErr_Format(PyExc_ValueError, "ek must be %d bytes for level %d", exp_ek_len, level);
        return NULL;
    }
    int ct_len = exp_ek_len;
    uint8_t *ct = OPENSSL_malloc(ct_len);
    uint8_t ss[32];
    mlkem_encaps(K, ek, ct, ss);
    PyObject *ct_obj = PyBytes_FromStringAndSize((char *)ct, ct_len);
    PyObject *ss_obj = PyBytes_FromStringAndSize((char *)ss, 32);
    OPENSSL_free(ct);
    OPENSSL_cleanse(ss, 32);
    if (!ct_obj || !ss_obj) {
        Py_XDECREF(ct_obj); Py_XDECREF(ss_obj);
        return NULL;
    }
    return PyTuple_Pack(2, ct_obj, ss_obj);
}

static PyObject *py_decaps(PyObject *self, PyObject *args) {
    (void)self;
    const uint8_t *ct, *dk;
    Py_ssize_t ct_len, dk_len;
    int level;
    if (!PyArg_ParseTuple(args, "y#y#i", &ct, &ct_len, &dk, &dk_len, &level)) return NULL;
    if (level != 512 && level != 768 && level != 1024) {
        PyErr_SetString(PyExc_ValueError, "level must be 512, 768, or 1024");
        return NULL;
    }
    int K = (level == 512) ? 2 : (level == 768) ? 3 : 4;
    int exp_ct_len = kem_ek_bytes(K);
    int exp_dk_len = kem_dk_bytes(K);
    if (ct_len != exp_ct_len) {
        PyErr_Format(PyExc_ValueError, "ct must be %d bytes", exp_ct_len);
        return NULL;
    }
    if (dk_len != exp_dk_len) {
        PyErr_Format(PyExc_ValueError, "dk must be %d bytes", exp_dk_len);
        return NULL;
    }
    uint8_t ss[32];
    mlkem_decaps(K, ct, dk, ss);
    PyObject *ret = PyBytes_FromStringAndSize((char *)ss, 32);
    OPENSSL_cleanse(ss, 32);
    return ret;
}

static PyMethodDef methods[] = {
    {"keygen", py_keygen, METH_VARARGS, "keygen(level) -> (ek, dk)"},
    {"encaps", py_encaps, METH_VARARGS, "encaps(ek, level) -> (ct, ss)"},
    {"decaps", py_decaps, METH_VARARGS, "decaps(ct, dk, level) -> ss"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "qsteg_mlkem",
    "ML-KEM-512/768/1024 for QSteg",
    -1,
    methods
};

PyMODINIT_FUNC PyInit_qsteg_mlkem(void) {
    mlkem_init_tables();
    RAND_poll();
    return PyModule_Create(&module);
}