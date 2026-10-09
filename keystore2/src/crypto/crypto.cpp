/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "keystore2"

#include "crypto.hpp"

#include "certificate_utils.h"

#include <android-base/properties.h>
#include <assert.h>
#include <log/log.h>
#include <openssl/aes.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/obj.h>
#include <openssl/pkcs8.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <cstdio>
#include <ctime>
#include <memory>
#include <mutex>
#include <vector>

// Copied from system/security/keystore/blob.h.

constexpr size_t kGcmTagLength = 128 / 8;
constexpr size_t kAes128KeySizeBytes = 128 / 8;

// Copied from system/security/keystore/blob.cpp.

#if defined(__clang__)
#define OPTNONE __attribute__((optnone))
#elif defined(__GNUC__)
#define OPTNONE __attribute__((optimize("O0")))
#else
#error Need a definition for OPTNONE
#endif

class ArrayEraser {
  public:
    ArrayEraser(uint8_t* arr, size_t size) : mArr(arr), mSize(size) {}
    OPTNONE ~ArrayEraser() { std::fill(mArr, mArr + mSize, 0); }

  private:
    volatile uint8_t* mArr;
    size_t mSize;
};

/**
 * Returns a EVP_CIPHER appropriate for the given key size.
 */
const EVP_CIPHER* getAesCipherForKey(size_t key_size) {
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    if (key_size == kAes128KeySizeBytes) {
        cipher = EVP_aes_128_gcm();
    }
    return cipher;
}

bool hmacSha256(const uint8_t* key, size_t key_size, const uint8_t* msg, size_t msg_size,
                uint8_t* out, size_t out_size) {
    const EVP_MD* digest = EVP_sha256();
    unsigned int actual_out_size = out_size;
    uint8_t* p = HMAC(digest, key, key_size, msg, msg_size, out, &actual_out_size);
    return (p != nullptr);
}

bool randomBytes(uint8_t* out, size_t len) {
    return RAND_bytes(out, len);
}

/*
 * Encrypt 'len' data at 'in' with AES-GCM, using 128-bit or 256-bit key at 'key', 96-bit IV at
 * 'iv' and write output to 'out' (which may be the same location as 'in') and 128-bit tag to
 * 'tag'.
 */
bool AES_gcm_encrypt(const uint8_t* in, uint8_t* out, size_t len, const uint8_t* key,
                     size_t key_size, const uint8_t* iv, uint8_t* tag) {

    // There can be 128-bit and 256-bit keys
    const EVP_CIPHER* cipher = getAesCipherForKey(key_size);

    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());

    EVP_EncryptInit_ex(ctx.get(), cipher, nullptr /* engine */, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0 /* no padding needed with GCM */);

    std::vector<uint8_t> out_tmp(len);
    uint8_t* out_pos = out_tmp.data();
    int out_len;

    EVP_EncryptUpdate(ctx.get(), out_pos, &out_len, in, len);
    out_pos += out_len;
    EVP_EncryptFinal_ex(ctx.get(), out_pos, &out_len);
    out_pos += out_len;
    if (out_pos - out_tmp.data() != static_cast<ssize_t>(len)) {
        ALOGD("Encrypted ciphertext is the wrong size, expected %zu, got %zd", len,
              out_pos - out_tmp.data());
        return false;
    }

    std::copy(out_tmp.data(), out_pos, out);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kGcmTagLength, tag);

    return true;
}

/*
 * Decrypt 'len' data at 'in' with AES-GCM, using 128-bit or 256-bit key at 'key', 96-bit IV at
 * 'iv', checking 128-bit tag at 'tag' and writing plaintext to 'out'(which may be the same
 * location as 'in').
 */
bool AES_gcm_decrypt(const uint8_t* in, uint8_t* out, size_t len, const uint8_t* key,
                     size_t key_size, const uint8_t* iv, const uint8_t* tag) {

    // There can be 128-bit and 256-bit keys
    const EVP_CIPHER* cipher = getAesCipherForKey(key_size);

    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());

    EVP_DecryptInit_ex(ctx.get(), cipher, nullptr /* engine */, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0 /* no padding needed with GCM */);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kGcmTagLength, const_cast<uint8_t*>(tag));

    std::vector<uint8_t> out_tmp(len);
    ArrayEraser out_eraser(out_tmp.data(), len);
    uint8_t* out_pos = out_tmp.data();
    int out_len;

    EVP_DecryptUpdate(ctx.get(), out_pos, &out_len, in, len);
    out_pos += out_len;
    if (!EVP_DecryptFinal_ex(ctx.get(), out_pos, &out_len)) {
        // No error log here; this is expected when trying two different keys to see which one
        // works.  The callers handle the error appropriately.
        return false;
    }
    out_pos += out_len;
    if (out_pos - out_tmp.data() != static_cast<ssize_t>(len)) {
        ALOGE("Encrypted plaintext is the wrong size, expected %zu, got %zd", len,
              out_pos - out_tmp.data());
        return false;
    }

    std::copy(out_tmp.data(), out_pos, out);

    return true;
}

// Copied from system/security/keystore/keymaster_enforcement.cpp.

class EvpMdCtx {
  public:
    EvpMdCtx() { EVP_MD_CTX_init(&ctx_); }
    ~EvpMdCtx() { EVP_MD_CTX_cleanup(&ctx_); }

    EVP_MD_CTX* get() { return &ctx_; }

  private:
    EVP_MD_CTX ctx_;
};

bool CreateKeyId(const uint8_t* key_blob, size_t len, km_id_t* out_id) {
    EvpMdCtx ctx;

    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr /* ENGINE */) &&
        EVP_DigestUpdate(ctx.get(), key_blob, len) &&
        EVP_DigestFinal_ex(ctx.get(), hash, &hash_len)) {
        assert(hash_len >= sizeof(*out_id));
        memcpy(out_id, hash, sizeof(*out_id));
        return true;
    }

    return false;
}

// Copied from system/security/keystore/user_state.h

static constexpr size_t SALT_SIZE = 16;

// Copied from system/security/keystore/user_state.cpp.

void PBKDF2(uint8_t* key, size_t key_len, const char* pw, size_t pw_len, const uint8_t* salt) {
    const EVP_MD* digest = EVP_sha256();

    // SHA1 was used prior to increasing the key size
    if (key_len == kAes128KeySizeBytes) {
        digest = EVP_sha1();
    }

    PKCS5_PBKDF2_HMAC(pw, pw_len, salt, SALT_SIZE, 8192, digest, key_len, key);
}

// New code.

bool HKDFExtract(uint8_t* out_key, size_t* out_len, const uint8_t* secret, size_t secret_len,
                 const uint8_t* salt, size_t salt_len) {
    const EVP_MD* digest = EVP_sha256();
    auto result = HKDF_extract(out_key, out_len, digest, secret, secret_len, salt, salt_len);
    return result == 1;
}

bool HKDFExpand(uint8_t* out_key, size_t out_len, const uint8_t* prk, size_t prk_len,
                const uint8_t* info, size_t info_len) {
    const EVP_MD* digest = EVP_sha256();
    auto result = HKDF_expand(out_key, out_len, digest, prk, prk_len, info, info_len);
    return result == 1;
}

int ECDHComputeKey(void* out, size_t out_len, const EC_POINT* pub_key, const EC_KEY* priv_key) {
    return ECDH_compute_key(out, out_len, pub_key, priv_key, nullptr);
}

EC_KEY* ECKEYGenerateKey() {
    EC_KEY* key = EC_KEY_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    EC_KEY_set_group(key, group);
    auto result = EC_KEY_generate_key(key);
    if (result == 0) {
        EC_GROUP_free(group);
        EC_KEY_free(key);
        return nullptr;
    }
    return key;
}

size_t ECKEYMarshalPrivateKey(const EC_KEY* priv_key, uint8_t* buf, size_t len) {
    CBB cbb;
    size_t out_len;
    if (!CBB_init_fixed(&cbb, buf, len) ||
        !EC_KEY_marshal_private_key(&cbb, priv_key, EC_PKEY_NO_PARAMETERS | EC_PKEY_NO_PUBKEY) ||
        !CBB_finish(&cbb, nullptr, &out_len)) {
        return 0;
    } else {
        return out_len;
    }
}

EC_KEY* ECKEYParsePrivateKey(const uint8_t* buf, size_t len) {
    CBS cbs;
    CBS_init(&cbs, buf, len);
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    auto result = EC_KEY_parse_private_key(&cbs, group);
    EC_GROUP_free(group);
    if (result != nullptr && CBS_len(&cbs) != 0) {
        EC_KEY_free(result);
        return nullptr;
    }
    return result;
}

size_t ECPOINTPoint2Oct(const EC_POINT* point, uint8_t* buf, size_t len) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    auto result = EC_POINT_point2oct(group, point, form, buf, len, nullptr);
    EC_GROUP_free(group);
    return result;
}

EC_POINT* ECPOINTOct2Point(const uint8_t* buf, size_t len) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    EC_POINT* point = EC_POINT_new(group);
    auto result = EC_POINT_oct2point(group, point, buf, len, nullptr);
    EC_GROUP_free(group);
    if (result == 0) {
        EC_POINT_free(point);
        return nullptr;
    }
    return point;
}

int extractSubjectFromCertificate(const uint8_t* cert_buf, size_t cert_len, uint8_t* subject_buf,
                                  size_t subject_buf_len) {
    if (!cert_buf || !subject_buf) {
        ALOGE("extractSubjectFromCertificate: received null pointer");
        return 0;
    }

    const uint8_t* p = cert_buf;
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr /* Allocate X509 struct */, &p, cert_len));
    if (!cert) {
        ALOGE("extractSubjectFromCertificate: failed to parse certificate");
        return 0;
    }

    X509_NAME* subject = X509_get_subject_name(cert.get());
    if (!subject) {
        ALOGE("extractSubjectFromCertificate: failed to retrieve subject name");
        return 0;
    }

    int subject_len = i2d_X509_NAME(subject, nullptr /* Don't copy the data */);
    if (subject_len < 0) {
        ALOGE("extractSubjectFromCertificate: error obtaining encoded subject name length");
        return 0;
    }

    if (subject_len > subject_buf_len) {
        // Return the subject length, negated, so the caller knows how much
        // buffer space is required.
        ALOGI("extractSubjectFromCertificate: needed %d bytes for subject, caller provided %zu",
              subject_len, subject_buf_len);
        return -subject_len;
    }

    // subject_buf has enough space.
    uint8_t* tmp = subject_buf;
    return i2d_X509_NAME(subject, &tmp);
}

static bool parseHexDigestProperty(const std::string& value, std::vector<uint8_t>* out) {
    if (!out || value.size() != 64) {
        return false;
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out->clear();
    out->reserve(32);
    for (size_t i = 0; i < value.size(); i += 2) {
        int hi = nibble(value[i]);
        int lo = nibble(value[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out->push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out->size() == 32;
}

static bool isAllZeroDigest(const std::vector<uint8_t>& v) {
    if (v.empty()) return true;
    for (uint8_t b : v) {
        if (b != 0) return false;
    }
    return true;
}

static bool readBootDigestProperty(const char* prop_name, std::vector<uint8_t>* out) {
    if (!prop_name || !out) return false;
    const std::string value = android::base::GetProperty(prop_name, "");
    if (!parseHexDigestProperty(value, out)) return false;
    if (isAllZeroDigest(*out)) return false;
    return true;
}

static void appendDerLength(std::vector<uint8_t>* out, size_t len) {
    if (len < 0x80) {
        out->push_back(static_cast<uint8_t>(len));
        return;
    }
    uint8_t tmp[8];
    size_t n = 0;
    size_t v = len;
    while (v > 0) {
        tmp[n++] = static_cast<uint8_t>(v & 0xff);
        v >>= 8;
    }
    out->push_back(static_cast<uint8_t>(0x80 | n));
    while (n > 0) {
        out->push_back(tmp[--n]);
    }
}

static std::vector<uint8_t> makeDerTlv(uint8_t tag, const std::vector<uint8_t>& value) {
    std::vector<uint8_t> out;
    out.reserve(1 + 5 + value.size());
    out.push_back(tag);
    appendDerLength(&out, value.size());
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

static std::vector<uint8_t> makeDerInteger(uint64_t value) {
    std::vector<uint8_t> bytes;
    do {
        bytes.insert(bytes.begin(), static_cast<uint8_t>(value & 0xFF));
        value >>= 8;
    } while (value != 0);
    if (bytes[0] & 0x80) bytes.insert(bytes.begin(), 0x00);
    return makeDerTlv(0x02, bytes);
}

static uint32_t osVersionFromProperty() {
    const std::string release = android::base::GetProperty("ro.build.version.release", "");
    int major = 0, minor = 0, sub = 0;
    if (sscanf(release.c_str(), "%d.%d.%d", &major, &minor, &sub) < 1) return 0;
    return major * 10000 + minor * 100 + sub;
}

static uint32_t patchLevelFromProperty(bool with_day) {
    const std::string patch = android::base::GetProperty("ro.build.version.security_patch", "");
    int year = 0, month = 0, day = 0;
    if (sscanf(patch.c_str(), "%d-%d-%d", &year, &month, &day) != 3) return 0;
    return with_day ? year * 10000 + month * 100 + day : year * 100 + month;
}

static std::vector<uint8_t> makeExplicitContextTlv(uint32_t tag_no,
                                                   const std::vector<uint8_t>& val) {
    std::vector<uint8_t> out;
    if (tag_no < 31) {
        out.push_back(static_cast<uint8_t>(0xA0 | tag_no));
    } else {
        out.push_back(0xBF);
        if (tag_no < 128) {
            out.push_back(static_cast<uint8_t>(tag_no));
        } else {
            out.push_back(static_cast<uint8_t>((tag_no >> 7) | 0x80));
            out.push_back(static_cast<uint8_t>(tag_no & 0x7F));
        }
    }
    appendDerLength(&out, val.size());
    out.insert(out.end(), val.begin(), val.end());
    return out;
}

static bool sha256OfBytes(const uint8_t* data, size_t len, std::vector<uint8_t>* out) {
    if (!data || !out) return false;
    out->assign(SHA256_DIGEST_LENGTH, 0);
    return SHA256(data, len, out->data()) != nullptr;
}

static void resolveVerifiedBootFields(std::vector<uint8_t>* out_key,
                                      std::vector<uint8_t>* out_hash) {
    if (!out_key || !out_hash) return;
    out_key->clear();
    out_hash->clear();

    readBootDigestProperty("ro.boot.vbmeta.digest", out_hash);
    readBootDigestProperty("ro.boot.vbmeta.public_key_digest", out_key);

    if (out_key->size() != 32 || isAllZeroDigest(*out_key)) {
        static constexpr char kFallbackKeySeed[] = "keystore_compat_verified_boot_key_seed_v1";
        sha256OfBytes(reinterpret_cast<const uint8_t*>(kFallbackKeySeed),
                      sizeof(kFallbackKeySeed) - 1, out_key);
    }
    if (out_hash->size() != 32 || isAllZeroDigest(*out_hash)) {
        static constexpr char kFallbackHashSeed[] = "keystore_compat_verified_boot_hash_seed_v1";
        sha256OfBytes(reinterpret_cast<const uint8_t*>(kFallbackHashSeed),
                      sizeof(kFallbackHashSeed) - 1, out_hash);
    }
}

static EVP_PKEY* getSoftwareRootKey() {
    static bssl::UniquePtr<EVP_PKEY> s_root_key;
    static std::once_flag s_key_once;
    std::call_once(s_key_once, []() {
        bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
        if (ec && EC_KEY_generate_key(ec.get())) {
            s_root_key.reset(EVP_PKEY_new());
            if (s_root_key) {
                EVP_PKEY_set1_EC_KEY(s_root_key.get(), ec.get());
            }
        }
    });
    return s_root_key.get();
}

static X509* getSoftwareRootCert() {
    static bssl::UniquePtr<X509> s_root_cert;
    static std::once_flag s_cert_once;
    std::call_once(s_cert_once, []() {
        EVP_PKEY* root_key = getSoftwareRootKey();
        if (!root_key) return;
        bssl::UniquePtr<X509> cert(X509_new());
        if (!cert) return;
        X509_set_version(cert.get(), 2);
        bssl::UniquePtr<BIGNUM> serial_bn(BN_new());
        if (serial_bn && BN_set_word(serial_bn.get(), 1)) {
            bssl::UniquePtr<ASN1_INTEGER> serial(BN_to_ASN1_INTEGER(serial_bn.get(), nullptr));
            if (serial) {
                X509_set_serialNumber(cert.get(), serial.get());
            }
        }
        X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert.get()), 315360000L);
        X509_set_pubkey(cert.get(), root_key);
        X509_NAME* name = X509_get_subject_name(cert.get());
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const uint8_t*>("Android Software Attestation Root"), -1, -1, 0);
        X509_set_issuer_name(cert.get(), name);
        bssl::UniquePtr<BASIC_CONSTRAINTS> bc(BASIC_CONSTRAINTS_new());
        if (bc) {
            bc->ca = 1;
            X509_add1_ext_i2d(cert.get(), NID_basic_constraints, bc.get(), 1, 0);
        }
        if (!keystore::signCert(cert.get(), root_key)) {
            s_root_cert = std::move(cert);
        }
    });
    return s_root_cert.get();
}

int getSoftwareRootCertDer(uint8_t* out_cert_buf, size_t out_cert_buf_len) {
    if (!out_cert_buf) return 0;
    X509* root_cert = getSoftwareRootCert();
    if (!root_cert) return 0;
    auto encoded_or_error = keystore::encodeCert(root_cert);
    if (std::holds_alternative<keystore::CertUtilsError>(encoded_or_error)) {
        return 0;
    }
    const auto& encoded = std::get<std::vector<uint8_t>>(encoded_or_error);
    if (encoded.size() > out_cert_buf_len) {
        return -static_cast<int>(encoded.size());
    }
    memcpy(out_cert_buf, encoded.data(), encoded.size());
    return static_cast<int>(encoded.size());
}

int generateSoftwareAttestedKey(int key_type, int rsa_key_size, const uint8_t* challenge,
                                size_t challenge_len, const uint8_t* attest_app_id_buf,
                                size_t attest_app_id_len, int is_attest_key,
                                uint8_t* out_privkey_buf, size_t out_privkey_buf_len,
                                size_t* out_privkey_len, uint8_t* out_cert_buf,
                                size_t out_cert_buf_len) {
    if (!out_privkey_buf || !out_privkey_len || !out_cert_buf) {
        ALOGE("generateSoftwareAttestedKey: null pointer input");
        return 0;
    }

    X509* signer_cert_ptr = getSoftwareRootCert();
    EVP_PKEY* signer_key_ptr = getSoftwareRootKey();
    if (!signer_cert_ptr || !signer_key_ptr) {
        ALOGE("generateSoftwareAttestedKey: failed to obtain software root cert or key");
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (!pkey) return 0;

    int key_algorithm_val = 3;  // 3 = EC, 1 = RSA
    int key_size_val = 256;

    if (key_type == 1) {  // RSA
        key_algorithm_val = 1;
        key_size_val = (rsa_key_size >= 2048) ? rsa_key_size : 2048;
        bssl::UniquePtr<RSA> rsa(RSA_new());
        bssl::UniquePtr<BIGNUM> e(BN_new());
        if (!rsa || !e || !BN_set_word(e.get(), RSA_F4) ||
            !RSA_generate_key_ex(rsa.get(), key_size_val, e.get(), nullptr)) {
            ALOGE("generateSoftwareAttestedKey: RSA generation failed");
            return 0;
        }
        if (!EVP_PKEY_set1_RSA(pkey.get(), rsa.get())) return 0;
    } else {  // EC P-256
        bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
        if (!ec || !EC_KEY_generate_key(ec.get())) {
            ALOGE("generateSoftwareAttestedKey: EC generation failed");
            return 0;
        }
        if (!EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get())) return 0;
    }

    std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)> p8(
        EVP_PKEY2PKCS8(pkey.get()), PKCS8_PRIV_KEY_INFO_free);
    if (!p8) {
        ALOGE("generateSoftwareAttestedKey: EVP_PKEY2PKCS8 failed");
        return 0;
    }
    int p8_len = i2d_PKCS8_PRIV_KEY_INFO(p8.get(), nullptr);
    if (p8_len <= 0 || static_cast<size_t>(p8_len) > out_privkey_buf_len) {
        ALOGE("generateSoftwareAttestedKey: PKCS8 buffer too small or encode failed");
        return 0;
    }
    uint8_t* p8_ptr = out_privkey_buf;
    if (i2d_PKCS8_PRIV_KEY_INFO(p8.get(), &p8_ptr) <= 0) {
        ALOGE("generateSoftwareAttestedKey: i2d_PKCS8_PRIV_KEY_INFO failed");
        return 0;
    }
    *out_privkey_len = static_cast<size_t>(p8_len);

    bssl::UniquePtr<X509> cert(X509_new());
    if (!cert) return 0;
    if (!X509_set_version(cert.get(), 2)) return 0;

    bssl::UniquePtr<BIGNUM> serial_bn(BN_new());
    if (!serial_bn || !BN_pseudo_rand(serial_bn.get(), 64, 0, 0)) return 0;
    bssl::UniquePtr<ASN1_INTEGER> serial(BN_to_ASN1_INTEGER(serial_bn.get(), nullptr));
    if (!serial || !X509_set_serialNumber(cert.get(), serial.get())) return 0;

    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 315360000L);

    if (!X509_set_pubkey(cert.get(), pkey.get())) return 0;
    if (!X509_set_issuer_name(cert.get(), X509_get_subject_name(signer_cert_ptr))) return 0;

    X509_NAME* subj = X509_get_subject_name(cert.get());
    if (!subj || !X509_NAME_add_entry_by_txt(
                     subj, "CN", MBSTRING_ASC,
                     reinterpret_cast<const uint8_t*>("Android Keystore Key"), -1, -1, 0)) {
        return 0;
    }

    std::vector<uint8_t> boot_key, boot_hash;
    resolveVerifiedBootFields(&boot_key, &boot_hash);

    std::vector<uint8_t> boot_key_der = makeDerTlv(0x04, boot_key);
    std::vector<uint8_t> boot_hash_der = makeDerTlv(0x04, boot_hash);

    std::vector<uint8_t> rot_val;
    rot_val.insert(rot_val.end(), boot_key_der.begin(), boot_key_der.end());
    const std::vector<uint8_t> locked_der = {0x01, 0x01, 0xff};
    rot_val.insert(rot_val.end(), locked_der.begin(), locked_der.end());
    const std::vector<uint8_t> verified_der = {0x0A, 0x01, 0x00};
    rot_val.insert(rot_val.end(), verified_der.begin(), verified_der.end());
    rot_val.insert(rot_val.end(), boot_hash_der.begin(), boot_hash_der.end());
    std::vector<uint8_t> rot_seq = makeDerTlv(0x30, rot_val);

    std::vector<uint8_t> tee_items;

    std::vector<uint8_t> purpose_set_val;
    const std::vector<uint8_t> p_sign = {0x02, 0x01, 0x02};
    const std::vector<uint8_t> p_verify = {0x02, 0x01, 0x03};
    purpose_set_val.insert(purpose_set_val.end(), p_sign.begin(), p_sign.end());
    purpose_set_val.insert(purpose_set_val.end(), p_verify.begin(), p_verify.end());
    if (is_attest_key) {
        const std::vector<uint8_t> p_attest = {0x02, 0x01, 0x07};
        purpose_set_val.insert(purpose_set_val.end(), p_attest.begin(), p_attest.end());
    }
    std::vector<uint8_t> purpose_set = makeDerTlv(0x31, purpose_set_val);
    auto tag1 = makeExplicitContextTlv(1, purpose_set);
    tee_items.insert(tee_items.end(), tag1.begin(), tag1.end());

    std::vector<uint8_t> alg_int = {0x02, 0x01, static_cast<uint8_t>(key_algorithm_val)};
    auto tag2 = makeExplicitContextTlv(2, alg_int);
    tee_items.insert(tee_items.end(), tag2.begin(), tag2.end());

    auto tag3 = makeExplicitContextTlv(3, makeDerInteger(key_size_val));
    tee_items.insert(tee_items.end(), tag3.begin(), tag3.end());

    std::vector<uint8_t> dig_set_val = {0x02, 0x01, 0x04};
    std::vector<uint8_t> dig_set = makeDerTlv(0x31, dig_set_val);
    auto tag5 = makeExplicitContextTlv(5, dig_set);
    tee_items.insert(tee_items.end(), tag5.begin(), tag5.end());

    if (key_algorithm_val == 3) {
        auto tag10 = makeExplicitContextTlv(10, makeDerInteger(1));  // 1 = secp256r1 (P-256)
        tee_items.insert(tee_items.end(), tag10.begin(), tag10.end());
    }

    if (key_algorithm_val == 1) {
        const std::vector<uint8_t> mgf_dig_set_val = {0x02, 0x01, 0x02,
                                                      0x02, 0x01, 0x04};  // SHA-1, SHA-256
        std::vector<uint8_t> mgf_set = makeDerTlv(0x31, mgf_dig_set_val);
        auto tag203 = makeExplicitContextTlv(203, mgf_set);
        tee_items.insert(tee_items.end(), tag203.begin(), tag203.end());
    }

    std::vector<uint8_t> null_val = {0x05, 0x00};
    auto tag503 = makeExplicitContextTlv(503, null_val);
    tee_items.insert(tee_items.end(), tag503.begin(), tag503.end());

    std::vector<uint8_t> orig_val = {0x02, 0x01, 0x00};
    auto tag702 = makeExplicitContextTlv(702, orig_val);
    tee_items.insert(tee_items.end(), tag702.begin(), tag702.end());

    auto tag704 = makeExplicitContextTlv(704, rot_seq);
    tee_items.insert(tee_items.end(), tag704.begin(), tag704.end());

    auto tag705 = makeExplicitContextTlv(705, makeDerInteger(osVersionFromProperty()));
    tee_items.insert(tee_items.end(), tag705.begin(), tag705.end());

    auto tag706 = makeExplicitContextTlv(706, makeDerInteger(patchLevelFromProperty(false)));
    tee_items.insert(tee_items.end(), tag706.begin(), tag706.end());

    uint32_t patch_day_val = patchLevelFromProperty(true);
    if (patch_day_val > 0) {
        const std::vector<uint8_t> patch_with_day = makeDerInteger(patch_day_val);
        auto tag718 = makeExplicitContextTlv(718, patch_with_day);
        tee_items.insert(tee_items.end(), tag718.begin(), tag718.end());
        auto tag719 = makeExplicitContextTlv(719, patch_with_day);
        tee_items.insert(tee_items.end(), tag719.begin(), tag719.end());
    }

    std::vector<uint8_t> tee_enforced_seq = makeDerTlv(0x30, tee_items);

    std::vector<uint8_t> kd_items;
    const std::vector<uint8_t> att_ver = {0x02, 0x02, 0x01, 0x2C};
    const std::vector<uint8_t> att_sec = {0x0A, 0x01, 0x01};
    const std::vector<uint8_t> km_ver = {0x02, 0x02, 0x01, 0x2C};
    const std::vector<uint8_t> km_sec = {0x0A, 0x01, 0x01};
    size_t safe_challenge_len = std::min(challenge_len, static_cast<size_t>(128));
    std::vector<uint8_t> chal_oct =
        makeDerTlv(0x04, std::vector<uint8_t>(challenge, challenge + safe_challenge_len));
    const std::vector<uint8_t> uniq_id = {0x04, 0x00};

    std::vector<uint8_t> sw_items;
    const uint64_t now_ms = static_cast<uint64_t>(time(nullptr)) * 1000;
    auto tag701 = makeExplicitContextTlv(701, makeDerInteger(now_ms));
    sw_items.insert(sw_items.end(), tag701.begin(), tag701.end());
    if (attest_app_id_buf && attest_app_id_len > 0) {
        auto tag709 = makeExplicitContextTlv(
            709, makeDerTlv(0x04, std::vector<uint8_t>(attest_app_id_buf,
                                                       attest_app_id_buf + attest_app_id_len)));
        sw_items.insert(sw_items.end(), tag709.begin(), tag709.end());
    }
    const std::vector<uint8_t> sw_enforced = makeDerTlv(0x30, sw_items);

    kd_items.insert(kd_items.end(), att_ver.begin(), att_ver.end());
    kd_items.insert(kd_items.end(), att_sec.begin(), att_sec.end());
    kd_items.insert(kd_items.end(), km_ver.begin(), km_ver.end());
    kd_items.insert(kd_items.end(), km_sec.begin(), km_sec.end());
    kd_items.insert(kd_items.end(), chal_oct.begin(), chal_oct.end());
    kd_items.insert(kd_items.end(), uniq_id.begin(), uniq_id.end());
    kd_items.insert(kd_items.end(), sw_enforced.begin(), sw_enforced.end());
    kd_items.insert(kd_items.end(), tee_enforced_seq.begin(), tee_enforced_seq.end());

    std::vector<uint8_t> kd_seq = makeDerTlv(0x30, kd_items);

    bssl::UniquePtr<ASN1_OCTET_STRING> ext_data(ASN1_OCTET_STRING_new());
    if (!ext_data || ASN1_OCTET_STRING_set(ext_data.get(), kd_seq.data(),
                                           static_cast<int>(kd_seq.size())) != 1) {
        return 0;
    }
    bssl::UniquePtr<ASN1_OBJECT> ext_oid(OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1));
    if (!ext_oid) return 0;
    bssl::UniquePtr<X509_EXTENSION> ext(
        X509_EXTENSION_create_by_OBJ(nullptr, ext_oid.get(), 0, ext_data.get()));
    if (!ext || !X509_add_ext(cert.get(), ext.get(), -1)) return 0;

    if (auto e = keystore::signCert(cert.get(), signer_key_ptr); e) {
        ALOGE("generateSoftwareAttestedKey: signCert failed");
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> signer_pubkey(X509_get_pubkey(signer_cert_ptr));
    if (!signer_pubkey || X509_verify(cert.get(), signer_pubkey.get()) != 1) {
        ALOGE("generateSoftwareAttestedKey: verification failed");
        return 0;
    }

    auto encoded_or_error = keystore::encodeCert(cert.get());
    if (std::holds_alternative<keystore::CertUtilsError>(encoded_or_error)) {
        return 0;
    }
    const auto& encoded = std::get<std::vector<uint8_t>>(encoded_or_error);
    if (encoded.size() > out_cert_buf_len) {
        return -static_cast<int>(encoded.size());
    }
    memcpy(out_cert_buf, encoded.data(), encoded.size());
    return static_cast<int>(encoded.size());
}
