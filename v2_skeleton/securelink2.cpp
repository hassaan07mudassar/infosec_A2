// Hassaan Mudassar — 23i-0536 — CS3002 Information Security — Assignment 2
// SmartLock v2 record and policy module.
//
// OpenSSL building blocks: EVP for AES-GCM, EVP_KDF "HKDF" for key derivation.

#include "securelink2.hpp"
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

namespace sl2 {

// Fixed 4-byte prefix for all record nonces under SmartLock v2 ("SL02")
static const uint8_t kNoncePrefix[4] = {0x53, 0x4c, 0x30, 0x32};

std::vector<std::string> strong_suites() {
    static const char* const kSuites[] = {"AES256-GCM", "AES128-GCM"};
    return std::vector<std::string>(kSuites, kSuites + 2);
}

std::string choose_suite(const std::vector<std::string>& hub_offer) {
    static const char* const kPreferred[] = {"AES256-GCM", "AES128-GCM"};
    const size_t kNumPreferred = sizeof(kPreferred) / sizeof(kPreferred[0]);

    for (size_t i = 0; i < kNumPreferred; ++i) {
        for (size_t j = 0; j < hub_offer.size(); ++j) {
            if (hub_offer[j] == kPreferred[i]) {
                return std::string(kPreferred[i]);
            }
        }
    }
    return "";
}

std::vector<uint8_t> derive_key(const std::vector<uint8_t>& shared_secret,
                                const std::string& suite, const std::string& context) {
    const int kl = keylen(suite);
    if (kl <= 0 || kl > 32) {
        throw std::runtime_error("derive_key: unaccepted or unsupported cipher suite");
    }

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        throw std::runtime_error("derive_key: EVP_KDF_fetch HKDF failed");
    }

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        throw std::runtime_error("derive_key: EVP_KDF_CTX_new failed");
    }

    char digest_name[] = "SHA256";
    static const char kHkdfSalt[] = "smartlock-v2-salt";

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name, 0);
    params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY,
        const_cast<uint8_t*>(shared_secret.data()),
        shared_secret.size()
    );
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO,
        const_cast<char*>(context.data()),
        context.size()
    );
    params[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT,
        const_cast<char*>(kHkdfSalt),
        sizeof(kHkdfSalt) - 1
    );
    params[4] = OSSL_PARAM_construct_end();

    uint8_t out_key[32];
    if (EVP_KDF_derive(kctx, out_key, (size_t)kl, params) <= 0) {
        EVP_KDF_CTX_free(kctx);
        throw std::runtime_error("derive_key: EVP_KDF_derive failed");
    }

    EVP_KDF_CTX_free(kctx);
    return std::vector<uint8_t>(out_key, out_key + kl);
}

std::vector<uint8_t> make_nonce(uint64_t seqno) {
    uint8_t n[12];
    n[0] = kNoncePrefix[0];
    n[1] = kNoncePrefix[1];
    n[2] = kNoncePrefix[2];
    n[3] = kNoncePrefix[3];

    // Encode 64-bit sequence number in big-endian order into the last 8 bytes
    uint64_t temp = seqno;
    for (int i = 7; i >= 0; --i) {
        n[4 + i] = static_cast<uint8_t>(temp & 0xff);
        temp >>= 8;
    }

    return std::vector<uint8_t>(n, n + 12);
}

std::vector<uint8_t> seal(const std::vector<uint8_t>& key, uint64_t seqno, const std::string& plaintext) {
    const EVP_CIPHER* cipher = nullptr;
    if (key.size() == 32) {
        cipher = EVP_aes_256_gcm();
    } else if (key.size() == 16) {
        cipher = EVP_aes_128_gcm();
    } else {
        throw std::runtime_error("seal: unsupported key length");
    }

    const size_t pt_len = plaintext.size();
    const size_t rec_len = 8 + pt_len + 16;
    uint8_t* out = new uint8_t[rec_len];

    // Encode 64-bit sequence number in big-endian into the first 8 bytes
    uint64_t temp = seqno;
    for (int i = 7; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(temp & 0xff);
        temp >>= 8;
    }

    auto nonce = make_nonce(seqno);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        delete[] out;
        throw std::runtime_error("seal: EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) <= 0 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] out;
        throw std::runtime_error("seal: cipher init failed");
    }

    int len = 0;
    // Bind sequence number as Additional Authenticated Data (AAD)
    if (EVP_EncryptUpdate(ctx, nullptr, &len, out, 8) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] out;
        throw std::runtime_error("seal: setting AAD failed");
    }

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, out + 8, &len,
                           reinterpret_cast<const unsigned char*>(plaintext.data()),
                           static_cast<int>(pt_len)) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] out;
        throw std::runtime_error("seal: EncryptUpdate failed");
    }
    int outl = len;

    if (EVP_EncryptFinal_ex(ctx, out + 8 + outl, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] out;
        throw std::runtime_error("seal: EncryptFinal failed");
    }
    outl += len;

    // Append 16-byte GCM authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + 8 + outl) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        delete[] out;
        throw std::runtime_error("seal: getting tag failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> result(out, out + rec_len);
    delete[] out;
    return result;
}

std::string open_record(const std::vector<uint8_t>& key, const std::vector<uint8_t>& record,
                        uint64_t expected_seqno) {
    if (record.size() < 8 + 16) {
        throw std::runtime_error("open_record: record too short");
    }

    const EVP_CIPHER* cipher = nullptr;
    if (key.size() == 32) {
        cipher = EVP_aes_256_gcm();
    } else if (key.size() == 16) {
        cipher = EVP_aes_128_gcm();
    } else {
        throw std::runtime_error("open_record: unsupported key length");
    }

    // Parse the 64-bit sequence number from the first 8 bytes (big-endian)
    uint64_t parsed_seqno = 0;
    for (int i = 0; i < 8; ++i) {
        parsed_seqno = (parsed_seqno << 8) | record[i];
    }

    // Strict validation: reject any replayed, dropped, or out-of-order record
    if (parsed_seqno != expected_seqno) {
        throw std::runtime_error("open_record: sequence number mismatch (replay / reorder rejected)");
    }

    const size_t ct_len = record.size() - 8 - 16;
    const uint8_t* ct_data = record.data() + 8;
    const uint8_t* tag_data = record.data() + 8 + ct_len;

    auto nonce = make_nonce(parsed_seqno);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("open_record: EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) <= 0 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("open_record: cipher init failed");
    }

    int len = 0;
    // Authenticate the sequence number as AAD
    if (EVP_DecryptUpdate(ctx, nullptr, &len, record.data(), 8) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("open_record: setting AAD failed");
    }

    uint8_t* pt_buf = new uint8_t[ct_len + 1];
    if (EVP_DecryptUpdate(ctx, pt_buf, &len, ct_data, static_cast<int>(ct_len)) <= 0) {
        delete[] pt_buf;
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("open_record: DecryptUpdate failed");
    }
    int outl = len;

    // Set expected 16-byte authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag_data)) <= 0) {
        delete[] pt_buf;
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("open_record: setting tag failed");
    }

    int ok = EVP_DecryptFinal_ex(ctx, pt_buf + outl, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ok <= 0) {
        delete[] pt_buf;
        throw std::runtime_error("open_record: auth tag verification failed (tampered ciphertext / tag)");
    }
    outl += len;

    std::string result(reinterpret_cast<char*>(pt_buf), outl);
    delete[] pt_buf;
    return result;
}

}  // namespace sl2
