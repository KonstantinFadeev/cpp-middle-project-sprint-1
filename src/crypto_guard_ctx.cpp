#include "crypto_guard_ctx.h"
#include <array>
#include <iomanip>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {

namespace {

constexpr size_t BUFFER_SIZE = 4096;

std::string GetOpenSSLErrorString() {
    unsigned long errCode = ERR_get_error();
    if (errCode == 0) {
        return "Unknown OpenSSL error";
    }

    char errorBuffer[256];
    ERR_error_string_n(errCode, errorBuffer, sizeof(errorBuffer));
    return std::string(errorBuffer);
}

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

struct MdCtxDeleter {
    void operator()(EVP_MD_CTX *ctx) const {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }
};
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

}  // namespace

class CryptoGuardCtx::Impl {
public:
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;
        static const size_t IV_SIZE = 16;
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();

        int encrypt;
        std::array<unsigned char, KEY_SIZE> key;
        std::array<unsigned char, IV_SIZE> iv;
    };

    Impl() { OpenSSL_add_all_algorithms(); }

    ~Impl() { EVP_cleanup(); }

    Impl(const Impl &) = delete;
    Impl &operator=(const Impl &) = delete;

    Impl(Impl &&) noexcept = default;
    Impl &operator=(Impl &&) noexcept = default;

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()),
                                    static_cast<int>(password.size()), 1, params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error("Failed to create a key from password: " + GetOpenSSLErrorString());
        }

        return params;
    }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream.good()) {
            throw std::runtime_error("Input stream is not in good state");
        }
        if (!outStream.good()) {
            throw std::runtime_error("Output stream is not in good state");
        }

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;
        CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, params.key.data(), params.iv.data()) != 1) {
            throw std::runtime_error("Failed to initialize encryption: " + GetOpenSSLErrorString());
        }

        std::vector<unsigned char> inBuffer(BUFFER_SIZE);
        std::vector<unsigned char> outBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);

        while (inStream.good() && !inStream.eof()) {
            inStream.read(reinterpret_cast<char *>(inBuffer.data()), BUFFER_SIZE);
            std::streamsize bytesRead = inStream.gcount();

            if (bytesRead > 0) {
                int outLen = 0;
                if (EVP_EncryptUpdate(ctx.get(), outBuffer.data(), &outLen, inBuffer.data(),
                                      static_cast<int>(bytesRead)) != 1) {
                    throw std::runtime_error("Encryption failed");
                }

                if (outLen > 0) {
                    outStream.write(reinterpret_cast<const char *>(outBuffer.data()), outLen);
                    if (!outStream.good()) {
                        throw std::runtime_error("Failed to write encrypted data");
                    }
                }
            }
        }

        int finalLen = 0;
        if (EVP_EncryptFinal_ex(ctx.get(), outBuffer.data(), &finalLen) != 1) {
            throw std::runtime_error("Failed to finalize encryption: " + GetOpenSSLErrorString());
        }

        if (finalLen > 0) {
            outStream.write(reinterpret_cast<const char *>(outBuffer.data()), finalLen);
            if (!outStream.good()) {
                throw std::runtime_error("Failed to write final encrypted data");
            }
        }

        outStream.flush();
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream.good()) {
            throw std::runtime_error("Input stream is not in good state");
        }
        if (!outStream.good()) {
            throw std::runtime_error("Output stream is not in good state");
        }

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;

        CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, params.key.data(), params.iv.data()) != 1) {
            throw std::runtime_error("Failed to initialize decryption: " + GetOpenSSLErrorString());
        }

        std::vector<unsigned char> inBuffer(BUFFER_SIZE);
        std::vector<unsigned char> outBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);

        while (inStream.good() && !inStream.eof()) {
            inStream.read(reinterpret_cast<char *>(inBuffer.data()), BUFFER_SIZE);
            std::streamsize bytesRead = inStream.gcount();

            if (bytesRead > 0) {
                int outLen = 0;
                if (EVP_DecryptUpdate(ctx.get(), outBuffer.data(), &outLen, inBuffer.data(),
                                      static_cast<int>(bytesRead)) != 1) {
                    throw std::runtime_error("Decryption failed");
                }

                if (outLen > 0) {
                    outStream.write(reinterpret_cast<const char *>(outBuffer.data()), outLen);
                    if (!outStream.good()) {
                        throw std::runtime_error("Failed to write decrypted data");
                    }
                }
            }
        }

        int finalLen = 0;
        if (EVP_DecryptFinal_ex(ctx.get(), outBuffer.data(), &finalLen) != 1) {
            throw std::runtime_error("Failed to finalize decryption (possibly wrong password or corrupted data): " +
                                     GetOpenSSLErrorString());
        }

        if (finalLen > 0) {
            outStream.write(reinterpret_cast<const char *>(outBuffer.data()), finalLen);
            if (!outStream.good()) {
                throw std::runtime_error("Failed to write final decrypted data");
            }
        }

        outStream.flush();
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        if (!inStream.good()) {
            throw std::runtime_error("Input stream is not in good state");
        }

        MdCtxPtr ctx(EVP_MD_CTX_new());
        if (!ctx) {
            throw std::runtime_error("Failed to create message digest context");
        }

        if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
            throw std::runtime_error("Failed to initialize SHA-256: " + GetOpenSSLErrorString());
        }

        std::vector<unsigned char> buffer(BUFFER_SIZE);
        while (inStream.good() && !inStream.eof()) {
            inStream.read(reinterpret_cast<char *>(buffer.data()), BUFFER_SIZE);
            std::streamsize bytesRead = inStream.gcount();

            if (bytesRead > 0) {
                if (EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(bytesRead)) != 1) {
                    throw std::runtime_error("Failed to update digest");
                }
            }
        }

        std::array<unsigned char, EVP_MAX_MD_SIZE> hash;
        unsigned int hashLen = 0;
        if (EVP_DigestFinal_ex(ctx.get(), hash.data(), &hashLen) != 1) {
            throw std::runtime_error("Failed to finalize digest: " + GetOpenSSLErrorString());
        }

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < hashLen; ++i) {
            oss << std::setw(2) << static_cast<int>(hash[i]);
        }

        return oss.str();
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
