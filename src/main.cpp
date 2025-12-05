#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <array>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;
    static const size_t IV_SIZE = 16;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();

    int encrypt;
    std::array<unsigned char, KEY_SIZE> key;
    std::array<unsigned char, IV_SIZE> iv;
};

AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream inputFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            std::fstream outputFile(options.GetOutputFile(), std::ios::out | std::ios::binary);

            if (!inputFile.is_open()) {
                throw std::runtime_error("Failed to open input file: " + options.GetInputFile());
            }
            if (!outputFile.is_open()) {
                throw std::runtime_error("Failed to open output file: " + options.GetOutputFile());
            }

            cryptoCtx.EncryptFile(inputFile, outputFile, options.GetPassword());
            std::print("File encrypted successfully: {} -> {}\n", options.GetInputFile(), options.GetOutputFile());
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            std::fstream inputFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            std::fstream outputFile(options.GetOutputFile(), std::ios::out | std::ios::binary);

            if (!inputFile.is_open()) {
                throw std::runtime_error("Failed to open input file: " + options.GetInputFile());
            }
            if (!outputFile.is_open()) {
                throw std::runtime_error("Failed to open output file: " + options.GetOutputFile());
            }

            cryptoCtx.DecryptFile(inputFile, outputFile, options.GetPassword());
            std::print("File decrypted successfully: {} -> {}\n", options.GetInputFile(), options.GetOutputFile());
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            std::fstream inputFile(options.GetInputFile(), std::ios::in | std::ios::binary);

            if (!inputFile.is_open()) {
                throw std::runtime_error("Failed to open input file: " + options.GetInputFile());
            }

            std::string checksum = cryptoCtx.CalculateChecksum(inputFile);
            std::print("SHA-256 checksum: {}\n", checksum);
            break;
        }

        default:
            throw std::runtime_error("Unsupported command");
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}