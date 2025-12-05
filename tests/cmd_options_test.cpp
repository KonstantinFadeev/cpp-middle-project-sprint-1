#include "cmd_options.h"
#include <gtest/gtest.h>
#include <vector>

std::vector<char *> CreateArgv(const std::vector<std::string> &args) {
    std::vector<char *> argv;
    for (const auto &arg : args) {
        argv.push_back(const_cast<char *>(arg.c_str()));
    }
    return argv;
}

TEST(ProgramOptions, SuccessfulEncryptParsing) {
    CryptoGuard::ProgramOptions options;
    std::vector<std::string> args = {"program", "-c", "encrypt", "-i", "input.txt", "-o", "output.txt", "-p", "secret"};
    auto argv = CreateArgv(args);

    EXPECT_NO_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "secret");
}

TEST(ProgramOptions, SuccessfulDecryptParsing) {
    CryptoGuard::ProgramOptions options;
    std::vector<std::string> args = {"program",  "--command",     "decrypt",    "--input",      "encrypted.txt",
                                     "--output", "decrypted.txt", "--password", "mypassword123"};
    auto argv = CreateArgv(args);

    EXPECT_NO_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "encrypted.txt");
    EXPECT_EQ(options.GetOutputFile(), "decrypted.txt");
    EXPECT_EQ(options.GetPassword(), "mypassword123");
}

TEST(ProgramOptions, SuccessfulChecksumParsing) {
    CryptoGuard::ProgramOptions options;
    std::vector<std::string> args = {"program", "-c", "checksum", "-i", "file.txt"};
    auto argv = CreateArgv(args);

    EXPECT_NO_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "file.txt");
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptions, ThrowsOnInvalidCommand) {
    CryptoGuard::ProgramOptions options;
    std::vector<std::string> args = {"program", "-c", "invalid_command", "-i", "input.txt"};
    auto argv = CreateArgv(args);

    EXPECT_THROW(
        {
            try {
                options.Parse(static_cast<int>(argv.size()), argv.data());
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("Invalid command: 'invalid_command'. Supported commands: encrypt, decrypt, checksum",
                             e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ThrowsOnMissingOutputForEncrypt) {
    CryptoGuard::ProgramOptions options;
    std::vector<std::string> args = {"program", "-c", "encrypt", "-i", "input.txt", "-p", "password"};
    auto argv = CreateArgv(args);

    EXPECT_THROW(
        {
            try {
                options.Parse(static_cast<int>(argv.size()), argv.data());
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("The 'encrypt' command requires --output option", e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ThrowsOnMissingPasswordForDecrypt) {
    CryptoGuard::ProgramOptions options;
    std::vector<std::string> args = {"program", "-c", "decrypt", "-i", "input.txt", "-o", "output.txt"};
    auto argv = CreateArgv(args);

    EXPECT_THROW(
        {
            try {
                options.Parse(static_cast<int>(argv.size()), argv.data());
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("The 'decrypt' command requires --password option", e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ThrowsOnEmptyPassword) {
    CryptoGuard::ProgramOptions options;
    std::vector<std::string> args = {"program", "-c", "encrypt", "-i", "input.txt", "-o", "output.txt", "-p", ""};
    auto argv = CreateArgv(args);

    EXPECT_THROW(
        {
            try {
                options.Parse(static_cast<int>(argv.size()), argv.data());
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("Password cannot be empty", e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ThrowsOnSameInputOutputFiles) {
    CryptoGuard::ProgramOptions options;
    std::vector<std::string> args = {"program", "-c", "encrypt", "-i", "file.txt", "-o", "file.txt", "-p", "pass"};
    auto argv = CreateArgv(args);

    EXPECT_THROW(
        {
            try {
                options.Parse(static_cast<int>(argv.size()), argv.data());
            } catch (const std::runtime_error &e) {
                EXPECT_STREQ("Input and output files cannot be the same", e.what());
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ThrowsOnMissingRequiredCommand) {
    CryptoGuard::ProgramOptions options;
    std::vector<std::string> args = {"program", "-i", "input.txt"};
    auto argv = CreateArgv(args);

    EXPECT_THROW(
        {
            try {
                options.Parse(static_cast<int>(argv.size()), argv.data());
            } catch (const std::runtime_error &e) {
                std::string errorMsg(e.what());
                EXPECT_TRUE(errorMsg.find("Command line parsing error") != std::string::npos);
                throw;
            }
        },
        std::runtime_error);
}

TEST(ProgramOptions, ThrowsOnMissingRequiredInput) {
    CryptoGuard::ProgramOptions options;
    std::vector<std::string> args = {"program", "-c", "checksum"};
    auto argv = CreateArgv(args);

    EXPECT_THROW(
        {
            try {
                options.Parse(static_cast<int>(argv.size()), argv.data());
            } catch (const std::runtime_error &e) {
                std::string errorMsg(e.what());
                EXPECT_TRUE(errorMsg.find("Command line parsing error") != std::string::npos);
                throw;
            }
        },
        std::runtime_error);
}
