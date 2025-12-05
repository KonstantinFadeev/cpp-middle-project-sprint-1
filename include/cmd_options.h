#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
    };

    static constexpr std::string_view CMD_ENCRYPT = "encrypt";
    static constexpr std::string_view CMD_DECRYPT = "decrypt";
    static constexpr std::string_view CMD_CHECKSUM = "checksum";

    void Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    std::string GetInputFile() const { return inputFile_; }
    std::string GetOutputFile() const { return outputFile_; }
    std::string GetPassword() const { return password_; }

private:
    COMMAND_TYPE command_;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {CMD_ENCRYPT, ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {CMD_DECRYPT, ProgramOptions::COMMAND_TYPE::DECRYPT},
        {CMD_CHECKSUM, ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    boost::program_options::options_description desc_;
};

}  // namespace CryptoGuard
