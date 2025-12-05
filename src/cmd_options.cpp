#include "cmd_options.h"
#include <iostream>
#include <stdexcept>

namespace {

constexpr std::string_view ARG_HELP = "help,h";
constexpr std::string_view ARG_COMMAND = "command,c";
constexpr std::string_view ARG_INPUT = "input,i";
constexpr std::string_view ARG_OUTPUT = "output,o";
constexpr std::string_view ARG_PASSWORD = "password,p";

constexpr std::string_view ARG_HELP_NAME = "help";
constexpr std::string_view ARG_COMMAND_NAME = "command";
constexpr std::string_view ARG_INPUT_NAME = "input";
constexpr std::string_view ARG_OUTPUT_NAME = "output";
constexpr std::string_view ARG_PASSWORD_NAME = "password";

}  // namespace

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace po = boost::program_options;

    std::string commandDesc = std::string("Command to execute: ") + std::string(CMD_ENCRYPT) + ", " +
                              std::string(CMD_DECRYPT) + ", or " + std::string(CMD_CHECKSUM);

    desc_.add_options()(ARG_HELP.data(), "Display help message and list available options")(
        ARG_COMMAND.data(), po::value<std::string>()->required(),
        commandDesc.c_str())(ARG_INPUT.data(), po::value<std::string>()->required(), "Path to the input file")(
        ARG_OUTPUT.data(), po::value<std::string>(), "Path to the output file (required for encrypt/decrypt)")(
        ARG_PASSWORD.data(), po::value<std::string>(),
        "Password for encryption/decryption (required for encrypt/decrypt)");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    namespace po = boost::program_options;

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm);

        if (vm.count(ARG_HELP_NAME.data())) {
            std::cout << desc_ << std::endl;
            std::exit(0);
        }

        po::notify(vm);

    } catch (const po::error &e) {
        throw std::runtime_error(std::string("Command line parsing error: ") + e.what());
    }

    std::string commandStr = vm[ARG_COMMAND_NAME.data()].as<std::string>();
    auto commandIt = commandMapping_.find(commandStr);
    if (commandIt == commandMapping_.end()) {
        throw std::runtime_error("Invalid command: '" + commandStr +
                                 "'. Supported commands: " + std::string(CMD_ENCRYPT) + ", " +
                                 std::string(CMD_DECRYPT) + ", " + std::string(CMD_CHECKSUM));
    }
    command_ = commandIt->second;

    inputFile_ = vm[ARG_INPUT_NAME.data()].as<std::string>();

    switch (command_) {
    case COMMAND_TYPE::ENCRYPT:
    case COMMAND_TYPE::DECRYPT:
        if (!vm.count(ARG_OUTPUT_NAME.data())) {
            throw std::runtime_error("The '" + commandStr + "' command requires --output option");
        }
        if (!vm.count(ARG_PASSWORD_NAME.data())) {
            throw std::runtime_error("The '" + commandStr + "' command requires --password option");
        }

        outputFile_ = vm[ARG_OUTPUT_NAME.data()].as<std::string>();
        password_ = vm[ARG_PASSWORD_NAME.data()].as<std::string>();

        if (password_.empty()) {
            throw std::runtime_error("Password cannot be empty");
        }
        break;

    case COMMAND_TYPE::CHECKSUM:
        if (vm.count(ARG_OUTPUT_NAME.data())) {
            outputFile_ = vm[ARG_OUTPUT_NAME.data()].as<std::string>();
        }
        if (vm.count(ARG_PASSWORD_NAME.data())) {
            password_ = vm[ARG_PASSWORD_NAME.data()].as<std::string>();
        }
        break;

    default:
        throw std::runtime_error("Unsupported command type");
    }

    if (!outputFile_.empty() && inputFile_ == outputFile_) {
        throw std::runtime_error("Input and output files cannot be the same");
    }
}

}  // namespace CryptoGuard
