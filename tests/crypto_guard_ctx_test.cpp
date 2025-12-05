#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <string>

// Тесты для метода EncryptFile
TEST(CryptoGuardCtx, EncryptFile_SuccessfulEncryption) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::string plaintext = "Hello, OpenSSL crypto world!";
    std::stringstream input(plaintext);
    std::stringstream output;

    EXPECT_NO_THROW(ctx.EncryptFile(input, output, "test_password"));

    // Проверяем, что зашифрованные данные не пусты
    std::string encrypted = output.str();
    EXPECT_FALSE(encrypted.empty());

    // Проверяем, что зашифрованные данные отличаются от исходных
    EXPECT_NE(encrypted, plaintext);
}

TEST(CryptoGuardCtx, EncryptFile_EmptyInput) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("");  // Пустой поток
    std::stringstream output;

    EXPECT_NO_THROW(ctx.EncryptFile(input, output, "password"));

    // Даже для пустого ввода должны быть данные (padding)
    std::string encrypted = output.str();
    EXPECT_FALSE(encrypted.empty());
}

TEST(CryptoGuardCtx, EncryptFile_ThrowsOnBadInputStream) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("test data");
    std::stringstream output;

    // Делаем входной поток невалидным
    input.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.EncryptFile(input, output, "password"), std::runtime_error);
}

TEST(CryptoGuardCtx, EncryptFile_ThrowsOnBadOutputStream) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("test data");
    std::stringstream output;

    // Делаем выходной поток невалидным
    output.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.EncryptFile(input, output, "password"), std::runtime_error);
}

TEST(CryptoGuardCtx, EncryptFile_LargeData) {
    CryptoGuard::CryptoGuardCtx ctx;

    // Создаём большой текст (больше одного блока)
    std::string largeText(10000, 'A');
    std::stringstream input(largeText);
    std::stringstream output;

    EXPECT_NO_THROW(ctx.EncryptFile(input, output, "secure_password"));

    std::string encrypted = output.str();
    EXPECT_FALSE(encrypted.empty());
    EXPECT_NE(encrypted, largeText);
}

// Тесты для метода DecryptFile
TEST(CryptoGuardCtx, DecryptFile_SuccessfulDecryption) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::string original = "Secret message for encryption test";
    std::stringstream encryptInput(original);
    std::stringstream encrypted;

    // Сначала шифруем
    ctx.EncryptFile(encryptInput, encrypted, "my_password");

    // Теперь дешифруем
    std::stringstream decrypted;
    ctx.DecryptFile(encrypted, decrypted, "my_password");

    // Проверяем, что получили исходное сообщение
    EXPECT_EQ(decrypted.str(), original);
}

TEST(CryptoGuardCtx, DecryptFile_RoundTrip) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::string original = "Round trip test: 12345!@#$%";
    std::stringstream input1(original);
    std::stringstream encrypted;
    std::stringstream decrypted;

    // Encrypt
    EXPECT_NO_THROW(ctx.EncryptFile(input1, encrypted, "password123"));

    // Decrypt
    EXPECT_NO_THROW(ctx.DecryptFile(encrypted, decrypted, "password123"));

    // Verify
    EXPECT_EQ(decrypted.str(), original);
}

TEST(CryptoGuardCtx, DecryptFile_ThrowsOnWrongPassword) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::string original = "Encrypted with password";
    std::stringstream input(original);
    std::stringstream encrypted;

    // Шифруем с одним паролем
    ctx.EncryptFile(input, encrypted, "correct_password");

    // Пытаемся дешифровать с другим паролем
    std::stringstream decrypted;
    ASSERT_THROW(ctx.DecryptFile(encrypted, decrypted, "wrong_password"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptFile_ThrowsOnBadInputStream) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("encrypted data");
    std::stringstream output;

    input.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.DecryptFile(input, output, "password"), std::runtime_error);
}

// Тесты для метода CalculateChecksum
TEST(CryptoGuardCtx, CalculateChecksum_EmptyInput) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("");

    std::string checksum = ctx.CalculateChecksum(input);

    // SHA-256 хеш пустой строки (известное значение)
    EXPECT_EQ(checksum, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(CryptoGuardCtx, CalculateChecksum_KnownValue) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("hello");

    std::string checksum = ctx.CalculateChecksum(input);

    // SHA-256 хеш строки "hello"
    EXPECT_EQ(checksum, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

TEST(CryptoGuardCtx, CalculateChecksum_SameInputSameOutput) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::string data = "Test data for checksum";
    std::stringstream input1(data);
    std::stringstream input2(data);

    std::string checksum1 = ctx.CalculateChecksum(input1);
    std::string checksum2 = ctx.CalculateChecksum(input2);

    // Одинаковые данные должны давать одинаковый хеш
    EXPECT_EQ(checksum1, checksum2);
}

TEST(CryptoGuardCtx, CalculateChecksum_DifferentInputDifferentOutput) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input1("Data 1");
    std::stringstream input2("Data 2");

    std::string checksum1 = ctx.CalculateChecksum(input1);
    std::string checksum2 = ctx.CalculateChecksum(input2);

    // Разные данные должны давать разные хеши
    EXPECT_NE(checksum1, checksum2);
}

TEST(CryptoGuardCtx, CalculateChecksum_ThrowsOnBadInputStream) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream input("data");
    input.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.CalculateChecksum(input), std::runtime_error);
}

TEST(CryptoGuardCtx, CalculateChecksum_LargeData) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::string largeData(100000, 'X');
    std::stringstream input(largeData);

    std::string checksum;
    EXPECT_NO_THROW(checksum = ctx.CalculateChecksum(input));

    // SHA-256 всегда возвращает 64 hex символа (32 байта = 256 бит)
    EXPECT_EQ(checksum.length(), 64);
}
