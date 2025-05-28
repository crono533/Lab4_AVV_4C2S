#ifndef CRYPTERSINGLETON_H
#define CRYPTERSINGLETON_H

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <openssl/evp.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <string>

constexpr size_t MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB

class CrypterSingleton {
private:
    CrypterSingleton();
    ~CrypterSingleton();
    CrypterSingleton(const CrypterSingleton&) = delete;
    CrypterSingleton& operator=(const CrypterSingleton&) = delete;

    int perform_encryption(const unsigned char* plaintext, int plaintext_length, const unsigned char* key,
                           const unsigned char* iv, unsigned char* ciphertext);

    int perform_decryption(const unsigned char* ciphertext, int ciphertext_length, const unsigned char* key,
                           const unsigned char* iv, unsigned char* plaintext);

    void process_directory(const std::string& path, const std::string& password, bool encryption_mode);

public:
    static CrypterSingleton& instance();
    bool encrypt_file(const std::string& path, const std::string& password);
    bool decrypt_file(const std::string& path, const std::string& password);
    void encrypt_directory(const std::string& path, const std::string& password);
    void decrypt_directory(const std::string& path, const std::string& password);
};

#endif // CRYPTERSINGLETON_H
