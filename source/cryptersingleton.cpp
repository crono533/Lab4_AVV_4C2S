#include "cryptersingleton.h"
#include <openssl/sha.h>
#include <openssl/rand.h>



CrypterSingleton::CrypterSingleton(){}
CrypterSingleton::~CrypterSingleton(){}



int CrypterSingleton::perform_encryption(const unsigned char* plaintext, int plaintext_length, const unsigned char* key,
                       const unsigned char* iv, unsigned char* ciphertext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_length) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int CrypterSingleton::perform_decryption(const unsigned char* ciphertext, int ciphertext_length, const unsigned char* key,
                       const unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_length) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}


void CrypterSingleton::process_directory(const std::string& path, const std::string& password, bool encryption_mode) {
    QDir dir(QString::fromStdString(path));

    if (!dir.exists()) {
        std::cerr << "Directory does not exist: " << path << std::endl;
        return;
    }

    QFileInfoList entries = dir.entryInfoList(QDir::NoDotAndDotDot | QDir::AllEntries);
    for (const QFileInfo& entry : std::as_const(entries)) {
        std::string fullPath = entry.absoluteFilePath().toStdString();
        if (entry.isDir()) {
            process_directory(fullPath, password, encryption_mode);
        } else if (entry.isFile()) {
            if (encryption_mode) {
                if (encrypt_file(fullPath, password))
                    std::cout << "Encrypted: " << fullPath << std::endl;
            } else {
                if (decrypt_file(fullPath, password))
                    std::cout << "Decrypted: " << fullPath << std::endl;
            }
        }
    }
}

CrypterSingleton& CrypterSingleton::instance() {
    static CrypterSingleton manager;
    return manager;
}

bool CrypterSingleton::encrypt_file(const std::string& path, const std::string& password)
{

    QFileInfo fileInfo(QString::fromStdString(path));
    std::ifstream input_file(path, std::ios::binary);
    if (!input_file) {
        std::cerr << "Error opening file for reading: " << path << std::endl;
        return false;
    }


    // Проверка размера файла
    if (static_cast<size_t>(fileInfo.size()) > MAX_FILE_SIZE) {
        std::cerr << "File is too large to process: " << path << std::endl;
        return false;
    }

    std::vector<unsigned char> plaintext( (std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());

    input_file.close();

    unsigned char key[SHA256_DIGEST_LENGTH];

    SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), key);

    unsigned char iv[EVP_MAX_IV_LENGTH];

    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
        std::cerr << "Error generating initialization vector" << std::endl;
        return false;
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    int ciphertext_length = perform_encryption( plaintext.data(), plaintext.size(), key, iv, ciphertext.data());

    if (ciphertext_length < 0) {
        std::cerr << "Encryption process failed" << std::endl;
        return false;
    }

    ciphertext.resize(ciphertext_length);

    std::ofstream output_file(path, std::ios::binary | std::ios::trunc);
    if (!output_file) {
        std::cerr << "Error opening file for writing: " << path << std::endl;
        return false;
    }

    output_file.write(reinterpret_cast<const char*>(iv), EVP_MAX_IV_LENGTH);
    output_file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    output_file.close();

    return true;
}

bool CrypterSingleton::decrypt_file(const std::string& path, const std::string& password) {
    std::ifstream input_file(path, std::ios::binary);
    if (!input_file) {
        std::cerr << "Error opening file for reading: " << path << std::endl;
        return false;
    }

    QFileInfo fileInfo(QString::fromStdString(path));
    // Проверка размера файла
    if (static_cast<size_t>(fileInfo.size()) > MAX_FILE_SIZE)
    {
        std::cerr << "File is too large to process: " << path << std::endl;
        return false;
    }

    unsigned char iv[EVP_MAX_IV_LENGTH];
    input_file.read(reinterpret_cast<char*>(iv), EVP_MAX_IV_LENGTH);

    if (input_file.gcount() != EVP_MAX_IV_LENGTH)
    {
        std::cerr << "Invalid initialization vector size" << std::endl;
        return false;
    }

    std::vector<unsigned char> ciphertext(
        (std::istreambuf_iterator<char>(input_file)),
        std::istreambuf_iterator<char>()
        );
    input_file.close();

    unsigned char key[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), key);

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);

    int plaintext_length = perform_decryption(ciphertext.data(), ciphertext.size(), key, iv, plaintext.data());

    if (plaintext_length < 0) {
        std::cerr << "Decryption process failed. Invalid password?" << std::endl;
        return false;
    }

    plaintext.resize(plaintext_length);

    std::ofstream output_file(path, std::ios::binary | std::ios::trunc);

    if (!output_file) {
        std::cerr << "Error opening file for writing: " << path << std::endl;
        return false;
    }

    output_file.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    output_file.close();

    return true;
}

void CrypterSingleton::encrypt_directory(const std::string& path, const std::string& password) {
    process_directory(path, password, true);
}

void CrypterSingleton::decrypt_directory(const std::string& path, const std::string& password) {
    process_directory(path, password, false);
}
