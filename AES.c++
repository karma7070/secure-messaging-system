#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <stdexcept>

using namespace std;

class AES256 {
public:
    static constexpr size_t KEY_LEN = 32; // 256 bit
    static constexpr size_t IV_LEN  = 16; // 128 bit

    AES256() {
        // Generate random key and IV
        key_.resize(KEY_LEN);
        iv_.resize(IV_LEN);
        if (RAND_bytes(key_.data(), KEY_LEN) != 1 || RAND_bytes(iv_.data(), IV_LEN) != 1) {
            throw runtime_error("RAND_bytes failed");
        }
    }

    vector<unsigned char> encrypt(const string& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handle_errors();

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_.data(), iv_.data()) != 1)
            handle_errors();

        vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        int len = 0, ciphertext_len = 0;

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                              reinterpret_cast<const unsigned char*>(plaintext.data()), 
                              plaintext.size()) != 1)
            handle_errors();
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
            handle_errors();
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }

    string decrypt(const vector<unsigned char>& ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handle_errors();

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_.data(), iv_.data()) != 1)
            handle_errors();

        vector<unsigned char> plaintext(ciphertext.size());
        int len = 0, plaintext_len = 0;

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
            handle_errors();
        plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
            handle_errors();
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        plaintext.resize(plaintext_len);
        return string(plaintext.begin(), plaintext.end());
    }

    void print_key_iv() const {
        cout << "=== Key Exchange Simulation ===\n";
        print_hex("Generated AES-256 Key", key_);
        print_hex("Generated IV", iv_);
        cout << "In real life you'd send this key/IV encrypted with RSA/DH\n";
    }

    const vector<unsigned char>& get_key() const { return key_; }
    const vector<unsigned char>& get_iv() const { return iv_; }

private:
    vector<unsigned char> key_;
    vector<unsigned char> iv_;

    static void handle_errors() {
        ERR_print_errors_fp(stderr);
        throw runtime_error("OpenSSL error");
    }

    static void print_hex(const string& label, const vector<unsigned char>& data) {
        cout << label << ": ";
        for (unsigned char byte : data)
            cout << hex << setw(2) << setfill('0') << (int)byte;
        cout << dec << "\n";
    }
};

int main() {
    try {
        AES256 aes;
        aes.print_key_iv();

        // Client side
        string message = "Hello Server, this is a secret message!";
        cout << "=== Client Encrypting ===\n";
        cout << "Plaintext: " << message << "\n";

        auto ciphertext = aes.encrypt(message);
        AES256::print_hex("Ciphertext", ciphertext);

        // Server side
        cout << "\n=== Server Decrypting ===\n";
        string decrypted = aes.decrypt(ciphertext);
        cout << "Decrypted: " << decrypted << "\n";

        // Verify
        if (message == decrypted) {
            cout << "\nSuccess: Decryption matches original message\n";
        } else {
            cout << "\nError: Decryption failed\n";
        }

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}